/*
 * Phoenix-RTOS
 *
 * Operating system kernel
 *
 * CPU related routines
 *
 * Copyright 2012, 2017 Phoenix Systems
 * Copyright 2001, 2006 Pawel Pisarczyk
 * Author: Pawel Pisarczyk
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include "../../../include/errno.h"
#include "../../../include/arch/ia32.h"
#include "cpu.h"
#include "spinlock.h"
#include "syspage.h"
#include "string.h"
#include "pmap.h"
#include "spinlock.h"
#include "lib/lib.h"


extern int threads_schedule(unsigned int n, cpu_context_t *context, void *arg);


struct {
	tss_t tss[256];
	char stacks[256][128];
	u32 dr5;
	spinlock_t lock;
	volatile unsigned int ncpus;
} cpu;


/* Function reads word from PCI configuration space */
static u32 _hal_pciGet(u8 bus, u8 dev, u8 func, u8 reg)
{
	u32 v;

	hal_outl((void *)0xcf8, 0x80000000 | ((u32)bus << 16 ) | ((u32)dev << 11) | ((u32)func << 8) | (reg << 2));
	v = hal_inl((void *)0xcfc);

	return v;
}


/* Function writes word to PCI configuration space */
static u32 _hal_pciSet(u8 bus, u8 dev, u8 func, u8 reg, u32 v)
{
	hal_outl((void *)0xcf8, 0x80000000 | ((u32)bus << 16 ) | ((u32)dev << 11) | ((u32)func << 8) | (reg << 2));
	hal_outl((void *)0xcfc, v);

	return v;
}


static int hal_pciSetBusmaster(pci_device_t *dev, u8 enable)
{
	u32 dv;

	if (dev == NULL)
		return -EINVAL;

	hal_spinlockSet(&cpu.lock);
	dv = _hal_pciGet(dev->b, dev->d, dev->f, 1);
	dv &= ~(!enable << 2);
	dv |= !!enable << 2;
	_hal_pciSet(dev->b, dev->d, dev->f, 1, dv);
	hal_spinlockClear(&cpu.lock);

	dev->command = dv & 0xffff;

	return EOK;
}


static int hal_pciGetDevice(pci_id_t *id, pci_device_t *dev)
{
	unsigned int b, d, f, i;
	u32 dv, cl, tmp, shift;

	if (id == NULL || dev == NULL)
		return -EINVAL;

	for (b = 0; b < 256; b++) {
		for (d = 0; d < 32; d++) {
			for (f = 0; f < 8; f++) {
				hal_spinlockSet(&cpu.lock);
				dv = _hal_pciGet(b, d, f, 0);
				hal_spinlockClear(&cpu.lock);

				if (dv == 0xffffffff)
					continue;

				if (id->vendor != PCI_ANY && id->vendor != (dv & 0xffff))
					continue;

				if (id->device != PCI_ANY && id->device != (dv >> 16))
					continue;

				hal_spinlockSet(&cpu.lock);
				cl = _hal_pciGet(b, d, f, 2) >> 16;
				hal_spinlockClear(&cpu.lock);

				if (id->cl != PCI_ANY && id->cl != cl)
					continue;

				dev->b = b;
				dev->d = d;
				dev->f = f;
				dev->device = dv & 0xffff;
				dev->vendor = dv >> 16;
				dev->cl = cl;

				hal_spinlockSet(&cpu.lock);
				dv = _hal_pciGet(b, d, f, 1);
				dev->status = dv >> 16;
				dev->command = dv & 0xffff;
				dev->progif = (_hal_pciGet(b, d, f, 2) >> 8) & 0xff;
				dev->revision = _hal_pciGet(b, d, f, 2) & 0xff;
				dev->type = _hal_pciGet(b, d, f, 3) >> 16 & 0xff;
				dev->irq = _hal_pciGet(b, d, f, 15) & 0xff;

				/* Get resources */
				for (i = 0; i < 6; i++) {
					dev->resources[i].base = _hal_pciGet(b, d, f, 4 + i);

					/* Get resource limit */
					_hal_pciSet(b, d, f, 4 + i, 0xffffffff);
					dev->resources[i].limit = _hal_pciGet(b, d, f, 4 + i);
					tmp = dev->resources[i].limit & ((dev->resources[i].limit & 1) ? ~0x03 : ~0xf);

					__asm__ volatile
					(" \
						mov %1, %%eax; \
						bsfl %%eax, %0; \
						jnz 1f; \
						xorl %0, %0; \
					1:"
					:"=r" (shift)
					:"g" (tmp)
					:"eax");

					dev->resources[i].limit = (1 << shift);

					_hal_pciSet(b, d, f, 4 + i, dev->resources[i].base);
				}

				hal_spinlockClear(&cpu.lock);

				return EOK;
			}
		}
	}

	return -ENODEV;
}


/* context management */


static inline u32 cpu_getEFLAGS(void)
{
	u32 eflags;

	__asm__ volatile
	(" \
		pushf; \
		popl %%eax; \
		movl %%eax, %0"
	:"=g" (eflags)
	:
	:"eax");

	return eflags;
}


int hal_cpuDebugGuard(u32 enable, u32 slot)
{
	/* guard 4 bytes read/write */
	u32 mask = (3 << (2 * slot)) | (0xf << (2 * slot + 16));

	/* exact breakpoint match */
	mask |= 3 << 8;

	if (slot > 3)
		return -EINVAL;

	if (enable)
		cpu.dr5 |= mask;
	else
		cpu.dr5 &= ~mask;

	__asm__ volatile ("movl %0, %%dr5" : : "r" (cpu.dr5));

	return EOK;
}


int hal_cpuCreateContext(cpu_context_t **nctx, void *start, void *kstack, size_t kstacksz, void *ustack, void *arg)
{
	cpu_context_t *ctx;

	*nctx = NULL;
	if (kstack == NULL)
		return -EINVAL;

	if (kstacksz < sizeof(cpu_context_t))
		return -EINVAL;

	/* Prepare initial kernel stack */
	ctx = (cpu_context_t *)(kstack + kstacksz - sizeof(cpu_context_t));
	hal_cpuRestore(ctx, ctx);

#ifndef NDEBUG
	ctx->dr0 = (u32)kstack + 16; /* protect bottom bytes of kstack */
	ctx->dr1 = 0;
	ctx->dr2 = 0;
	ctx->dr3 = 0;
#endif

	ctx->edi = 0;
	ctx->esi = 0;
	ctx->ebp = 0;
	ctx->edx = 0;
	ctx->ecx = 0;
	ctx->ebx = 0;
	ctx->eax = 0;
	ctx->gs = ustack ? SEL_UDATA : SEL_KDATA;
	ctx->fs = ustack ? SEL_UDATA : SEL_KDATA;
	ctx->es = ustack ? SEL_UDATA : SEL_KDATA;
	ctx->ds = ustack ? SEL_UDATA : SEL_KDATA;
	ctx->eip = (u32)start;
	ctx->cs = ustack ? SEL_UCODE : SEL_KCODE;

	/* Copy flags from current process and enable interrupts */
	ctx->eflags = (cpu_getEFLAGS() | 0x00000200 | 0x00003000); /* IOPL = 3 */

	/* Prepare user stack for user-level thread */
	if (ustack != NULL) {
		ctx->esp = (u32)ustack - 8;
		((u32 *)ctx->esp)[1] = (u32)arg;
		ctx->ss = SEL_UDATA;
	}

	/* Prepare kernel stack for kernel-level thread */
	else {
		ctx->ss = (u32)arg;
	}

	*nctx = ctx;

	return EOK;
}


int hal_cpuReschedule(spinlock_t *spinlock)
{
	int err;

	if (spinlock != NULL) {
		hal_cpuGetCycles((void *)&spinlock->e);

		/* Calculate maximum and minimum lock time */
		if ((cycles_t)(spinlock->e - spinlock->b) > spinlock->dmax)
			spinlock->dmax = spinlock->e - spinlock->b;

		if (spinlock->e - spinlock->b < spinlock->dmin)
			spinlock->dmin = spinlock->e - spinlock->b;
	}

	__asm__ volatile (
		"movl %1, %%eax;"
		"cmp $0, %%eax;"
		"je 1f;"

		"movl %3, %%eax;"
		"pushl %%eax;"
		"xorl %%eax, %%eax;"
		"incl %%eax;"
		"xchgl %2, %%eax;"
		"jmp 2f;"

		"1:;"
		"pushf;"

		"2:;"
		"pushl %%cs;"
		"cli;"
		"leal 3f, %%eax;"
		"pushl %%eax;"
		"movl $0, %%eax;"
		"call interrupts_pushContext;"
		"leal 0(%%esp), %%eax;"
		"pushl $0;"
		"pushl %%eax;"
		"pushl $0;"
		"movl %4, %%eax;"
		"call *%%eax;"
		"cli;"
		"addl $12, %%esp;"
		"jmp interrupts_popContext;"

		"3:;"
		"movl %%eax, %0"
	: "=g" (err)
	: "m" (spinlock), "m" (spinlock->lock), "m" (spinlock->eflags), "g" (threads_schedule)
	: "eax", "edx", "esp", "cc", "memory");

	return err;
}


void _hal_cpuSetKernelStack(void *kstack)
{
	cpu.tss[hal_cpuGetID()].ss0 = SEL_KDATA;
	cpu.tss[hal_cpuGetID()].esp0 = (u32)kstack;
}


/* core management */


unsigned int hal_cpuGetCount(void)
{
	return cpu.ncpus;
}


void _cpu_gdtInsert(unsigned int idx, u32 base, u32 limit, u32 type)
{
	u32 descrl, descrh;
	u32 *gdt;

	/* Modify limit for 4KB granularity */
	if (type & DBITS_4KB)
		limit = (limit >> 12);

	descrh = (base & 0xff000000) | (type & 0x00c00000) | (limit & 0x000f0000) |
	         (type & 0x0000ff00) | ((base >> 16) & 0x000000ff);

	descrl = (base << 16) | (limit & 0xffff);

	gdt = (void *)*(u32 *)&syspage->gdtr[2];

	gdt[idx * 2] = descrl;
	gdt[idx * 2 + 1] = descrh;

	return;
}


void _cpu_initCore(void)
{
	cpu.ncpus++;

	u8 cpuid = getCpuID();

	lib_printf("ncpus: %d cpuid: %x\n", cpu.ncpus, cpuid);

	hal_memset(&cpu.tss[hal_cpuGetID()], 0, sizeof(tss_t));

	u64 apic_msr = hal_rdmsr(0x1b);
	u8 is_bsp = (apic_msr >> 8) & 1;
	lib_printf("APIC MSR: %x\n", apic_msr);
	lib_printf("APIC is BSP: %x\n", (apic_msr >> 8) & 1);
	lib_printf("APIC is enabled: %x\n", (apic_msr >> 11) & 1);


	volatile u32 spurious_reg = 0;
	spurious_reg = *((u32 *) 0xfee000f0);
	*((u32 *) 0xfee000f0) = 0x1ff;
	lib_printf("LAPIC spurious reg: %x\n", *((u32 *) 0xfee000f0));

	volatile u32 tpr = *((u32 *) 0xFEE00080);
	lib_printf("LAPIC task priority reg: %x\n", tpr);

	*((volatile u32 *) 0x0FEE000D0) = 1 << (cpuid + 24);
	lib_printf("LAPIC logical address: %x\n", *((volatile u32 *) 0x0FEE000D0) & (0xff << 24));

	/* Select logical destination flat model */
	*((volatile u32 *) 0xFEE000E0) = 0xf << 28;
	volatile u32 dfr = *((u32 *) 0xFEE000E0);
	lib_printf("LAPIC destination format reg: %x\n", dfr);




	volatile u32 ppr = *((u32 *) 0xFEE000A0);
	lib_printf("Processor priority reg: %x\n", ppr);




	/* Mask LINT0 and LINT1 */
	if (!is_bsp) {
		*((u32 *) 0xFEE00350) = 1 << 16;
		*((u32 *) 0xFEE00360) = 1 << 16;
	}

	volatile u32 lvt1 = *((u32 *) 0xFEE00350);
	lib_printf("LVT INT0: %x\n", lvt1);

	volatile u32 lvt2 = *((u32 *) 0xFEE00360);
	lib_printf("LVT INT1: %x\n", lvt1);

	



	_cpu_gdtInsert(4 + cpu.ncpus, (u32)&cpu.tss[hal_cpuGetID()], sizeof(tss_t), DESCR_TSS);

	cpu.tss[hal_cpuGetID()].ss0 = SEL_KDATA;
	cpu.tss[hal_cpuGetID()].esp0 = (u32)&cpu.stacks[hal_cpuGetID()][127];

	/* Set task register */
	__asm__ volatile (" \
		movl %0, %%eax; \
		ltr %%ax"
	:
	: "r" ((4 + cpu.ncpus) * 8));
}


void _hal_cpuInitCores(void)
{
	unsigned int i, k;

	/* Prepare descriptors for user segments */
	_cpu_gdtInsert(3, 0x00000000, VADDR_KERNEL, DESCR_UCODE);
	_cpu_gdtInsert(4, 0x00000000, VADDR_KERNEL, DESCR_UDATA);

	/* Initialize BSP */
	cpu.ncpus = 0;
	_cpu_initCore();

	*(u32 *)((void *)syspage->stack + VADDR_KERNEL - 4) = 0;

	for (;;) {
		k = cpu.ncpus;
		i = 0;
		while ((cpu.ncpus == k) && (++i < 50000000));
		if (i >= 50000000)
			break;
	}
}

/* This table is obligatory if the system is MP */
struct {
	char signature[4]; /* Equal to _MP_ */
	addr_t mp_table_pointer; /* Physical address of MP Table */
	u8 length; /* Length of table in 16-byte units */
	u8 spec_rev; /* Version number of the MP specification */
	u8 checksum; /* Checksum of the complete pointer structure */
	u8 mp_feature_information[5]; /* When 0 byte is equal to 0,
									the MP configuration is present.
									Otherwise, it indicates, which default
									MP configuration is used.

									Bit 7 if set, means that IMCR is present
									and PIC Mode is implemented. Otherwise,
									Virtual Wire Mode is implemented */


} mp_floating_pointer_struct;




addr_t find_mp_floating_table(void)
{
	/* Search in BIOS ROM */
	char *current = 0x0F0000;
	char *max_addr = 0x0FFFFF;

	for (; current+4 < max_addr; current++) {
		if (*(current) == '_' &&
			*(current + 1) == 'M' &&
			*(current + 2) == 'P' &&
			*(current + 3) == '_') {
				lib_printf("FOUND: %p\n", current);
				return current;
			}
	}

	lib_printf("NOT FOUND\n");

	return 0;
}

struct {
	char signature[4]; /* Equal to PCMP */
	u16 base_table_length;
	u8 spec_rev;
	u8 checksum;
	char oem_id[8];
	char product_id[12];
	addr_t oem_table_pointer;
	u16 oem_table_size;
	u16 entry_count;
	addr_t local_apic_address;
	u16 ex_table_length;
	u8 ex_table_checksum;
} mp_table_header;


typedef struct {
	u8 id;
	u8 ver;
	u8 flags;
	u32 ioapic_address;
} io_apic_entry_t;


addr_t parse_mp_floating_table(addr_t address)
{
	hal_memcpy(&mp_floating_pointer_struct, (void *) address, sizeof(mp_floating_pointer_struct));
	lib_printf("MP Floating table:\n");
	lib_printf("signature: %c\n", mp_floating_pointer_struct.signature[3]);
	lib_printf("physical address: %x\n", mp_floating_pointer_struct.mp_table_pointer);
	lib_printf("length: %d\n", mp_floating_pointer_struct.length);
	lib_printf("spec_rev: %d\n", mp_floating_pointer_struct.spec_rev);
	lib_printf("checksum: %d\n", mp_floating_pointer_struct.checksum);
	lib_printf("feature byte 1: %d\n", mp_floating_pointer_struct.mp_feature_information[0]);
	lib_printf("feature byte 2: %d\n", mp_floating_pointer_struct.mp_feature_information[1]);

	return mp_floating_pointer_struct.mp_table_pointer;
}


addr_t parse_mp_table_header(addr_t address)
{
	hal_memcpy(&mp_table_header, (void *) address, sizeof(mp_table_header));

	lib_printf("MP Floating header:\n");
	lib_printf("signature: %c\n", mp_table_header.signature[3]);
	lib_printf("base_table_length: %d\n", mp_table_header.base_table_length);
	lib_printf("spec_rev: %d\n", mp_table_header.spec_rev);
	lib_printf("checksum: %d\n", mp_table_header.checksum);
	lib_printf("oemid: %.8s\n", mp_table_header.oem_id);
	lib_printf("productid: %.16s\n", mp_table_header.product_id);
	lib_printf("oem table pointer: %x\n", mp_table_header.oem_table_pointer);
	lib_printf("oem table size: %d\n", mp_table_header.oem_table_size);
	lib_printf("entry count: %d\n", mp_table_header.entry_count);
	lib_printf("local apic address: %x\n", mp_table_header.local_apic_address);
	lib_printf("extended table length: %d\n", mp_table_header.ex_table_length);
	lib_printf("extended table checksum: %d\n", mp_table_header.ex_table_checksum);

	return mp_table_header.entry_count;
}


#define MP_TABLE_ENTRY_PROC 0
#define MP_TABLE_ENTRY_BUS 1
#define MP_TABLE_ENTRY_IOAPIC 2
#define MP_TABLE_ENTRY_IOINT 3
#define MP_TABLE_ENTRY_LINT 4

#define INT_TYPE_INT 0
#define INT_TYPE_NMI 1
#define INT_TYPE_SMI 2
#define INT_TYPE_EXTINT 3


void parse_mp_table_entries(addr_t address, u16 n_entries)
{
	u16 i;
	for (i = 0; i < n_entries; i++) {
		u8 entry_type = *((u8 *) address);

		lib_printf("ENTRY TYPE: %d\n", entry_type);

		switch (entry_type) {
			case MP_TABLE_ENTRY_PROC:
				address += 20;
				break;

			case MP_TABLE_ENTRY_BUS:
				lib_printf("\nBUS ENTRY\n");
				address++;
				lib_printf("BUS ID: %x\n", *((u8 *) address));
				address++;
				char bus_type[7];
				hal_memcpy(bus_type, (void *) address, 6);
				bus_type[6] = '\0';
				lib_printf("BUS TYPE: %s\n", bus_type);
				address += 6;
				break;

			case MP_TABLE_ENTRY_IOAPIC:
				lib_printf("\nI/O APIC ENTRY\n");
				address++;
				lib_printf("I/O APIC ID: %x\n", *((u8 *) address));
				address++;
				lib_printf("I/O APIC VERSION: %x\n", *((u8 *) address));
				address++;
				lib_printf("I/O APIC EN: %x\n", *((u8 *) address) & 0x1);
				address++;
				lib_printf("I/O APIC BASE ADDRESS: %x\n\n", *((u32 *) address));
				address += 4;
				break;

			case MP_TABLE_ENTRY_IOINT:
				lib_printf("\nI/O APIC ASSIGNMENT ENTRY\n");
				address++;
				lib_printf("INTERRUPT TYPE: %x\n", *((u8 *) address));
				address++;
				lib_printf("Polarity: %x\n", *((u8 *) address) & 0x3);
				lib_printf("Trigger mode: %x\n", (*((u8 *) address) >> 2) & 0x3);
				address += 2;
				lib_printf("Source bus ID: %x\n", *((u8 *) address));
				address++;
				lib_printf("Source bus IRQ: %x\n", *((u8 *) address));
				address++;
				lib_printf("Destination I/O APIC: %x\n", *((u8 *) address));
				address++;
				lib_printf("Destination I/O APIC INTIN: %x\n", *((u8 *) address));
				address++;
				break;

			case MP_TABLE_ENTRY_LINT:
				address++;
				lib_printf("\nLOCAL APIC ASSIGNMENT ENTRY\n");
				lib_printf("INTERRUPT TYPE: %x\n", *((u8 *) address));
				address++;
				lib_printf("Polarity: %x\n", *((u8 *) address) & 0x3);
				lib_printf("Trigger mode: %x\n", (*((u8 *) address) >> 2) & 0x3);
				address += 2;
				lib_printf("Source bus ID: %x\n", *((u8 *) address));
				address++;
				lib_printf("Source bus IRQ: %x\n", *((u8 *) address));
				address++;
				lib_printf("Destination local APIC: %x\n", *((u8 *) address));
				address++;
				lib_printf("Destination local APIC LINTIN: %x\n", *((u8 *) address));
				address++;
				break;

			default:
				return;
		}
	}	
}

typedef struct {
	char signature[4];
	u32 length;
	u8 revision;
	u8 checksum;
	char oemid[6];
	char oem_table_id[8];
	u32 oem_revision;
	u32 creator_id;
	u32 creator_revision;
} acpi_sdt_header;

typedef struct {
	acpi_sdt_header header;
} acpi_rsdt;

typedef struct {
	char signature[8];
	u8 checksum;
	char oemid[6];
	u8 revision;
	acpi_rsdt *rsdt;
	u32 length;
	u64 xsdt_address;
	u8 extended_checksum;
	u8 reserved[3];
} acpi_rsdp;


acpi_rsdp *acpi_find_rsdp()
{
	const char rsdp_signature[] = {'R', 'S', 'D', ' ', 'P', 'T', 'R', ' '};
	/* Search in BIOS ROM */
	char *current = 0x000E0000;
	char *max_addr = 0x000FFFFF;


	for (; current + sizeof(rsdp_signature) < max_addr; current++) {
		if (hal_strncmp(rsdp_signature, current, sizeof(rsdp_signature)) == 0) {
				lib_printf("FOUND: %p\n", current);
				return (acpi_rsdp *) current;
			}
	}

	return NULL;
}

void *acpi_read_rsdp(acpi_rsdp *rsdp)
{
	char sign[9] = {};
	lib_printf("ACPI ADDR: %p\n", rsdp);
	hal_memcpy(sign, rsdp->signature, 8);

	char oemid[7] = {};
	hal_memcpy(oemid, rsdp->oemid, 6);

	/* TODO valdate checksum */
	lib_printf("ACPI signature: %s\n", sign);
	lib_printf("ACPI checksum: %d\n", rsdp->checksum);
	lib_printf("ACPI oemid: %s\n", oemid);
	lib_printf("ACPI revision: %x\n", rsdp->revision);
	lib_printf("ACPI rsdt address: %p\n", rsdp->rsdt);
	lib_printf("ACPI  length: %d\n", rsdp->length);
	lib_printf("ACPI xsdt address: %x\n", rsdp->xsdt_address);

}

unsigned int acpi_read_rsdt(acpi_rsdt *rsdt)
{
	char sign[5] = {};
	//lib_printf("RSDT ADDRESS: %p\n", rsdt);
	//hal_memcpy(sign, rsdt->header.signature, 4);

	//lib_printf("ACPI RSDT SIGNATURE: %s\n", sign);
	//lib_printf("ACPI RSDT LENGTH: %d\n", rsdt->header.length);
}


char *hal_cpuInfo(char *info)
{
	u32 nb, nx, v[4], a, fam, model;
	unsigned int i = 12;

	/* Get number of extended cpuid levels */
	hal_cpuid(0x80000000, 0, &nx, v + 1, v + 2, v + 3);
	nx &= 0x7fffffff;

	/* Get vendor and model */
	hal_cpuid(0, 0, &nb, (u32 *)&info[0], (u32 *)&info[8], (u32 *)&info[4]);
	info[i] = 0;

	hal_cpuid(1, 0, &a, v + 1, v + 2, v + 3);
	fam = (a >> 8) & 0xf;
	if (fam == 0xf)
		fam += (a >> 20) & 0xff;

	model = (a >> 4) & 0xf;
	if (fam == 6 || fam == 15)
		model |= (a >> 12) & 0xf0;

	i += hal_i2s(" Family ", &info[i], fam, 16, 0);
	i += hal_i2s(" Model ", &info[i], model, 16, 0);
	i += hal_i2s(" Stepping ", &info[i], a & 0xf, 16, 0);

	i += hal_i2s(" (", &info[i], nb, 10, 0);
	i += hal_i2s("/", &info[i], nx, 10, 0);
	info[i++] = ')';

	i += hal_i2s(", cores=", &info[i], cpu.ncpus, 10, 0);

	info[i] = 0;

	// addr_t mp_floating_table = find_mp_floating_table();
	// if (mp_floating_table) {
	// 	addr_t mp_table_addr = parse_mp_floating_table(mp_floating_table);

	// 	if (mp_table_addr) {
	// 		parse_mp_table_header(mp_table_addr);

	// 		parse_mp_table_entries(mp_table_addr + sizeof(mp_table_header),
	// 							   mp_table_header.entry_count);
	// 	}
		
	// }


	acpi_rsdp *rsdp = acpi_find_rsdp();

	acpi_read_rsdp(rsdp);
	acpi_read_rsdt(rsdp->rsdt);


	return info;
}


struct cpu_feature_t {
	const char *name;
	u32 eax;
	u8 reg;
	u8 offset;         /* eax, ebx, ecx, edx */
};


static const struct cpu_feature_t cpufeatures[] = {
	{ "fpu", 1, 3, 0 },          /* x87 FPU insns */
	{ "de", 1, 3, 2 },           /* debugging ext: CR4.DE, DR4 DR5 traps */
	{ "pse", 1, 3, 3 },          /* 4MiB pages */
	{ "tsc", 1, 3, 4 },          /* RDTSC insn */
	{ "msr", 1, 3, 5 },          /* RDMSR/WRMSR insns */
	{ "pae", 1, 3, 6 },          /* PAE */
	{ "apic", 1, 3, 6 },         /* APIC present */
	{ "cx8", 1, 2, 8 },          /* CMPXCHG8B insn */
	{ "sep", 1, 2, 11 },         /* SYSENTER/SYSEXIT insns */
	{ "mtrr", 1, 3, 12 },        /* MTRRs */
	{ "pge", 1, 3, 13 },         /* global pages */
	{ "cmov", 1, 3, 15 },        /* CMOV insn */
	{ "pat", 1, 3, 16 },         /* PAT */
	{ "pse36", 1, 3, 17 },       /* 4MiB pages can reach beyond 4GiB */
	{ "psn", 1, 3, 18 },         /* CPU serial number enabled */
	{ "clflush", 1, 3, 19 },     /* CLFLUSH insn */
	{ "cx16", 1, 2, 13 },        /* CMPXCHG16B insn */
	{ "dca", 1, 2, 18 },         /* prefetch from MMIO */
	{ "xsave", 1, 2, 26 },       /* XSAVE/XRSTOR insns */
	{ "smep", 7, 1, 7 },         /* SMEP */
	{ "smap", 7, 1, 20 },        /* SMAP */
	{ "nx", -1, 3, 20 },         /* page execute disable bit */
	{ NULL, }
};


char *hal_cpuFeatures(char *features, unsigned int len)
{
	u32 nb, nx, v[4], a;
	unsigned int i = 0, overflow = 0;
	const struct cpu_feature_t *p;
	unsigned int ln;

	/* Get number of basic cpuid levels */
	hal_cpuid(0, 0, &nb, v + 1, v + 2, v + 3);

	/* Get number of extended cpuid levels */
	hal_cpuid(0x80000000, 0, &nx, v + 1, v + 2, v + 3);
	nx &= 0x7fffffff;

	for (p = cpufeatures; p->name != NULL; ++p) {
		if (p->eax < 0 ? p->eax < -nx : p->eax > nb)
			continue;

		a = p->eax < 0 ? 0x80000000 - p->eax : p->eax;
		hal_cpuid(a, 0, v + 0, v + 1, v + 2, v + 3);

		if (v[p->reg] & (1 << p->offset)) {
			ln = hal_strlen(p->name);
			if (!overflow && (i + ln + 1 + 1 < len)) {
				features[i++] = '+';
				hal_memcpy(&features[i], p->name, ln);
				i += ln;
			}
			else if (!overflow) {
				overflow = 1;
				features[i++] = '|';
			}
		}
	}
	features[i] = 0;

	return features;
}


int hal_platformctl(void *ptr)
{
	platformctl_t *data = (platformctl_t *)ptr;

	switch (data->type) {
		case pctl_pci:
			if (data->action == pctl_get)
				return hal_pciGetDevice(&data->pci.id, &data->pci.dev);
			break;

		case pctl_busmaster:
			if (data->action == pctl_set)
				return hal_pciSetBusmaster(&data->busmaster.dev, data->busmaster.enable);
			break;
	}

	return -EINVAL;
}


void _hal_cpuInit(void)
{
	cpu.ncpus = 0;

	_hal_cpuInitCores();
#ifndef NDEBUG
	hal_cpuDebugGuard(1, 0);
//	hal_cpuDebugGuard(1, 1);
//	hal_cpuDebugGuard(1, 2);
//	hal_cpuDebugGuard(1, 3);
#endif

	hal_spinlockCreate(&cpu.lock, "cpu.lock");
}
