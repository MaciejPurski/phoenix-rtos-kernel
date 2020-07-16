/*
 * Phoenix-RTOS
 *
 * Operating system kernel
 *
 * Interrupt handling
 *
 * Copyright 2012-2013, 2016-2017 Phoenix Systems
 * Copyright 2001, 2005-2006 Pawel Pisarczyk
 * Author: Pawel Pisarczyk
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include "interrupts.h"
#include "spinlock.h"
#include "syspage.h"
#include "cpu.h"
#include "pmap.h"

#include "../../proc/userintr.h"

#include "../../../include/errno.h"


/* Hardware interrupt stubs */
extern void _interrupts_irq0(void);
extern void _interrupts_irq1(void);
extern void _interrupts_irq2(void);
extern void _interrupts_irq3(void);
extern void _interrupts_irq4(void);
extern void _interrupts_irq5(void);
extern void _interrupts_irq6(void);
extern void _interrupts_irq7(void);
extern void _interrupts_irq8(void);
extern void _interrupts_irq9(void);
extern void _interrupts_irq10(void);
extern void _interrupts_irq11(void);
extern void _interrupts_irq12(void);
extern void _interrupts_irq13(void);
extern void _interrupts_irq14(void);
extern void _interrupts_irq15(void);

extern void _interrupts_unexpected(void);

extern void _interrupts_syscall(void);


#define SIZE_INTERRUPTS 16

#define IOAPIC

#define _intr_add(list, t) \
	do { \
		if (t == NULL) \
			break; \
		if (*list == NULL) { \
			t->next = t; \
			t->prev = t; \
			(*list) = t; \
			break; \
		} \
		t->prev = (*list)->prev; \
		(*list)->prev->next = t; \
		t->next = (*list); \
		(*list)->prev = t; \
	} while (0)


#define _intr_remove(list, t) \
	do { \
		if (t == NULL) \
			break; \
		if ((t->next == t) && (t->prev == t)) \
			(*list) = NULL; \
		else { \
			t->prev->next = t->next; \
			t->next->prev = t->prev; \
			if (t == (*list)) \
				(*list) = t->next; \
		} \
		t->next = NULL; \
		t->prev = NULL; \
	} while (0)


struct {
	spinlock_t spinlocks[SIZE_INTERRUPTS];
	intr_handler_t *handlers[SIZE_INTERRUPTS];
	unsigned int counters[SIZE_INTERRUPTS];
} interrupts;


void _interrupts_apicACK(unsigned int n)
{
	if (n >= SIZE_INTERRUPTS)
		return;

#ifndef IOAPIC
	if (n < 8) {
		hal_outb((void *)0x20, 0x60 | n);
	}
	else {
		hal_outb((void *)0x20, 0x62);
		hal_outb((void *)0xa0, 0x60 | (n - 8));
	}
#else
	/* Write to Local APIC EOI register */
	*((volatile u32 *) 0xFEE000B0) = 0;
	//lib_printf("ACK IRQ: %x CPU: %x\n", n, getCpuID());

#endif
	return;
}

#define IOREGSEL 0xfec00000
#define IOWIN 0xfec00010

#define IOAPIC_RET_OFF 0x10

#define IOAPIC_DELMOD_FIXED 0x00 << 8
#define IOAPIC_DELMOD_LOWEST_PRIORITY 0x01 << 8

#define IOAPIC_DESTMOD_PHY 0x0
#define IOAPIC_DESTMOD_LOG 0x1 << 11

#define IOAPIC_INTMASK 0x1 << 16

void io_apic_write_ret2(u8 index, u32 higher, u32 lower)
{
	u32 offset = IOAPIC_RET_OFF + 2 * index + 1;
	__asm__ volatile(" \
		movl %0, (0xfec00000); \
		movl %1, (0xfec00010); \
		decl %0; \
		movl %0, (0xfec00000); \
		movl %2, (0xfec00010);"
		: \
		: "r" (offset), "r" (higher), "r" (lower)\
		:);


	// *((u8 *) IOREGSEL) = offset + 1;
	// *((u32 *) IOWIN) = (u32) (val >> 32);

	// while (*((u32 *) IOWIN) != (u32) (val >> 32)) {lib_printf("w");};

	// *((u8 *) IOREGSEL) = offset;
	// *((u32 *) IOWIN) = (u32) val;

	// while (*((u32 *) IOWIN) != (u32) (val)) {};
}

u64 io_apic_read_ret(u8 index)
{
	u8 offset = IOAPIC_RET_OFF + 2 * index;
	volatile u64 result = 0;
	volatile u32 *ioregsel = IOREGSEL;
	volatile u32 *iowin = IOWIN;

	*ioregsel = offset + 1;
	result = *iowin;
	result = result << 32;
	*ioregsel = offset;
	result |= *iowin;


	return result;
}

int interrupts_dispatchIRQ(unsigned int n, cpu_context_t *ctx)
{
	intr_handler_t *h;
	int reschedule = 0;


	if (n >= SIZE_INTERRUPTS)
		return 0;

	hal_spinlockSet(&interrupts.spinlocks[n]);
	volatile u32 *tpr = ((u32 *) 0xFEE00080);
	volatile u32 *apr = ((u32 *) 0xFEE00090);
	volatile u32 *ppr = ((u32 *) 0xFEE000A0);
	volatile u32 esp = 0;
	u8 cpuid = getCpuID();


	lib_printf("IRQ: %d CPU: %x\n", n, getCpuID(), esp);
	//*tpr = (*tpr + 1) % 8; 
	//*tpr = 0xff;

	// volatile int current_proc = (io_apic_read_ret(2) >> 56) & 0xf;
	// io_apic_write_ret2(2, ((current_proc + 1) % 8) << 24,
	// 					IOAPIC_DESTMOD_PHY |
	// 					 IOAPIC_DELMOD_FIXED |
	// 					 (32 + 0)); /* Interrupt Vector */



	interrupts.counters[n]++;

	if ((h = interrupts.handlers[n]) != NULL) {
		do {
			if (h->f(n, ctx, h->data))
				reschedule = 1;
		} while ((h = h->next) != interrupts.handlers[n]);
	}

	hal_spinlockClear(&interrupts.spinlocks[n]);

	if (n == 0)
		return 0;
	return reschedule;
}


int hal_interruptsSetHandler(intr_handler_t *h)
{
	if (h == NULL || h->f == NULL || h->n >= SIZE_INTERRUPTS)
		return -EINVAL;

	hal_spinlockSet(&interrupts.spinlocks[h->n]);
	_intr_add(&interrupts.handlers[h->n], h);
	hal_spinlockClear(&interrupts.spinlocks[h->n]);

	return EOK;
}


int hal_interruptsDeleteHandler(intr_handler_t *h)
{
	if (h == NULL || h->f == NULL || h->n >= SIZE_INTERRUPTS)
		return -EINVAL;

	hal_spinlockSet(&interrupts.spinlocks[h->n]);
	_intr_remove(&interrupts.handlers[h->n], h);
	hal_spinlockClear(&interrupts.spinlocks[h->n]);

	return EOK;
}


/* Function setups interrupt stub in IDT */
__attribute__ ((section (".init"))) int _interrupts_setIDTEntry(unsigned int n, void *addr, u32 type)
{
	u32 w0, w1;
	u32 *idtr;

	if (n > 255)
		return -EINVAL;

	w0 = ((u32)addr & 0xffff0000);
	w1 = ((u32)addr & 0x0000ffff);

	w0 |= IGBITS_DPL3 | IGBITS_PRES | IGBITS_SYSTEM | type;
	w1 |= (SEL_KCODE << 16);

	idtr = *(u32 **)&syspage->idtr[2];
	idtr[n * 2 + 1] = w0;
	idtr[n * 2] = w1;

	return EOK;
}

// #define IOREGSEL 0xfec00000
// #define IOWIN 0xfec00010

// #define IOAPIC_RET_OFF 0x10

// #define IOAPIC_DELMOD_FIXED 0x00 << 8
// #define IOAPIC_DELMOD_LOWEST_PRIORITY 0x01 << 8

// #define IOAPIC_DESTMOD_PHY 0x0
// #define IOAPIC_DESTMOD_LOG 0x1 << 11

// #define IOAPIC_INTMASK 0x1 << 16

// void io_apic_read(void)
// {
// 	*((u8 *) IOREGSEL) = 0;
// 	lib_printf("io apic id: %x\n", *((u32 *) IOWIN));
// }

// u32 io_apic_version(void)
// {
// 	u32 version_reg = 0;
// 	*((u8 *) IOREGSEL) = 1;
// 	version_reg = *((u32 *) IOWIN);
// 	lib_printf("io apic version_register: %x\n", version_reg);

// 	return version_reg;
// }

#define IOREGSEL 0xfec00000
#define IOWIN 0xfec00010

void io_apic_write_id(u8 id)
{
	*((u8 *) IOREGSEL) = 0;
	*((u32 *) IOWIN) = id << 24;
}

// void io_apic_write_ret(u8 index, u32 higher, u32 lower)
// {
// 	u32 offset = IOAPIC_RET_OFF + 2 * index + 1;

// 	lib_printf("offset: %x, higher: %x, lower: %x\n", offset, higher, lower);
// 	__asm__ volatile(" \
// 		movl %0, (0xfec00000); \
// 		movl %1, (0xfec00010); \
// 		decl %0; \
// 		movl %0, (0xfec00000); \
// 		movl %2, (0xfec00010);"
// 		: \
// 		: "r" (offset), "r" (higher), "r" (lower)\
// 		:);


// 	// *((u8 *) IOREGSEL) = offset + 1;
// 	// *((u32 *) IOWIN) = (u32) (val >> 32);

// 	// while (*((u32 *) IOWIN) != (u32) (val >> 32)) {lib_printf("w");};

// 	// *((u8 *) IOREGSEL) = offset;
// 	// *((u32 *) IOWIN) = (u32) val;

// 	// while (*((u32 *) IOWIN) != (u32) (val)) {};

// }

// u64 io_apic_read_ret(u8 index)
// {
// 	u8 offset = IOAPIC_RET_OFF + 2 * index;
// 	u32 result = 0;

// 	*((u8 *) IOREGSEL) = offset;
// 	result = *((u32 *) IOWIN);

// 	lib_printf("i: %d val: %08X ", index, result);

// 	*((u8 *) IOREGSEL) = offset + 1;
// 	result = *((u32 *) IOWIN);
// 	lib_printf("%08X\n", result);

// 	return result;
// }



__attribute__ ((section (".init"))) void _hal_interruptsInit(void)
{
	unsigned int k;

#ifndef IOAPIC
	/* Initialize interrupt controllers (8259A) */
	hal_outb((void *)0x20, 0x11);  /* ICW1 */
	hal_outb((void *)0x21, 0x20);  /* ICW2 (Master) */
	hal_outb((void *)0x21, 0x04);  /* ICW3 (Master) */
	hal_outb((void *)0x21, 0x01);  /* ICW4 */

	hal_outb((void *)0xa0, 0x11);  /* ICW1 (Slave) */
	hal_outb((void *)0xa1, 0x28);  /* ICW2 (Slave) */
	hal_outb((void *)0xa1, 0x02);  /* ICW3 (Slave) */
	hal_outb((void *)0xa1, 0x01);  /* ICW4 (Slave) */
#else
	/* Disable 8259A */
	hal_outb((void *) 0xa1, 0xff);
	hal_outb((void *) 0x21, 0xff);

	/* Enable IMCR Register */
	hal_outb((void *) 0x22,0x70);
    hal_outb((void *) 0x23,0x01);

	u32 spurious_reg = 0;
	__asm__ volatile(" \
		movl (0xfee000f0), %%eax; \
		movl %%eax, %0;"
		: "=g" (spurious_reg) \
		: \
		: "%eax");


	u64 apic_msr = hal_rdmsr(0x1b);
	lib_printf("APIC MSR: %x\n", apic_msr);
	lib_printf("APIC is BSP: %x\n", (apic_msr >> 8) & 1);
	lib_printf("APIC is enabled: %x\n", (apic_msr >> 11) & 1);

	lib_printf("APIC spurious reg: %x\n", spurious_reg);
	u32 ver_reg = io_apic_version();
	io_apic_write_id(8);



	// u8 max_entry = (ver_reg >> 16) & 0xff;
	// u8 apic_ver = ver_reg & 0xff;
	// lib_printf("Max entry: %d Version: %d\n", max_entry, apic_ver);


	// unsigned int i;
	// for (i = 0; i < 16; i++) {
	// 	io_apic_write_ret(i, 0,
	// 					 IOAPIC_INTMASK |
	// 					 IOAPIC_DESTMOD_PHY |
	// 					 IOAPIC_DELMOD_FIXED |
	// 					 (32 + i)); /* Interrupt Vector */
	// }

	// /* Unmask clock interrupt */
	// io_apic_write_ret(2, 1 << 24, IOAPIC_DESTMOD_PHY |
	// 					 IOAPIC_DELMOD_FIXED |
	// 					 (32 + 0)); /* Interrupt Vector */

	// /* Unmask COM1 interrupt */
	// io_apic_write_ret(4, 1 << 24, IOAPIC_DESTMOD_PHY |
	// 					 IOAPIC_DELMOD_FIXED |
	// 					 (32 + 4)); /* Interrupt Vector */

	// io_apic_read();

	// for (i = 0; i < 16; i++) {
	// 	io_apic_read_ret(i);
	// }
#endif

	/* Set stubs for hardware interrupts */
	_interrupts_setIDTEntry(32 + 0,  _interrupts_irq0, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 1,  _interrupts_irq1, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 2,  _interrupts_irq2, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 3,  _interrupts_irq3, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 4,  _interrupts_irq4, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 5,  _interrupts_irq5, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 6,  _interrupts_irq6, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 7,  _interrupts_irq7, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 8,  _interrupts_irq8, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 9,  _interrupts_irq9, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 10, _interrupts_irq10, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 11, _interrupts_irq11, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 12, _interrupts_irq12, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 13, _interrupts_irq13, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 14, _interrupts_irq14, IGBITS_IRQEXC);
	_interrupts_setIDTEntry(32 + 15, _interrupts_irq15, IGBITS_IRQEXC);

	for (k = 0; k < SIZE_INTERRUPTS; k++) {
		interrupts.handlers[k] = NULL;
		interrupts.counters[k] = 0;
		hal_spinlockCreate(&interrupts.spinlocks[k], "interrupts.spinlocks[]");
	}

	/* Set stubs for unhandled interrupts */
	for (; k < 256 - SIZE_INTERRUPTS; k++)
		_interrupts_setIDTEntry(32 + k, _interrupts_unexpected, IGBITS_IRQEXC);

	/* Set stub for syscall */
/*	_interrupts_setIDTEntry(0x80, _interrupts_syscall, IGBITS_TRAP); */
	_interrupts_setIDTEntry(0x80, _interrupts_syscall, IGBITS_IRQEXC);

	return;
}
