/*
 * Phoenix-RTOS
 *
 * Operating system kernel
 *
 * Kernel initialization
 *
 * Copyright 2012-2017 Phoenix Systems
 * Copyright 2001, 2005-2006 Pawel Pisarczyk
 * Author: Pawel Pisarczyk, Aleksander Kaminski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include HAL

#include "lib/lib.h"
#include "vm/vm.h"
#include "proc/proc.h"
#include "posix/posix.h"
#include "syscalls.h"
#include "test/test.h"
#include "programs.h"


struct {
	vm_map_t kmap;
	vm_object_t kernel;
	page_t *page;
	void *stack;
	size_t stacksz;
} main_common;


void main_initthr(void *unused)
{
	int i, res;
	syspage_program_t *prog;
	int xcount = 0;
	char *cmdline = syspage->arg, *end;
	char *argv[32], *arg, *argend;

	/* Enable locking and multithreading related mechanisms */
	_hal_start();

	lib_printf("main: Decoding programs from data segment\n");
	programs_decode(&main_common.kmap, &main_common.kernel);

	lib_printf("main: Starting syspage programs:");
	for (i = 0; i < syspage->progssz; i++)
		lib_printf(" '%s',", syspage->progs[i].cmdline);
	lib_printf("\b \n");

	posix_init();
	posix_clone(-1);

	/* Free memory used by initial stack */
	/*vm_munmap(&main_common.kmap, main_common.stack, main_common.stacksz);
	vm_pageFree(p);*/

	/* Set stdin, stdout, stderr ports */
//	proc_fileAdd(&h, &oid, 0);
//	proc_fileAdd(&h, &oid, 0);
//	proc_fileAdd(&h, &oid, 0);

	argv[0] = NULL;

	while (cmdline != NULL && *cmdline != '\0') {
		end = cmdline;
		while (*end && *(++end) != ' ');
		while (*end && *end == ' ')
			*(end++) = 0;
		if (*cmdline == 'X' && ++xcount) {
			i = 0;
			argend = cmdline;

			while (i < sizeof(argv) / sizeof(*argv) - 1) {
				arg = ++argend;
				while (*argend && *argend != ';')
					argend++;

				argv[i++] = arg;

				if (!*argend)
					break;

				*argend = 0;
			}
			argv[i++] = NULL;

			if (i == sizeof(argv) / sizeof(*argv))
				lib_printf("main: truncated arguments for command '%s'\n", argv[0]);

			/* Start program loaded into memory */
			for (prog = syspage->progs, i = 0; i < syspage->progssz; i++, prog++) {
				if (!hal_strcmp(cmdline + 1, prog->cmdline)) {
					argv[0] = prog->cmdline;
					res = proc_syspageSpawn(prog, prog->cmdline, argv);
					if (res < 0) {
						lib_printf("main: failed to spawn %s (%d)\n", argv[0], res);
					}
				}
			}
		}

		cmdline = end;
	}

	if (!xcount && syspage->progssz != 0) {
		argv[1] = NULL;
		/* Start all syspage programs */
		for (prog = syspage->progs, i = 0; i < syspage->progssz; i++, prog++) {
				argv[0] = prog->cmdline;
				res = proc_syspageSpawn(prog, prog->cmdline, argv);
				if (res < 0) {
					lib_printf("main: failed to spawn %s (%d)\n", argv[0], res);
				}
		}
	}

	/* Reopen stdin, stdout, stderr */
//	proc_lookup("/dev/console", &oid);

//	proc_fileSet(0, 3, &oid, 0, 0);
//	proc_fileSet(1, 3, &oid, 0, 0);
//	proc_fileSet(2, 3, &oid, 0, 0);

	for (;;)
		proc_reap();
}

#define IOREGSEL 0xfec00000
#define IOWIN 0xfec00010

#define IOAPIC_RET_OFF 0x10

#define IOAPIC_DELMOD_FIXED 0x00 << 8
#define IOAPIC_DELMOD_LOWEST_PRIORITY 0x01 << 8

#define IOAPIC_DESTMOD_PHY 0x0
#define IOAPIC_DESTMOD_LOG 0x1 << 11

#define IOAPIC_INTMASK 0x1 << 16

void io_apic_read(void)
{
	*((u8 *) IOREGSEL) = 0;
	lib_printf("io apic id: %x\n", *((u32 *) IOWIN));
}

u32 io_apic_version(void)
{
	u32 version_reg = 0;
	*((u8 *) IOREGSEL) = 1;
	version_reg = *((u32 *) IOWIN);
	lib_printf("io apic version_register: %x\n", version_reg);

	return version_reg;
}

void io_apic_write_ret(u8 index, u32 higher, u32 lower)
{
	u32 offset = IOAPIC_RET_OFF + 2 * index + 1;

	lib_printf("offset: %x, higher: %x, lower: %x\n", offset, higher, lower);
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

int main(void)
{
	char s[128];

	_hal_init();

	hal_consolePrint(ATTR_BOLD, "Phoenix-RTOS microkernel v. " VERSION "\n");
	lib_printf("hal: %s\n", hal_cpuInfo(s));
	lib_printf("hal: %s\n", hal_cpuFeatures(s, sizeof(s)));

	_vm_init(&main_common.kmap, &main_common.kernel);
	_proc_init(&main_common.kmap, &main_common.kernel);
	_syscalls_init();

	/* Start tests */

	/*
	test_proc_threads1();
	test_vm_kmallocsim();
	test_proc_conditional();
	test_vm_alloc();
	test_vm_kmalloc();
	test_proc_exit();
	*/

	proc_start(main_initthr, NULL, (const char *)"init");

	unsigned int i;
	for (i = 0; i < 16; i++) {
		io_apic_write_ret(i, 0,
						 IOAPIC_INTMASK |
						 IOAPIC_DESTMOD_PHY |
						 IOAPIC_DELMOD_FIXED |
						 (32 + i)); /* Interrupt Vector */
	}



	// // /* Unmask clock interrupt */
	// io_apic_write_ret(2, 0 << 24, IOAPIC_DESTMOD_PHY |
	// 					 IOAPIC_DELMOD_FIXED |
	// 					 (32 + 0)); /* Interrupt Vector */

	// // /* Unmask COM1 interrupt */
	// io_apic_write_ret(4, 0 << 24, IOAPIC_DESTMOD_PHY |
	// 					 IOAPIC_DELMOD_FIXED |
	// 					 (32 + 4)); /* Interrupt Vector */

	/* Start scheduling, leave current stack */
	hal_cpuEnableInterrupts();
	hal_cpuReschedule(NULL);

	return 0;
}
