/*
 * Phoenix-RTOS
 *
 * Operating system kernel
 *
 * Virtual memory manager - page allocator
 *
 * Copyright 2012, 2016, 2017 Phoenix Systems
 * Copyright 2001, 2005-2006 Pawel Pisarczyk
 * Author: Pawel Pisarczyk
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include HAL
#include "page.h"
#include "../../include/errno.h"
#include "../lib/lib.h"
#include "map.h"
#include "../proc/proc.h"


/* Last BSS symbol */
extern void *_end;


struct {
	size_t allocsz;
	size_t bootsz;
	size_t freesz;

	page_t *freeq;
	size_t freeqsz;

	lock_t lock;
} pages;


page_t *_page_alloc(size_t size, u8 flags)
{
	page_t *lh = pages.freeq;

	if (lh == NULL)
		return NULL;

	pages.freeq = lh->next;

	lh->next = NULL;
	lh->idx = hal_cpuGetLastBit(size);

	if (hal_cpuGetFirstBit(size) < lh->idx)
		lh->idx++;

	pages.freesz -= (1 << lh->idx);
	pages.allocsz += (1 << lh->idx);

	return lh;
}


page_t *vm_pageAlloc(size_t size, u8 flags)
{
	page_t *p;

	proc_lockSet(&pages.lock);
	p = _page_alloc(size, flags);
	proc_lockClear(&pages.lock);

	return p;
}


void _page_free(page_t *lh)
{
	lh->next = pages.freeq;
	pages.freeq = lh;

	pages.freesz += (1 << lh->idx);
	pages.allocsz -= (1 << lh->idx);

	return;
}


void vm_pageFree(page_t *lh)
{
	proc_lockSet(&pages.lock);
	_page_free(lh);
	proc_lockClear(&pages.lock);

	return;
}


int _page_remove(pmap_t *pmap, void *vaddr)
{
	return EOK;
}


void _page_showPages(void)
{
	return;
}


int page_map(pmap_t *pmap, void *vaddr, addr_t pa, int attr)
{
	return EOK;
}


page_t *_page_get(addr_t addr)
{
	return NULL;
}


void vm_pageFreeAt(pmap_t *pmap, void *vaddr)
{
}


int _page_sbrk(pmap_t *pmap, void **start, void **end)
{
	(*end) += SIZE_PAGE;

	return EOK;
}


void vm_pageGetStats(size_t *freesz)
{
	*freesz = pages.freesz;
}


void vm_pageinfo(meminfo_t *info)
{
	proc_lockSet(&pages.lock);

	info->page.alloc = pages.allocsz;
	info->page.free = pages.freesz;
	info->page.boot = pages.bootsz;
	info->page.sz = sizeof(page_t);

	proc_lockClear(&pages.lock);
}


void _page_init(pmap_t *pmap, void **bss, void **top)
{
	page_t *p;
	unsigned int i;

	proc_lockInit(&pages.lock);

	pages.freesz = VADDR_MAX - (unsigned int)(*bss);
	pages.bootsz = 0;

	pages.freeq = (*bss);
	pages.freeqsz = pages.freesz / SIZE_PAGE;

	(*bss) += pages.freeqsz * sizeof(page_t);
	(*top) = max((*top), (*bss));

	/* Prepare memory hash */
	pages.allocsz = (unsigned int)(*bss) - VADDR_MIN;
	pages.freesz -= pages.freeqsz * sizeof(page_t);

	/* Show statistics one the console */
	lib_printf("vm: Initializing page allocator %d/%d KB, page_t=%d\n", (pages.allocsz - pages.bootsz) / 1024,
		(pages.freesz + pages.allocsz ) / 1024, sizeof(page_t));

	/* Prepare allocation queue */
	for (p = pages.freeq, i = 0; i < pages.freeqsz; i++) {
		p->next = p + 1;
		p = p->next;
	}
	(pages.freeq + pages.freeqsz - 1)->next = NULL;

	return;
}
