/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _POWERPC_ARCH_MODULE_H
#define _POWERPC_ARCH_MODULE_H

#ifdef CONFIG_MPROFILE_KERNEL
bool is_mprofile_mcount_callsite(const char *name, u32 *instruction);
#else
static inline bool is_mprofile_mcount_callsite(const char *name, u32 *instruction)
{
	return false;
}
#endif

#endif
