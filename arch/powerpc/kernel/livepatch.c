// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch.c - powerpc-specific Kernel Live Patching Core
 */

#include <linux/livepatch.h>
#include <asm/code-patching.h>
#include "module.h"

void arch_klp_free_object_loaded(struct klp_patch *patch,
				 struct klp_object *obj)
{
	const char *objname, *secname, *symname;
	char sec_objname[MODULE_NAME_LEN];
	struct klp_modinfo *info;
	Elf64_Shdr *s;
	Elf64_Rela *rel;
	Elf64_Sym *sym;
	void *loc;
	u32 *instruction;
	int i, cnt;

	info = patch->mod->klp_info;
	objname = klp_is_module(obj) ? obj->name : "vmlinux";

	/* See livepatch core code for BUILD_BUG_ON() explanation */
	BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 128);

	/* For each klp relocation section */
	for (s = info->sechdrs; s < info->sechdrs + info->hdr.e_shnum; s++) {
		if (!(s->sh_flags & SHF_RELA_LIVEPATCH))
			continue;

		/*
		 * Format: .klp.rela.sec_objname.section_name
		 */
		secname = info->secstrings + s->sh_name;
		cnt = sscanf(secname, ".klp.rela.%55[^.]", sec_objname);
		if (cnt != 1) {
			pr_err("section %s has an incorrectly formatted name\n",
			       secname);
			continue;
		}

		if (strcmp(objname, sec_objname))
			continue;

		rel = (void *)s->sh_addr;
		for (i = 0; i < s->sh_size / sizeof(*rel); i++) {
			loc = (void *)info->sechdrs[s->sh_info].sh_addr
				+ rel[i].r_offset;
			sym = (Elf64_Sym *)info->sechdrs[info->symndx].sh_addr
				+ ELF64_R_SYM(rel[i].r_info);
			symname = patch->mod->core_kallsyms.strtab
				+ sym->st_name;

			if (ELF64_R_TYPE(rel[i].r_info) != R_PPC_REL24)
				continue;

			if (sym->st_shndx != SHN_UNDEF &&
			    sym->st_shndx != SHN_LIVEPATCH)
				continue;

			instruction = (u32 *)loc;
			if (is_mprofile_mcount_callsite(symname, instruction))
				continue;

			if (!instr_is_relative_link_branch(*instruction))
				continue;

			instruction += 1;
			*instruction = PPC_INST_NOP;
		}
	}
}
