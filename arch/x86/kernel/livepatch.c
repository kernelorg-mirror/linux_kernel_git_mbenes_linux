// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch.c - x86-specific Kernel Live Patching Core
 */

#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/livepatch.h>
#include <asm/text-patching.h>

/* Apply per-object alternatives. Based on x86 module_finalize() */
void arch_klp_init_object_loaded(struct klp_patch *patch,
				 struct klp_object *obj)
{
	int cnt;
	struct klp_modinfo *info;
	Elf_Shdr *s, *alt = NULL, *para = NULL;
	void *aseg, *pseg;
	const char *objname;
	char sec_objname[MODULE_NAME_LEN];
	char secname[KSYM_NAME_LEN];

	info = patch->mod->klp_info;
	objname = obj->name ? obj->name : "vmlinux";

	/* See livepatch core code for BUILD_BUG_ON() explanation */
	BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 128);

	for (s = info->sechdrs; s < info->sechdrs + info->hdr.e_shnum; s++) {
		/* Apply per-object .klp.arch sections */
		cnt = sscanf(info->secstrings + s->sh_name,
			     ".klp.arch.%55[^.].%127s",
			     sec_objname, secname);
		if (cnt != 2)
			continue;
		if (strcmp(sec_objname, objname))
			continue;
		if (!strcmp(".altinstructions", secname))
			alt = s;
		if (!strcmp(".parainstructions", secname))
			para = s;
	}

	if (alt) {
		aseg = (void *) alt->sh_addr;
		apply_alternatives(aseg, aseg + alt->sh_size);
	}

	if (para) {
		pseg = (void *) para->sh_addr;
		apply_paravirt(pseg, pseg + para->sh_size);
	}
}

void arch_klp_free_object_loaded(struct klp_patch *patch,
				 struct klp_object *obj)
{
	const char *objname, *secname;
	char sec_objname[MODULE_NAME_LEN];
	struct klp_modinfo *info;
	Elf64_Shdr *s;
	Elf64_Rela *rel;
	void *loc;
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

			switch (ELF64_R_TYPE(rel[i].r_info)) {
			case R_X86_64_NONE:
				break;
			case R_X86_64_64:
				*(u64 *)loc = 0;
				break;
			case R_X86_64_32:
				*(u32 *)loc = 0;
				break;
			case R_X86_64_32S:
				*(s32 *)loc = 0;
				break;
			case R_X86_64_PC32:
			case R_X86_64_PLT32:
				*(u32 *)loc = 0;
				break;
			case R_X86_64_PC64:
				*(u64 *)loc = 0;
				break;
			default:
				break;
			}
		}
	}
}
