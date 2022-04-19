/*
 *  this is a patchfinder but bad
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "patchfinder.h"

/*
 *  iOS 9 only right now
 */

#define IS_IOS_9 1

static uint32_t bit_range(uint32_t x, int start, int end) {
	x = (x << (31 - start)) >> (31 - start);
	x = (x >> end);
	return x;
}

static uint32_t ror(uint32_t x, int places) {
	return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12) {
	if (bit_range(imm12, 11, 10) == 0) {
		switch (bit_range(imm12, 9, 8)) {
			case 0:
				return bit_range(imm12, 7, 0);
			case 1:
				return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
			case 2:
				return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
			case 3:
				return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
			default:
				return 0;
		}
	} else {
		uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
		return ror(unrotated_value, bit_range(imm12, 11, 7));
	}
}

static int insn_is_32bit(uint16_t* i) {
	return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_ldr_literal(uint16_t* i) {
	return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t* i) {
	if ((*i & 0xF800) == 0x4800) {
		return (*i >> 8) & 7;
	} else if ((*i & 0xFF7F) == 0xF85F) {
		return (*(i + 1) >> 12) & 0xF;
	} else {
		return 0;
	}
}

static int insn_ldr_literal_imm(uint16_t* i) {
	if ((*i & 0xF800) == 0x4800) {
		return (*i & 0xFF) << 2;
	} else if ((*i & 0xFF7F) == 0xF85F) {
		return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
	} else {
		return 0;
	}
}

int insn_ldr_reg_rt(uint16_t* i) {
	if ((*i & 0xFE00) == 0x5800) {
		return *i & 0x7;
	} else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000) {
		return (*(i + 1) >> 12) & 0xF;
	} else {
		return 0;
	}
}

int insn_ldr_reg_rm(uint16_t* i) {
	if ((*i & 0xFE00) == 0x5800) {
		return (*i >> 6) & 0x7;
	} else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000) {
		return *(i + 1) & 0xF;
	} else {
		return 0;
	}
}

static int insn_is_add_reg(uint16_t* i) {
	if ((*i & 0xFE00) == 0x1800) {
		return 1;
	} else if ((*i & 0xFF00) == 0x4400) {
		return 1;
	} else if ((*i & 0xFFE0) == 0xEB00) {
		return 1;
	} else {
		return 0;
	}
}

static int insn_add_reg_rd(uint16_t* i) {
	if ((*i & 0xFE00) == 0x1800) {
		return (*i & 7);
	} else if ((*i & 0xFF00) == 0x4400) {
		return (*i & 7) | ((*i & 0x80) >> 4);
	} else if ((*i & 0xFFE0) == 0xEB00) {
		return (*(i + 1) >> 8) & 0xF;
	} else {
		return 0;
	}
}

static int insn_add_reg_rn(uint16_t* i) {
	if ((*i & 0xFE00) == 0x1800) {
		return ((*i >> 3) & 7);
	} else if ((*i & 0xFF00) == 0x4400) {
		return (*i & 7) | ((*i & 0x80) >> 4);
	} else if ((*i & 0xFFE0) == 0xEB00) {
		return (*i & 0xF);
	} else {
		return 0;
	}
}

static int insn_add_reg_rm(uint16_t* i) {
	if ((*i & 0xFE00) == 0x1800) {
		return (*i >> 6) & 7;
	} else if ((*i & 0xFF00) == 0x4400) {
		return (*i >> 3) & 0xF;
	} else if ((*i & 0xFFE0) == 0xEB00) {
		return *(i + 1) & 0xF;
	} else {
		return 0;
	}
}

static int insn_is_movt(uint16_t* i) {
	return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t* i) {
	return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t* i) {
	return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t* i) {
	if ((*i & 0xF800) == 0x2000) {
		return 1;
	} else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) {
		return 1;
	} else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) {
		return 1;
	} else {
		return 0;
	}
}

static int insn_mov_imm_rd(uint16_t* i) {
	if ((*i & 0xF800) == 0x2000) {
		return (*i >> 8) & 7;
	} else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) {
		return (*(i + 1) >> 8) & 0xF;
	} else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) {
		return (*(i + 1) >> 8) & 0xF;
	} else {
		return 0;
	}
}

static int insn_mov_imm_imm(uint16_t* i) {
	if ((*i & 0xF800) == 0x2000) {
		return *i & 0xF;
	} else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0) {
		return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
	} else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0) {
		return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
	} else {
		return 0;
	}
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t* find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, uint32_t address) {
	uint16_t* current_instruction = insn;
	uint32_t value[16];
	memset(value, 0, sizeof(value));

	while ((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize)) {
		if (insn_is_mov_imm(current_instruction)) {
			value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
		} else if (insn_is_ldr_literal(current_instruction)) {
			uintptr_t literal_address  = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
			if (literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize)) {
				value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
			}
		} else if (insn_is_movt(current_instruction)) {
			int reg = insn_movt_rd(current_instruction);
			value[reg] |= insn_movt_imm(current_instruction) << 16;
			if (value[reg] == address) {
				return current_instruction;
			}
		} else if (insn_is_add_reg(current_instruction)) {
			int reg = insn_add_reg_rd(current_instruction);
			if (insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
				value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
				if (value[reg] == address) {
					return current_instruction;
				}
			}
		}

		current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
	}

	return NULL;
}

struct find_search_mask {
	uint16_t mask;
	uint16_t value;
};

// Search the range of kdata for a series of 16-bit values that match the search mask.
static uint16_t* find_with_search_mask(uint32_t region, uint8_t* kdata, size_t ksize, int num_masks, const struct find_search_mask* masks) {
	uint16_t* end = (uint16_t*)(kdata + ksize - (num_masks * sizeof(uint16_t)));
	uint16_t* cur;
	for (cur = (uint16_t*)kdata; cur <= end; cur++) {
		int matched = 1;
		int i;
		for (i = 0; i < num_masks; i++) {
			if ((*(cur + i) & masks[i].mask) != masks[i].value) {
				matched = 0;
				break;
			}
		}

		if (matched)
			return cur;
	}

	return NULL;
}

uint32_t find_mount_common(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	float version_float = strtof(version, 0);
	for (uint32_t i = 0; i < ksize; i++) {
		if (version_float == (float)9.3) {
			if (*(uint64_t*)&kdata[i] == 0x2501d1030f01f01b && *(uint32_t*)&kdata[i+0x8] == 0x2501e016) {
				uint32_t mount_common = i + 0x5;
				printf("[*] found mount_common: 0x%08x\n", mount_common);
				return mount_common;
			}
		} else if (version_float == (float)9.0) {
			if ((*(uint64_t*)&kdata[i] & 0x00ffffffffffffff) == 0xd4d0060f01f010) {
				uint32_t mount_common = i + 0x5;
				printf("[*] found mount_common: 0x%08x\n", mount_common);
				return mount_common;
			}
		} else {
			if (*(uint32_t*)&kdata[i] == 0x0f01f010 && *(uint8_t*)&kdata[i+0x5] == 0xd0 && *(uint32_t*)&kdata[i+0xe] == 0x0f40f010 && *(uint8_t*)&kdata[i+0x13] == 0xd0) {
				uint32_t mount_common = i + 0x5;
				printf("[*] found mount_common: 0x%08x\n", mount_common);
				return mount_common;
			}
		}
	}
	return -1;
}

uint32_t find_lwvm1(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	float version_float = strtof(version, 0);
	for (uint32_t i = 0; i < ksize; i++) {
		if (version_float == (float)9.3) {
			if (*(uint64_t*)&kdata[i] == 0x2501d1030f01f01b && *(uint32_t*)&kdata[i+0x8] == 0x2501e016) {
				uint32_t lwvm1 = i - 0x10;
				printf("[*] found lwvm1: 0x%08x\n", lwvm1);
				return lwvm1;
			}
		} else if (version_float == (float)9.0) {
			if ((*(uint64_t*)&kdata[i] & 0x00ffffffffffffff) == 0xd4d0060f01f010) {
				uint32_t lwvm1 = i - 0x10;
				printf("[*] found lwvm1: 0x%08x\n", lwvm1);
				return lwvm1;
			}
		} else {
			if (*(uint32_t*)&kdata[i] == 0x0f01f010 && *(uint8_t*)&kdata[i+0x5] == 0xd0 && *(uint32_t*)&kdata[i+0xe] == 0x0f40f010 && *(uint8_t*)&kdata[i+0x13] == 0xd0) {
				uint32_t lwvm1 = i - 0x10;
				printf("[*] found lwvm1: 0x%08x\n", lwvm1);
				return lwvm1;
			}
		}
	}
	return -1;
}

uint32_t find_lwvm2(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	float version_float = strtof(version, 0);
	for (uint32_t i = 0; i < ksize; i++) {
		if (version_float == (float)9.3) {
			if (*(uint64_t*)&kdata[i] == 0x2501d1030f01f01b && *(uint32_t*)&kdata[i+0x8] == 0x2501e016) {
				uint32_t lwvm2 = i + 0x4;
				printf("[*] found lwvm2: 0x%08x\n", lwvm2);
				return lwvm2;
			}
		} else if (version_float == (float)9.0) {
			if ((*(uint64_t*)&kdata[i] & 0x00ffffffffffffff) == 0xd4d0060f01f010) {
				uint32_t lwvm2 = i + 0x4;
				printf("[*] found lwvm2: 0x%08x\n", lwvm2);
				return lwvm2;
			}
		} else {
			if (*(uint32_t*)&kdata[i] == 0x0f01f010 && *(uint8_t*)&kdata[i+0x5] == 0xd0 && *(uint32_t*)&kdata[i+0xe] == 0x0f40f010 && *(uint8_t*)&kdata[i+0x13] == 0xd0) {
				uint32_t lwvm2 = i + 0x4;
				printf("[*] found lwvm2: 0x%08x\n", lwvm2);
				return lwvm2;
			}
		}
	}
	return -1;
}

uint32_t find_lwvm_call(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	char* faceable = memmem(kdata, ksize, "\xce\xab\x1e\xef\xfa\xce\xab\x1e", 8);
	if (!faceable)
		return -1;
	char* lwvm_call_pointer = faceable + 0x78;
	uint32_t lwvm_call = (uintptr_t)lwvm_call_pointer - (uintptr_t)kdata;
	printf("[*] found lwvm_call: 0x%08x\n", lwvm_call);
	return lwvm_call;
}

uint32_t find_lwvm_call_offset(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	for (uint32_t i = 0; i < ksize; i += 2) {
		if (*(uint64_t*)&kdata[i] == 0xf010798044406da0 && *(uint32_t*)&kdata[i+0x8] == 0xd0060f01 && *(uint16_t*)&kdata[i+0xC] == 0x4620) {
			uint32_t lwvm_call_offset = i + 1;
			printf("[*] found lwvm_call_offset: 0x%08x\n", lwvm_call_offset);
			return lwvm_call_offset;
		}
	}
	return -1;
}

uint32_t find_sbops(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	char* seatbelt_sandbox_policy = memmem(kdata,
										   ksize,
										   "Seatbelt sandbox policy",
										   strlen("Seatbelt sandbox policy"));
	printf("[*] seatbelt_sandbox_policy 0x%08lx\n",
		   (uintptr_t)seatbelt_sandbox_policy);
	if (!seatbelt_sandbox_policy)
		return -1;
	
	uint32_t seatbelt =   (uintptr_t)seatbelt_sandbox_policy
						- (uintptr_t)kdata
						+ region;
	printf("[*] seatbelt: 0x%08x\n", seatbelt);
	
	char* seatbelt_sandbox_policy_ptr = memmem(kdata,
											   ksize,
											   (char*)&seatbelt,
											   sizeof(seatbelt));
	
	printf("[*] seatbelt_sandbox_policy_ptr 0x%08lx\n",
		   (uintptr_t)seatbelt_sandbox_policy_ptr);
	if (!seatbelt_sandbox_policy_ptr)
		return -1;
	
	uint32_t ptr_to_seatbelt =   (uintptr_t)seatbelt_sandbox_policy_ptr
							   - (uintptr_t)kdata;
	uint32_t sbops = ptr_to_seatbelt + 0x24;
	printf("[*] found sbops: 0x%08x\n", sbops);
	
	return sbops;
}

uint32_t find_substrate1(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	for (uint32_t i = 0; i < ksize; i++) {
		if (*(uint64_t*)&kdata[i] == 0x0000f8dabf1e2800 && *(uint32_t*)&kdata[i+0x8] == 0x0004f040) {
			uint32_t substrate1 = i + 0x2 - 0x49000;
			printf("[*] found substrate1: 0x%08x\n", substrate1);
			return substrate1;
		}
	}
	return -1;
}

uint32_t find_substrate2(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	for (uint32_t i = 0; i < ksize; i++) {
		if (*(uint64_t*)&kdata[i] == 0x0000f8dabf1e2800 && *(uint32_t*)&kdata[i+0x8] == 0x0004f040) {
			uint32_t substrate2 = i + 0x16 - 0x49000;
			printf("[*] found substrate2: 0x%08x\n", substrate2);
			return substrate2;
		}
	}
	return -1;
}

uint32_t* find_substrate1_and_2(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	uint32_t* one_and_two = malloc(2 * sizeof(uint32_t));
	for (uint32_t i = 0; i < ksize; i++) {
		if (*(uint64_t*)&kdata[i] == 0x0000f8dabf1e2800 && *(uint32_t*)&kdata[i+0x8] == 0x0004f040) {
			uint32_t substrate1 = i + 0x2 - 0x49000;
			uint32_t substrate2 = i + 0x16 - 0x49000;
			one_and_two[0] = substrate1;
			one_and_two[1] = substrate2;
			printf("[*] found substrate1: 0x%08x\n", substrate1);
			printf("[*] found substrate2: 0x%08x\n", substrate2);
			return one_and_two;
		}
	}
	return NULL;
}

uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	// adapted from daibutsu pf
	char* proc_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on process operations", strlen("Enforce MAC policy on process operations"));
	if (!proc_enforce_description)
		return -1;
	
	uint32_t proc_enforce_description_address = region + ((uintptr_t)proc_enforce_description - (uintptr_t)kdata);
	char* proc_enforce_description_ptr = memmem(kdata, ksize, (char*)&proc_enforce_description_address, sizeof(proc_enforce_description_address));
	if (!proc_enforce_description_ptr)
		return -1;
	
	uint32_t* proc_enforce_ptr = (uint32_t*)(proc_enforce_description_ptr - (5 * sizeof(uint32_t)));
	uint32_t proc_enforce = *proc_enforce_ptr - region;
	
	printf("[*] proc_enforce: 0x%08x\n", proc_enforce);
	
	return proc_enforce;
}

uint32_t find_cs_enforcement_disable_amfi(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	char* amfi = memmem(kdata, ksize, "com.apple.driver.AppleMobileFileIntegrity", strlen("com.apple.driver.AppleMobileFileIntegrity"));
	uint32_t cs_enforcement_disable_amfi = (uintptr_t)amfi - (uintptr_t)kdata + 0xb1;
	printf("[*] cs_enforcement_disable_amfi: 0x%08x\n", cs_enforcement_disable_amfi);
	return cs_enforcement_disable_amfi;
}

uint32_t find_PE_i_can_has_debugger_1(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	// XXX: TODO
	uint32_t PE_i_can_has_debugger_1 = 0x456170;
	printf("[*] found PE_i_can_has_debugger_1: 0x%08x\n", PE_i_can_has_debugger_1);
	return PE_i_can_has_debugger_1;
}

uint32_t find_PE_i_can_has_debugger_2(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	// XXX: TODO
	uint32_t PE_i_can_has_debugger_2 = 0x456070;
	printf("[*] found PE_i_can_has_debugger_2: 0x%08x\n", PE_i_can_has_debugger_2);
	return PE_i_can_has_debugger_2;
}

uint32_t find_vm_fault_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	const struct find_search_mask search_masks[] = {
		{0xF800, 0x6800}, // LDR R2, [Ry,#X]
		{0xF8FF, 0x2800}, // CMP Rx, #0
		{0xFF00, 0xD100}, // BNE x
		{0xFBF0, 0xF010}, // TST.W Rx, #0x200000
		{0x0F00, 0x0F00},
		{0xFF00, 0xD100}, // BNE x
		{0xFFF0, 0xF400}, // AND.W Rx, Ry, #0x100000
		{0xF0FF, 0x1080}
	};
	
	uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
	if (!insn)
		return 0;
	
	uint32_t vm_fault_enter_patch = ((uintptr_t)insn) - ((uintptr_t)kdata);
	printf("[*] found vm_fault_enter_patch: 0x%08x\n", vm_fault_enter_patch);
	
	return vm_fault_enter_patch;
}

uint32_t find_vm_map_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	const struct find_search_mask search_masks_90[] = {
		{0xFFF0, 0xF010}, // TST.W Rz, #4
		{0xFFFF, 0x0F04},
		{0xFF78, 0x4600}, // MOV Rx, R0 (?)
		{0xFFF0, 0xBF10}, // IT NE (?)
		{0xFFF0, 0xF020}, // BICNE.W		 Rk, Rk, #4
		{0xF0FF, 0x0004}
	};
	
	const struct find_search_mask search_masks_84[] = {
		{0xFFF0, 0xF000}, // AND.W Rx, Ry, #2
		{0xF0FF, 0x0002},
		{0xFFF0, 0xF010}, // TST.W Rz, #2
		{0xFFFF, 0x0F02},
		{0xFF00, 0xD000}, // BEQ   loc_xxx
		{0xF8FF, 0x2000}, // MOVS  Rk, #0
		{0xFFF0, 0xF010}, // TST.W Rz, #4
		{0xFFFF, 0x0F04}
	};

	const struct find_search_mask search_masks[] = {
		{0xFBE0, 0xF000},
		{0x8000, 0x0000},
		{0xFFF0, 0xF010},
		{0xFFFF, 0x0F02},
		{0xFF00, 0xD000},
		{0xF8FF, 0x2000},
		{0xFFF0, 0xF010},
		{0xFFFF, 0x0F04}
	};

	uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
	if (!insn)
		insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
	if (!insn) {
		insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
		if (!insn)
			return 0;
		insn += 2;
		uint32_t vm_map_enter_patch = ((uintptr_t)insn) - ((uintptr_t)kdata);
		printf("[*] found vm_map_enter_patch: 0x%08x\n", vm_map_enter_patch);
		
		return vm_map_enter_patch;
	}
	
	insn += 4;
	uint32_t vm_map_enter_patch = ((uintptr_t)insn) - ((uintptr_t)kdata);
	printf("[*] found vm_map_enter_patch: 0x%08x\n", vm_map_enter_patch);
	
	return vm_map_enter_patch;
}

uint32_t find_csops(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	const struct find_search_mask search_masks_90[] =
	{
		{0xFFF0, 0xF100},
		{0x0000, 0x0000},
		{0xFF80, 0x4600},
		{0xFC00, 0xF400},
		{0x0000, 0x0000},
		{0xFFF0, 0xF890},
		{0x0000, 0x0000},
		{0xFFF0, 0xF010},
		{0xFFFF, 0x0F01},
		{0xF800, 0xD000},
	};
	
	const struct find_search_mask search_masks[] =
	{
		{0xFC00, 0xF400},
		{0x0000, 0x0000},
		{0xF800, 0xE000},
		{0x0000, 0x0000},
		{0xFFF0, 0xF100},
		{0x0000, 0x0000},
		{0xFF80, 0x4600},
		{0xF800, 0xF000},
		{0x0000, 0x0000},
		{0xFF80, 0x4600},
		{0xFFF0, 0xF890},
		{0x0000, 0x0000},
		{0xFFF0, 0xF010},
		{0xFFFF, 0x0F01},
		{0xFC00, 0xF000},
		{0x0000, 0x0000}
	};

	uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
	if (!insn) {
		insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
		if (!insn)
			return 0;
		insn += 14;
	}
	else
		insn += 9;
	
	uint32_t csops = ((uintptr_t)insn) - ((uintptr_t)kdata);
	printf("[*] found csops: 0x%08x\n", csops);
	
	return csops;
}

uint32_t find_mapForIO(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	for (uint32_t i = 0; i < ksize; i++) {
		if (*(uint64_t*)&kdata[i] == 0xf010798044406da0 && *(uint32_t*)&kdata[i+0x8] == 0xd0060f01 && *(uint16_t*)&kdata[i+0xC] == 0x4620) {
			uint32_t mapForIO = i - 4;
			printf("[*] found mapForIO: 0x%08x\n", mapForIO);
			return mapForIO;
		}
	}
	return -1;
}

uint32_t find_sandbox_call_i_can_has_debugger(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	const struct find_search_mask search_masks_90[] =
	{
		{0xFFFF, 0xB590}, // PUSH {R4,R7,LR}
		{0xFFFF, 0xAF01}, // ADD  R7, SP, #4
		{0xFFFF, 0x2000}, // MOVS R0, #0
		{0xFFFF, 0x2400}, // MOVS R4, #0
		{0xF800, 0xF000}, // BL   i_can_has_debugger
		{0xD000, 0xD000},
		{0xFD07, 0xB100}  // CBZ  R0, loc_xxx
	};

	const struct find_search_mask search_masks[] =
	{
		{0xFFFF, 0xB590}, // PUSH {R4,R7,LR}
		{0xFFFF, 0x2000}, // MOVS R0, #0
		{0xFFFF, 0xAF01}, // ADD  R7, SP, #4
		{0xFFFF, 0x2400}, // MOVS R4, #0
		{0xF800, 0xF000}, // BL   i_can_has_debugger
		{0xD000, 0xD000},
		{0xFD07, 0xB100}  // CBZ  R0, loc_xxx
	};

	uint16_t* ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
	if (!ptr) {
		printf("[*] not 90...\n");
		ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
	}
	if (!ptr)
		return 0;

	uint32_t sandbox_call_i_can_has_debugger = (uintptr_t)ptr + 8 - ((uintptr_t)kdata);
	printf("[*] found sandbox_call_i_can_has_debugger: 0x%08x\n", sandbox_call_i_can_has_debugger);
	
	return sandbox_call_i_can_has_debugger;
}

// literally just the og patchfinder function but with char* version, which is unused, but is there because of old patches lol
// actually minor changes were made
// the return otherwise nah
uint32_t find_amfi_file_check_mmap(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
#if 0
	uint8_t* hook_execve = memmem(kdata, ksize, "AMFI: hook..execve() killing pid %u: %s\n", sizeof("AMFI: hook..execve() killing pid %u: %s\n"));
	//printf("%x\n", hook_execve - kdata);
	if (!hook_execve)
		return 0;
	
	// Find a reference to the "AMFI: hook..execve() killing pid ..." string.
	uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)hook_execve - (uintptr_t)kdata);
	//printf("%x\n", (uint8_t*)ref - kdata);
	if (!ref)
		return 0;

	uint32_t amfi_off = (uintptr_t)ref - (uintptr_t)kdata;
#endif
	
	uint8_t* rootless = memmem(kdata, ksize, "com.apple.rootless.install", sizeof("com.apple.rootless.install"));
	//printf("%x\n", (uint8_t*)rootless - kdata);
	if (!rootless)
		return 0;
	
	// Find a reference to the "com.apple.rootless.install" string.
	uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)rootless - (uintptr_t)kdata);
	//printf("%x\n", (uint8_t*)ref - kdata);
	if (!ref)
		return 0;
	
#if 0
	uint32_t rootless_off = (uintptr_t)ref - (uintptr_t)kdata;
	if (amfi_off > rootless_off ||
	   (amfi_off + 0x800) < rootless_off)
	{
		rootless = memmem(kdata+rootless_off, ksize-rootless_off, "com.apple.rootless.install", sizeof("com.apple.rootless.install"));
		if (!rootless)
			return 0;
		
		// Re-Find a reference to the "com.apple.rootless.install" string.
		ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)rootless - (uintptr_t)kdata);
		//printf("%x\n", (uint8_t*)ref - kdata);
		if (!ref)
			return 0;
		rootless_off = (uintptr_t)ref - (uintptr_t)kdata;
	}
#endif
	
	int i=0;
	while (1){
		if (i>16)
			return 0;
		if ((ref[i] & 0xfff0) == 0xbf10) // it ne
			break;
		i++;
	}
	
	ref += (i-1);
	
	uint32_t amfi_file_check_mmap = (uintptr_t)ref - (uintptr_t)kdata;
	printf("[*] found amfi_file_check_mmap: 0x%08x\n", amfi_file_check_mmap);
	
	return amfi_file_check_mmap;
}

uint32_t find_allproc(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	// XXX: TODO
	uint32_t allproc = 0x45717c;
	printf("[*] found allproc: 0x%08x\n", allproc);
	return allproc;
}

uint32_t find_tfp0(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	for (uint32_t i = 0; i < ksize; i++) {
		if (*(uint16_t*)&kdata[i] == 0x4630 && *(uint64_t*)&kdata[i + 6] == 0xf0000f00f1ba4682 && *(uint32_t*)&kdata[i + 0x10] == 0xf0014650) {
			// jesus christ john, this is ugly as FUCK
			for (int a = i; a > (i - 0x30); a -= 2) {
				if (*(uint16_t*)&kdata[a] == 0xb5f0) {
					for (int e = a; e < (a + 0x20); e += 2) {
						if (*(uint16_t*)&kdata[e] == 0x2e00) {
							uint32_t tfp0 = e + 0x4;
							printf("[*] found tfp0: 0x%08x\n", tfp0);
							return tfp0;
						}
					}
				}
			}
		}
	}
	return -1;
}

uint32_t find_PE_i_can_has_debugger_offset(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
	char* mem_shit = memmem(kdata, ksize, "\x40\xf2\xaa\x30\xc0\xf2\x02\x00", 8);
	uint32_t PE_i_can_has_debugger_offset = (uintptr_t)mem_shit - (uintptr_t)kdata + 8;
	printf("[*] found PE_i_can_has_debugger_offset: 0x%08x\n", PE_i_can_has_debugger_offset);
	return PE_i_can_has_debugger_offset;
}
