/*
 *  this is a patchfinder
 *  but bad
 */

#ifndef patchfinder_h
#define patchfinder_h

struct offsets_t {
	uint32_t mount_common;
	uint32_t lwvm1;
	uint32_t lwvm2;
	uint32_t lwvm_call;
	uint32_t lwvm_call_offset;
	uint32_t sbops;
	uint32_t substrate1;
	uint32_t substrate2;
	uint32_t proc_enforce;
	uint32_t cs_enforcement_disable_amfi;
	uint32_t PE_i_can_has_debugger_1;
	uint32_t PE_i_can_has_debugger_2;
	uint32_t PE_i_can_has_debugger_offset;
	uint32_t vm_fault_enter_patch;
	uint32_t vm_map_enter_patch;
	uint32_t csops;
	uint32_t mapForIO;
	uint32_t sandbox_call_i_can_has_debugger;
	uint32_t amfi_file_check_mmap;
	uint32_t allproc;
	uint32_t tfp0;
};

uint32_t	find_mount_common						(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_lwvm1								(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_lwvm2								(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_lwvm_call							(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_lwvm_call_offset					(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_sbops								(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_substrate1							(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_substrate2							(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t*	find_substrate1_and_2					(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_proc_enforce						(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_cs_enforcement_disable_amfi		(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_PE_i_can_has_debugger_1			(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_PE_i_can_has_debugger_2			(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_vm_fault_enter_patch				(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_vm_map_enter_patch					(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_csops								(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_mapForIO							(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_sandbox_call_i_can_has_debugger	(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_amfi_file_check_mmap				(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_allproc							(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_tfp0								(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t	find_PE_i_can_has_debugger_offset		(uint32_t region, uint8_t* kdata, size_t ksize, char* version);

#endif /* patchfinder_h */
