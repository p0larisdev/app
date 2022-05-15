//
//  patchfinder10.h
//  p0laris
//
//  Created by spv on 5/14/22.
//

#ifndef patchfinder10_h
#define patchfinder10_h

#include <stdio.h>
uint32_t find_mount_common10(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t find_mapForIO10(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t find_PE_i_can_has_debugger_offset10(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t find_nosuid_enforcement(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t find_tfp10(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t find_fuck(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t find_bxlr_gadget(uint32_t region, uint8_t* kdata, size_t ksize, char* version);
uint32_t find_amfi_memcmp(uint32_t region, uint8_t* kdata, size_t ksize, char* version);

#endif /* patchfinder10_h */
