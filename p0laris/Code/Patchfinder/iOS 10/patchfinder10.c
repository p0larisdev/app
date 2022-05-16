//
//  patchfinder10.c
//  p0laris
//
//  Created by spv on 5/14/22.
//

#include "patchfinder10.h"
#include <mach/vm_types.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include "mac_policy.h"
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

/* Find start of a section in a macho */
struct section *find_section(struct segment_command *seg, const char *name)
{
    struct section *sect, *fs = NULL;
    uint32_t i = 0;
    for (i = 0, sect = (struct section *)((uintptr_t)seg + (uintptr_t)sizeof(struct segment_command));
         i < seg->nsects;
         i++, sect = (struct section*)((uintptr_t)sect + sizeof(struct section)))
    {
        if (!strcmp(sect->sectname, name)) {
            fs = sect;
            break;
        }
    }
    return fs;
}

/* Find start of a load command in a macho */
struct load_command *find_load_command(struct mach_header *mh, uint32_t cmd)
{
    struct load_command *lc, *flc;
    
    lc = (struct load_command *)((uintptr_t)mh + sizeof(struct mach_header));
    
    while (1) {
        if ((uintptr_t)lc->cmd == cmd) {
            flc = (struct load_command *)(uintptr_t)lc;
            break;
        }
        lc = (struct load_command *)((uintptr_t)lc + (uintptr_t)lc->cmdsize);
    }
    return flc;
}

/* Find start of a segment in a macho */
struct segment_command *find_segment(struct mach_header *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command *s, *fs = NULL;
    lc = (struct load_command *)((uintptr_t)mh + sizeof(struct mach_header));
    while ((uintptr_t)lc < (uintptr_t)mh + (uintptr_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT) {
            s = (struct segment_command *)lc;
            if (!strcmp(s->segname, segname)) {
                fs = s;
                break;
            }
        }
        lc = (struct load_command *)((uintptr_t)lc + (uintptr_t)lc->cmdsize);
    }
    return fs;
}

/* Find offset of an exported symbol in a macho */
void* find_sym(struct mach_header *mh, const char *name) {
    struct segment_command* first = (struct segment_command*) find_load_command(mh, LC_SEGMENT);
    struct symtab_command* symtab = (struct symtab_command*) find_load_command(mh, LC_SYMTAB);
    vm_address_t vmaddr_slide = (vm_address_t)mh - (vm_address_t)first->vmaddr;
    
    char* sym_str_table = (char*) (((char*)mh) + symtab->stroff);
    struct nlist* sym_table = (struct nlist*)(((char*)mh) + symtab->symoff);
    
    for (int i = 0; i < symtab->nsyms; i++) {
        if (sym_table[i].n_value && !strcmp(name,&sym_str_table[sym_table[i].n_un.n_strx])) {
            return (void*)(uintptr_t)(sym_table[i].n_value + vmaddr_slide);
        }
    }
    return 0;
}

/* The rest */

/* Find the VM base for prelinked kexts in a kernelcache */
uint32_t find_kextbase(void *kernelcache, size_t size) {
    
    if (!(*(uint32_t*)&kernelcache[0] == 0xFEEDFACE)) {
        printf("This doesn't look like a kernelcache\n");
        return 0;
    }
    
    struct mach_header *mh = kernelcache;
    struct segment_command *sc = (kernelcache+sizeof(struct mach_header));
    
    for (int i = 0; i < mh->ncmds; i++) {
        
        if (!strcmp(sc->segname, "__PRELINK_TEXT")) {
            
            uint32_t ret = (sc->vmaddr - sc->fileoff);
            
            return ret;
        }
        
        uintptr_t next = (uintptr_t)sc->cmdsize+(void*)sc-kernelcache;
        
        if (next+(uintptr_t)kernelcache > mh->sizeofcmds+(uintptr_t)kernelcache) {
            break;
        }
        
        sc=kernelcache+next;
        
    }
    
    return 0;
}

/* Find the beginning of a kext's _TEXT section */
uint32_t find_kext_text_section(void *kernelcache, size_t size, const char *name) {
    
    if (!(*(uint32_t*)&kernelcache[0] == 0xFEEDFACE)) {
        printf("This doesn't look like a kernelcache\n");
        return 0;
    }
    
    struct mach_header *mh = kernelcache;
    
    struct segment_command *sc = (kernelcache+sizeof(struct mach_header));
    
    for (int i = 0; i < mh->ncmds; i++) {
        
        if (!strcmp(sc->segname, "__PRELINK_INFO")) {
            
            uint32_t fileOffToBegin = sc->fileoff;
            uint32_t fileSize = sc->filesize;
            
            if (fileSize > size || (fileSize+fileOffToBegin > size)) {
                printf("Bounds check error\n");
                return 0;
            }
            
            void *prelinkInfo = (void*)(kernelcache+fileOffToBegin);
            
            uint32_t requestedKextStart = 0;
            
            /* XML parsing for dummies. Don't do this, kids */
            for (int c=0; c < fileSize; c++) {
                if (!memcmp(prelinkInfo+c, name, strlen(name))) {
                    for (int d=c; d < fileSize; d++) {
                        if (!memcmp(prelinkInfo+d, "_PrelinkExecutableLoadAddr", strlen("_PrelinkExecutableLoadAddr"))) {
                            for (int e=d; e < (d+0x40); e++) {
                                if (*(uint16_t*)&prelinkInfo[e] == 0x7830) {
                                    char addr[0x10];
                                    bzero(&addr, 0x10);
                                    memcpy(&addr, prelinkInfo+e+2, 0x8);
                                    *(uint8_t*)&addr[0xB-2] = 0x0;
                                    
                                    uint32_t addre = (uint32_t)strtoul(addr, NULL, 16);
                                    
                                    if (!(addre < 0x80000000+fileOffToBegin && addre > 0x80000000)) {
                                        goto done;
                                    }
                                    
                                    requestedKextStart = addre;
                                    
                                    goto done;
                                }
                            }
                        }
                    }
                }
            }
            
        done:;
            
            if(!requestedKextStart) {
                printf("Failed to find beginning of requested kext __text section\n");
                return 0;
            }
            
            return requestedKextStart;
        }
        
        
    nextSC:;
        uintptr_t next = (uintptr_t)sc->cmdsize+(void*)sc-kernelcache;
        
        if (next+(uintptr_t)kernelcache > mh->sizeofcmds+(uintptr_t)kernelcache) {
            break;
        }
        
        sc=kernelcache+next;
        
    }
    
    return 0;
}
#define SHIT_OFFSET 0x56000

uint32_t find_mount_common10(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    float version_float = strtof(version, 0);
    for (uint32_t i = 0; i < ksize; i++) {
        if (version_float < (float)10.3) {
            if (*(uint64_t*)&kdata[i] == 0xf04fd1040f01f01b && *(uint32_t*)&kdata[i+8] == 0x9d080801) {
                printf("[*] found mount_common: 0x%x\n", i + 0x5);
                return i + 0x5;
            }
        }
        else {
            if (*(uint32_t*)&kdata[i] == 0x0f01f01a && *(uint16_t*)&kdata[i+4] == 0xd13b) {
                printf("[*] found mount_common: 0x%x\n", i + 0x5);
                
                return i + 0x5;
            }
        }
    }
    return 0xffffffff;
}

uint32_t find_mapForIO10(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    float version_float = strtof(version, 0);
    for (uint32_t i = 0; i < ksize; i++) {
        if (*(uint64_t*)&kdata[i] == 0xf010798044406da8 && *(uint16_t*)&kdata[i+0x8] == 0x0f01) {
            uint32_t mapForIO = i - 4;
            printf("[*] found mapForIO: 0x%08x\n", mapForIO);
            return mapForIO;
        }
    }
    return 0xffffffff;
}

uint32_t find_PE_i_can_has_debugger_offset10(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    int i = 0;
    
    i = (uint32_t)find_sym(kdata, "_PE_i_can_has_debugger")-(uint32_t)kdata;
    
    for (i=i; i < (i+0x100); i+=0x2) {
        if (*(uint16_t*)(kdata+i) == 0x4770) {
//            printf("Found BX LR at 0x%x\n", i);
            printf("[*] found PE_i_can_has_debugger_offset: 0x%08x\n", i - 0x4);
            return i - 0x4;
        }
    }
    return 0xffffffff;
}

uint32_t find_nosuid_enforcement10(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    float version_float = strtof(version, 0);
    for (uint32_t i = 0; i < ksize; i++) {
        if (*(uint64_t*)&kdata[i] == 0x0108f04043080102) {
            i += 0x4;
            printf("[*] found nosuid enforcement: 0x%08x\n", i + 0x2);
            return i + 0x2;
        }
    }
    return 0xffffffff;
}

uint32_t find_tfp10(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    float version_float = strtof(version, 0);
    for (uint32_t i = 0; i < ksize; i++) {
        if (*(uint64_t*)&kdata[i] == 0xd04d2e001101e9cd && *(uint32_t*)&kdata[i+0xC] == 0x28009002) {
            printf("[*] found task for pid: 0x%x\n", i + 0x6);
            return i + 0x6;
        }
    }
    return 0xffffffff;
}

uint32_t find_fuck(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    uint32_t OSMalloc_Tagfree10 = (uint32_t)find_sym(kdata, "_OSMalloc_Tagfree")-(int)kdata;
    uint32_t PE_i_can_has_kernel_configuration = (uint32_t)find_sym(kdata, "_PE_i_can_has_kernel_configuration")-(uint32_t)kdata;
    OSMalloc_Tagfree10 += 0x80001000 + 1;
    PE_i_can_has_kernel_configuration += 0x80001000 + 1;
    
    for (uint32_t i = 0; i < ksize; i++) {
        if (*(uint32_t*)&kdata[i] == OSMalloc_Tagfree10) {
            if (*(uint32_t*)&kdata[i+0x4] == PE_i_can_has_kernel_configuration) {
                printf("[*] found lwvm call thingy: 0x%x\n", i + 0x4);
                return i + 0x4 + SHIT_OFFSET;
            }
        }
    }
    
    return 0xffffffff;
}

uint32_t find_bxlr_gadget(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    uint32_t bxlr_gadget = 0;
    for (int i = 0; i < ksize; i++) {
        if (*(uint32_t*)&kdata[i] == 0x47702000) {
            return i + 0x1;
//            bxlr_gadget = i + 0x80001000 + 0x1;
//            return bxlr_gadget;
        }
    }
    return 0xffffffff;
}

uint32_t find_amfi_memcmp(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    uint32_t memcmp_addy = (uint32_t)find_sym(kdata, "_memcmp")-(uint32_t)kdata;
    memcmp_addy += 0x80001000 + 1;
    printf("[i] found memcmp @ 0x%x\n", memcmp_addy);
    uint32_t mach_msg_rpc_from_kernel_proper = (uint32_t)find_sym(kdata, "_mach_msg_rpc_from_kernel_proper")-(uint32_t)kdata+0x1;
    mach_msg_rpc_from_kernel_proper += 0x80001000;
    printf("[i] found mach_msg_rpc_from_kernel_proper @ 0x%x\n", mach_msg_rpc_from_kernel_proper);
    for (int i = 0; i < ksize; i++) {
        if (*(uint32_t*)&kdata[i] == (uint32_t)mach_msg_rpc_from_kernel_proper) {
            printf("[*] found mach_msg_whatever @ 0x%x\n", 0x80001000 + i);
            if (*(uint32_t*)&kdata[i + 4] == memcmp_addy) {
                printf("[*] found memcmp_addy @ 0x%x\n", 0x80001000 + i + 0x4);
                return i + 0x4 + SHIT_OFFSET;
            }
        }
    }
    return 0xffffffff;
}

uint32_t find_sbops10(uint32_t region, uint8_t* kdata, size_t ksize, char* version) {
    uint32_t seatbelt_sandbox_policy_ptr = (uint32_t)memmem(kdata, ksize, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy")) - (uint32_t)kdata;
    uint32_t kextbase = find_kextbase(kdata, ksize) - 0x80001000;
    uint32_t str_ref = seatbelt_sandbox_policy_ptr + 0x80001000 + kextbase;
    uint32_t str_xref = 0;
    for (int af = 0; af < ksize; af++) {
        if (*(uint32_t*)&kdata[af] == str_ref) {
            str_xref = af;
            break;
        }
    }
    uint32_t off = 0x0;
    for (uint32_t cur1=str_xref; cur1 < (str_xref + 0x10); cur1++) {
        if (*(uint32_t*)&kdata[cur1] == 0x1) {
            off = cur1 + 0x4;
            break;
        }
    }
    uint32_t sbops_offset = *(uint32_t*)&kdata[off] - 0x80001000;
    return sbops_offset;
}
