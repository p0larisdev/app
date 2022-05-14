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
        PatchLog("This doesn't look like a kernelcache\n");
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
        PatchLog("This doesn't look like a kernelcache\n");
        return 0;
    }
    
    struct mach_header *mh = kernelcache;
    
    struct segment_command *sc = (kernelcache+sizeof(struct mach_header));
    
    for (int i = 0; i < mh->ncmds; i++) {
        
        if (!strcmp(sc->segname, "__PRELINK_INFO")) {
            
            uint32_t fileOffToBegin = sc->fileoff;
            uint32_t fileSize = sc->filesize;
            
            if (fileSize > size || (fileSize+fileOffToBegin > size)) {
                PatchLog("Bounds check error\n");
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
                PatchLog("Failed to find beginning of requested kext __text section\n");
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
