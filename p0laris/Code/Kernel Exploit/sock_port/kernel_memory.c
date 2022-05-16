//
//  kernel_memory.c
//  sock_port
//
//  Created by Jake James on 7/18/19.
//  Copyright © 2019 Jake James. All rights reserved.
//

#include "kernel_memory.h"

static mach_port_t tfpzero;

void init_kernel_memory(mach_port_t tfp0) {
    tfpzero = tfp0;
}

uint32_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

void kfree(mach_vm_address_t address, vm_size_t size) {
    mach_vm_deallocate(tfpzero, address, size);
}

size_t kread(uint32_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfpzero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            printf("[-] error on kread(0x%018lx)\n", where);
            break;
        }
        offset += sz;
    }
    return offset;
}

uint32_t rk32(uint32_t where) {
    uint32_t out;
    kread(where, &out, sizeof(uint32_t));
    return out;
}

//uint64_t rk64(uint64_t where) {
//    uint64_t out;
//    kread(where, &out, sizeof(uint64_t));
//    return out;
//}

size_t kwrite(uint32_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, (int)chunk);
        if (rv) {
            printf("[-] error on kwrite(0x%016llx)\n", where);
            break;
        }
        offset += chunk;
    }
    return offset;
}

void wk8(uint32_t where, uint8_t what) {
    uint32_t _what = what;
    kwrite(where, &_what, sizeof(uint8_t));
}

void wk16(uint32_t where, uint16_t what) {
    uint32_t _what = what;
    kwrite(where, &_what, sizeof(uint16_t));
}

void wk32(uint32_t where, uint32_t what) {
    uint32_t _what = what;
    kwrite(where, &_what, sizeof(uint32_t));
}


//void wk64(uint64_t where, uint64_t what) {
//    uint64_t _what = what;
//    kwrite(where, &_what, sizeof(uint64_t));
//}

uint32_t find_port(mach_port_name_t port, uint32_t task_self) {
    uint32_t task_addr = rk32(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint32_t itk_space = rk32(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint32_t is_table = rk32(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = koffset(KSTRUCT_SIZE_IPC_ENTRY);//0x18;
    
    uint32_t port_addr = rk32(is_table + (port_index * sizeof_ipc_entry_t));
    
    return port_addr;
}

#include <mach-o/loader.h>
#define IMAGE_OFFSET 0x1000
#define MACHO_HEADER_MAGIC MH_MAGIC
#define KERNEL_SEARCH_ADDRESS 0x81200000

vm_address_t get_kernel_base(task_t kernel_task) {
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000; /* arm64: addr = 0xffffff8000000000 */

    while (1) {
        if (KERN_SUCCESS != vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t) & info, &info_count))
            break;
        if (size > 1024 * 1024 * 1024) {
            /*
             * https://code.google.com/p/iphone-dataprotection/
             * hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
             */
            pointer_t buf;
            mach_msg_type_number_t sz = 0;
            addr += 0x200000;
            vm_read(kernel_task, addr + 0x1000, 512, &buf, &sz);
            if (*((uint32_t *)buf) != MH_MAGIC) {
                addr -= 0x200000;
                vm_read(kernel_task, addr + 0x1000, 512, &buf, &sz);
                if (*((uint32_t*)buf) != MH_MAGIC) {
                    break;
                }
            }
            addr += 0x1000;
            printf("kernel_base: 0x%08x\n", addr);
            return addr;
        }
        addr += size;
    }

    printf("ERROR: Failed to find kernel base.\n");
    return -1;
}
