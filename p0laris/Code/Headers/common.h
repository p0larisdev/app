/*
 *  common.h
 *  p0laris
 *
 *  created on 11/20/21
 */

#ifndef common_h
#define common_h

#include <UIKit/UIDevice.h>
#include <stdbool.h>

extern bool global_untethered;

/*
 *  v0rtex
 */
#include <stdint.h>             // uint*_t
#include <Foundation/Foundation.h>

#define LOG(str, args...) do { NSLog(@str "\n", ##args); } while(0)
#ifdef __LP64__
#   define ADDR                 "0x%016llx"
#   define MACH_HEADER_MAGIC    MH_MAGIC_64
#   define MACH_LC_SEGMENT      LC_SEGMENT_64
	typedef struct mach_header_64 mach_hdr_t;
	typedef struct segment_command_64 mach_seg_t;
	typedef uint64_t kptr_t;
#else
#   define ADDR                 "0x%08x"
#   define MACH_HEADER_MAGIC    MH_MAGIC
#   define MACH_LC_SEGMENT      LC_SEGMENT
	typedef struct mach_header mach_hdr_t;
	typedef struct segment_command mach_seg_t;
	typedef uint32_t kptr_t;
#endif
typedef struct load_command mach_lc_t;

#ifndef func_i_system_version_field
#define func_i_system_version_field

inline static int i_system_version_field(unsigned int fieldIndex) {
  NSString* const versionString = UIDevice.currentDevice.systemVersion;
  NSArray<NSString*>* const versionFields = [versionString componentsSeparatedByString:@"."];
  if (fieldIndex < versionFields.count) {
	NSString* const field = versionFields[fieldIndex];
	return field.intValue;
  }
  NSLog(@"[WARNING] i_system_version(%iu): field index not present in version string '%@'.", fieldIndex, versionString);
  return -1; // error indicator
}

#endif

#endif /* common_h */
