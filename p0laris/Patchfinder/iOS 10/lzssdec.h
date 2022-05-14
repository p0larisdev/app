//
//  lzssdec.h
//  p0laris
//
//  Created by spv on 5/14/22.
//

#ifndef lzssdec_h
#define lzssdec_h

#ifdef __cplusplus
extern "C" {
#endif
void lzss_me_harder(uint8_t *dst, uint32_t dstlen, uint32_t *pdstused, uint8_t *src, uint32_t srclen, uint32_t *psrcused);
#ifdef __cplusplus
};
#endif

#endif /* lzssdec_h */
