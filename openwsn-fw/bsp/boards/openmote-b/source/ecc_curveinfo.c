/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Andreas Dröscher <contiki@anticat.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/**
 * \addtogroup c2538-ecc-curves
 * @{
 */

#include <ecc_curveinfo.h>

//[NIST P-256, X9.62 prime256v1]
uint32_t nist_p_256_p[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                             0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
uint32_t nist_p_256_n[8] = { 0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
                             0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF };
uint32_t nist_p_256_a[8] = { 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                             0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
uint32_t nist_p_256_b[8] = { 0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
                             0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8 };
uint32_t nist_p_256_x[8] = { 0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
                             0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2 };
uint32_t nist_p_256_y[8] = { 0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
                             0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2 };

tECCCurveInfo nist_p_256 = {
  .name       = "NIST P-256",
  .ui8Size    = 8,
  .pui32Prime = nist_p_256_p,
  .pui32N     = nist_p_256_n,
  .pui32A     = nist_p_256_a,
  .pui32B     = nist_p_256_b,
  .pui32Gx    = nist_p_256_x,
  .pui32Gy    = nist_p_256_y
};

//[NIST P-192, X9.62 prime192v1]
static uint32_t nist_p_192_p[6] = { 0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff,
                                    0xffffffff, 0xffffffff };
static uint32_t nist_p_192_a[6] = { 0xfffffffc, 0xffffffff, 0xfffffffe, 0xffffffff,
                                    0xffffffff, 0xffffffff };
static uint32_t nist_p_192_b[6] = { 0xc146b9b1, 0xfeb8deec, 0x72243049, 0x0fa7e9ab,
                                    0xe59c80e7, 0x64210519 };
static uint32_t nist_p_192_x[6] = { 0x82ff1012, 0xf4ff0afd, 0x43a18800, 0x7cbf20eb,
                                    0xb03090f6, 0x188da80e };
static uint32_t nist_p_192_y[6] = { 0x1e794811, 0x73f977a1, 0x6b24cdd5, 0x631011ed,
                                    0xffc8da78, 0x07192b95 };
static uint32_t nist_p_192_n[6] = { 0xb4d22831, 0x146bc9b1, 0x99def836, 0xffffffff,
                                    0xffffffff, 0xffffffff };

tECCCurveInfo nist_p_192 = {
  .name       = "NIST P-192",
  .ui8Size    = 6,
  .pui32Prime = nist_p_192_p,
  .pui32N     = nist_p_192_n,
  .pui32A     = nist_p_192_a,
  .pui32B     = nist_p_192_b,
  .pui32Gx    = nist_p_192_x,
  .pui32Gy    = nist_p_192_y
};


//[NIST P-160, X9.62 prime160v1]
static uint32_t nist_p_160_p[5] = { 0x7fffffff, 0xffffffff, 0xffffffff,  0xffffffff,
								    0xffffffff};
static uint32_t nist_p_160_n[6] = { 0xca752257, 0xf927aed3, 0x0001f4c8, 0x00000000,
		                            0x00000001};
static uint32_t nist_p_160_a[5] = { 0x7ffffffc, 0xffffffff, 0xffffffff, 0xffffffff,
									0xffffffff};
static uint32_t nist_p_160_b[5] = { 0xc565fa45, 0x81d4d4ad, 0x65acf89f, 0x54bd7a8b,
							        0x1c97befc,};
static uint32_t nist_p_160_x[5] = { 0x13cbfc82, 0x68c38bb9, 0x46646989, 0x8ef57328,
                                    0x4a96b568};
static uint32_t nist_p_160_y[5] = { 0x7ac5fb32, 0x04235137, 0x59dcc912, 0x3168947d,
                                     0x23a62855};

tECCCurveInfo nist_p_160 = {
  .name       = "NIST P-160",
  .ui8Size    = 5,
  .pui32Prime = nist_p_160_p,
  .pui32N     = nist_p_160_n,
  .pui32A     = nist_p_160_a,
  .pui32B     = nist_p_160_b,
  .pui32Gx    = nist_p_160_x,
  .pui32Gy    = nist_p_160_y
};

/**
 * @}
 * @}
 */
