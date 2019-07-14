/*
 * Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author: Andreas Dröscher <contiki@anticat.ch>
 * Modified by: Pietro Tedeschi <ptedeschi@mail.hbku.edu.qa>, June 2019
 * Modified by: Savio Sciancalepore <savio.sciancalepore@poliba.it>, June 2015
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
 * \addtogroup c2538-ecc-algo
 * @{
 *
 * \file
 * Implementation of the cc2538 ECC Algorithms
 */


#include <headers/hw_ints.h>
#include <headers/hw_memmap.h>
#include <headers/hw_pka.h>
#include <headers/hw_types.h>
#include "interrupt.h"
#include "ecc-algorithms.h"
#include "ecc_curveinfo.h"
#include "pka.h"
#include "opendefs.h"

uint8_t ecc_compare(uint32_t a[12],            //Left Number
                    uint32_t b[12],            //Right Number
                    uint8_t  size){         //Length of a and b)

    uint8_t finalValue;
    finalValue = PKABigNumCmpStart(a,
			                       b,
			                       size);

   //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);

   finalValue = PKABigNumCmpGetResult();

  return finalValue;
}

uint8_t ecc_multiply(ecc_multiply_state_t *state) {

   state->result = PKAECCMultiplyStart(state->secret,
		                               &state->point_in,
		                               state->curve_info,
		                               &state->rv);

   //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);


   state->result = PKAECCMultiplyGetResult(&state->point_out,
		                                   state->rv);

   return state->result;
}

uint8_t ecc_dsa_verify(ecc_dsa_verify_state_t *state) {

  //Executed Every Time
  uint8_t   size = state->curve_info->ui8Size;
  uint32_t *ord  = state->curve_info->pui32N;

  tECPt point;
  memcpy(point.pui32X, state->curve_info->pui32Gx, sizeof(point.pui32X));
  memcpy(point.pui32Y, state->curve_info->pui32Gy, sizeof(point.pui32Y));

  //Invert s mod n
  state->result = PKABigNumInvModStart(state->signature_s,
		                               size,
		                               ord,
		                               size,
		                               &state->rv);
   //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);

   state->result = PKABigNumInvModGetResult(state->s_inv,
		                                    size,
		                                    state->rv);

  //Calculate u1 = s_inv * hash
  state->result = PKABigNumMultiplyStart(state->s_inv,
		                                 size,
		                                 state->hash,
		                                 size,
		                                 &state->rv);
   //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);

   state->len  = 24;
   state->result = PKABigNumMultGetResult(state->u1,
		                                  &state->len,
		                                  state->rv);

  //Calculate u1 = s_inv * hash mod n
  state->result = PKABigNumModStart(state->u1,
		                            state->len,
		                            ord,
		                            size,
		                            &state->rv);
     //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);
  state->result = PKABigNumModGetResult(state->u1,
		                                size,
		                                state->rv);

  //Calculate u2 = s_inv * r
  state->result = PKABigNumMultiplyStart(state->s_inv,
		                                 size,
		                                 state->signature_r,
		                                 size,
		                                 &state->rv);
   //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);

   state->len = 24;
   state->result = PKABigNumMultGetResult(state->u2,
		                                  &state->len,
		                                  state->rv);

  //Calculate u2 = s_inv * r mod n
  state->result = PKABigNumModStart(state->u2,
		                            state->len,
		                            ord,
		                            size,
		                            &state->rv);
   //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);

   state->result = PKABigNumModGetResult(state->u2,
		                                 size,
		                                 state->rv);

  //Calculate p1 = u1 * A
   state->result = PKAECCMultiplyStart(state->u1,
		                               &point,
		                               state->curve_info,
		                               &state->rv);
   //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);

   state->result = PKAECCMultiplyGetResult(&state->p1,
		                                   state->rv);

  //Calculate p2 = u1 * B
  state->result = PKAECCMultiplyStart(state->u2,
		                              &state->public,
		                              state->curve_info,
		                              &state->rv);
   //wait for the completion of operation
   do{
		ASM_NOP;
   }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);

   state->result = PKAECCMultiplyGetResult(&state->p2,
		                                   state->rv);

  //Calculate P = p1 + p2
  state->result = PKAECCAddStart(&state->p1,
		                         &state->p2,
		                         state->curve_info,
		                         &state->rv);
  //wait for the completion of operation
  do{
	ASM_NOP;
  }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);
  state->result = PKAECCAddGetResult(&state->p1, state->rv);

  //Verify Result
  state->result = PKABigNumCmpStart(state->signature_r,
		                            state->p1.pui32X,
		                            size);

  //wait for the completion of operation
  do{
	ASM_NOP;
  }while((HWREG(PKA_FUNCTION) & PKA_FUNCTION_RUN)!= 0);

  state->result = PKABigNumCmpGetResult();

  if((state->result == PKA_STATUS_A_GR_B) || (state->result == PKA_STATUS_A_LT_B)) {
    state->result = PKA_STATUS_SIGNATURE_INVALID;
  }

  return state->result;
}
