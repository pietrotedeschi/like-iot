/**
    \brief Declaration of the "soc" app.
  
*/

#ifndef __SOC_H
#define __SOC_H

/**
\addtogroup AppCoAP
\{
\addtogroup csoc
\{
*/

#include "opencoap.h"
#include "sensors.h"
#include "opentimers.h"

//=========================== define ==========================================

#define NUM_SOC_NEIGHBORS 10
//=========================== typedef =========================================

//=========================== module variables ================================

typedef struct {
	uint8_t id;
	bool    recv;
} soc_table_t;

typedef struct {
   uint16_t             SoC_periodMaintenance;
   opentimers_id_t      SoC_GatheringTimerId;    //timer for SoC gathering protocol
   bool                 SoC_stop;
   soc_table_t         soc_table[NUM_SOC_NEIGHBORS];
} soc_vars_t;

//=========================== variables =======================================

//=========================== prototypes ======================================

void soc_app_init(void);
void SoC_receive(OpenQueueEntry_t* msg);

/**
\}
\}
*/

#endif
