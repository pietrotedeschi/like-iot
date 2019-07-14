#ifndef __TOPOLOGY_H
#define __TOPOLOGY_H

/**
\addtogroup MAClow
\{
\addtogroup topology
\{
*/

#include "opendefs.h"
#include "IEEE802154.h"

#define COORDINATOR 0xcd
#define NODE_1 0x4b
#define NODE_2 0x87

//=========================== define ==========================================

//=========================== typedef =========================================

//=========================== variables =======================================

//=========================== prototypes ======================================

//=========================== prototypes ======================================

bool topology_isAcceptablePacket(ieee802154_header_iht* ieee802514_header);

/**
\}
\}
*/

#endif
