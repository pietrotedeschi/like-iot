/**
    \brief Definition of the "soc" app. A CoAP resource which allows an application to GET/SET the state of
   sensors.
*/

#include "opendefs.h"
#include "soc.h"
#include "opencoap.h"
#include "packetfunctions.h"
#include "openqueue.h"
#include "idmanager.h"
#include "opensensors.h"
#include "sensors.h"
#include "scheduler.h"
#include "openserial.h"
#include "IEEE802154E.h"
#include "openrandom.h"

//=========================== defines =========================================

//=========================== variables =======================================

soc_vars_t               soc_vars;

//=========================== prototypes ======================================

void soc_init(void);

//SoC functions
void timer_soC_management_fired(void);
void soC_maintenance_timer_cb(opentimers_id_t id);
void send_SoC_info(void);

//=========================== public ==========================================

void soc_init(void){

	soc_vars.SoC_periodMaintenance = 5000;

//	soc_vars.SoC_GatheringTimerId = opentimers_create();
//	opentimers_scheduleIn(
//			soc_vars.SoC_GatheringTimerId,
//			openrandom_get16b()%soc_vars.SoC_periodMaintenance,
//			TIME_MS,
//			TIMER_PERIODIC,
//			soC_maintenance_timer_cb
//		);

	soc_vars.SoC_stop = 0;

	uint8_t i;
	for (i=0; i<NUM_SOC_NEIGHBORS; i++){
		soc_vars.soc_table[i].id = 0;
		soc_vars.soc_table[i].recv = 0;
	}

//	openserial_printInfo(COMPONENT_SoC,ERR_OK,
//						(errorparameter_t)0,
//						(errorparameter_t)200);

}

void soC_maintenance_timer_cb(opentimers_id_t id){
	scheduler_push_task(timer_soC_management_fired,TASKPRIO_SIXTOP);
}

void timer_soC_management_fired(void) {

	send_SoC_info();
}

void send_SoC_info(void){

	OpenQueueEntry_t* pkt;
	open_addr_t * p;

	// if SoC is not finished, abort
	if (!ieee154e_getSoCstatus()) return;

	// don't run if not synch
	if (ieee154e_isSynch() == FALSE) return;

	//do not run on the DAG root
	if (idmanager_getIsDAGroot()) return;

	if (soc_vars.SoC_stop == 1) return;

//	openserial_printInfo(COMPONENT_SoC,ERR_OK,
//						(errorparameter_t)0,
//						(errorparameter_t)201);

	//otherwise create an app-layer packet embedding info
	pkt = openqueue_getFreePacketBuffer(COMPONENT_SoC);
    if (pkt==NULL) {
	  openserial_printError(COMPONENT_SIXTOP,ERR_NO_FREE_PACKET_BUFFER,
							(errorparameter_t)0,
							(errorparameter_t)0);
	  return;
    }


    //add ASN
    packetfunctions_reserveHeaderSize(pkt,2);
    uint16_t value;
    value = SoC_getASN();
    // add value
    pkt->payload[0]                  = (value>>8) & 0x00ff;
    pkt->payload[1]                  = value & 0x00ff;

    //add slotOffset
    packetfunctions_reserveHeaderSize(pkt,1);
    uint8_t value_n;
    value_n = SoC_getSlotOffset();
	// add value
	pkt->payload[0]                  = value_n;

	//add sender ID
	packetfunctions_reserveHeaderSize(pkt,2);
    p=idmanager_getMyID(ADDR_64B);
    pkt->payload[0]    = p->addr_64b[6];
    pkt->payload[1]    = p->addr_64b[7];

    // metadata
    pkt->l4_protocol                 = IANA_UDP;
    pkt->l4_sourcePortORicmpv6Type   = WKP_UDP_LATENCY;
    pkt->l4_destination_port         = WKP_UDP_LATENCY;
    pkt->l3_destinationAdd.type      = ADDR_128B;
    memcpy(&pkt->l3_destinationAdd.addr_128b[0],&ipAddr_ringmaster,16);

//    coap_option_iht*        options;
//	options = NULL;

    // send
//    outcome = opencoap_send(
//	  pkt,
//	  COAP_TYPE_NON,
//	  COAP_CODE_REQ_PUT,
//	  2, // token len
//	  options,
//	  3, // options len
//	  &soc_vars.csensors_resource[id].desc
//    );

    // send packet
       if ((openudp_send(pkt)) == E_FAIL) {
          openqueue_freePacketBuffer(pkt);
          openserial_printInfo(COMPONENT_SoC,ERR_OK,
          						(errorparameter_t)0,
          						(errorparameter_t)202);

       } else {
    	   //soc_vars.SoC_stop = 1;
       }

    // avoid overflowing the queue if fails
//    if (outcome==E_FAIL) {
//	  openqueue_freePacketBuffer(pkt);
//    }

    return;

}

void SoC_receive(OpenQueueEntry_t* msg){

	//open_addr_t p;
	uint8_t byte0, byte1, sender_addr_0, sender_addr_1;
	uint16_t rec_ASN;
	uint8_t  rec_slotOffset;

//	openserial_printInfo(COMPONENT_SoC,ERR_OK,
//						(errorparameter_t)0,
//						(errorparameter_t)2021);

	//read sender Address
	sender_addr_0 = msg->payload[msg->length-5];
	sender_addr_1 = msg->payload[msg->length-4];
    //packetfunctions_tossHeader(msg, 2);

	// read ASN
	byte0 = msg->payload[msg->length-1];
    byte1 = msg->payload[msg->length-2];
    rec_ASN    = (uint16_t)byte1<<8 | (uint16_t)byte0;

    //packetfunctions_tossHeader(msg, 2);

    //read SlotOffset
    rec_slotOffset = msg->payload[msg->length-3];

    //verify if the sender is already in slot table. Otherwise, print values
    uint8_t i;
    uint8_t soc_table_stop;
    uint8_t do_print;
    do_print = 1;
    soc_table_stop = 0;
    for (i=0; i<NUM_SOC_NEIGHBORS; i++){
		if (soc_table_stop == 0){
			if (soc_vars.soc_table[i].id == sender_addr_1){
				do_print = 0;
				soc_table_stop = 1;
			}
		}
	}

    //store the sender in the table
    soc_table_stop = 0;
    for (i=0; i<NUM_SOC_NEIGHBORS; i++){
    	if (soc_table_stop == 0){
    		if (soc_vars.soc_table[i].recv == 0){
    			soc_vars.soc_table[i].id = sender_addr_1;
    			soc_vars.soc_table[i].recv = 1;
    			soc_table_stop = 1;
    		}
    	}
    }

    //display values
    if (do_print == 1){
		openserial_printInfo(COMPONENT_SoC,ERR_OK,
										(errorparameter_t)sender_addr_1,
										(errorparameter_t)202);
		openserial_printInfo(COMPONENT_SoC,ERR_OK,
										(errorparameter_t)rec_ASN,
										(errorparameter_t)203);
		openserial_printInfo(COMPONENT_SoC,ERR_OK,
										(errorparameter_t)rec_slotOffset,
										(errorparameter_t)204);
    }

    //free buffer
    openqueue_freePacketBuffer(msg);

    return;
}
