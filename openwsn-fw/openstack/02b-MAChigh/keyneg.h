/**
 * Author: Author: Pietro Tedeschi, Hamad Bin Khalifa University - email: ptedeschi at hbku.edu.qa, pietrotedeschi.me at gmail.com
\brief Header file for LiKe
*/

#ifndef __KEYNEG_H
#define __KEYNEG_H

#include "opendefs.h"
#include "scheduler.h"
#include "sixtop.h"
#include "pka.h"
#include "radio.h"
#include "topology.h"

//=========================== define ==========================================

#define CURVE_LEN 5 //6//8

#define A_PRIVKEYEXTENDLENGTH CURVE_LEN * 2 + 1 //17
#define ESSEINTLENGTH CURVE_LEN * 2             //16
#define ESSEEXTENDLENGTH CURVE_LEN * 2 + 1      //17
#define ESSEMODNLENGTH CURVE_LEN + 1            //9
#define HASHLENGTH CURVE_LEN                    //8
#define A_PRIVKEYINTLENGTH CURVE_LEN * 2        //16
#define ESSEMODLENGTH CURVE_LEN + 1             //9
#define AKEYPRIVATEMODLENGTH CURVE_LEN + 1      //9
#define HMAC_KEY "802.15.4e"
#define SHA1_SIZE 20

//=========================== typedef =======================================

static uint32_t nist_p_160_p[5] = {0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                                   0xffffffff};
static uint32_t nist_p_160_n[6] = {0xca752257, 0xf927aed3, 0x0001f4c8, 0x00000000,
                                   0x00000000, 0x00000001};
static uint32_t nist_p_160_a[5] = {0x7ffffffc, 0xffffffff, 0xffffffff, 0xffffffff,
                                   0xffffffff};
static uint32_t nist_p_160_b[5] = {0xc565fa45,0x81d4d4ad,0x65acf89f,0x54bd7a8b,
                                    0x1c97befc,};
static uint32_t nist_p_160_x[5] = {0x13cbfc82, 0x68c38bb9, 0x46646989, 0x8ef57328,
                                   0x4a96b568};
static uint32_t nist_p_160_y[5] = {0x7ac5fb32, 0x04235137, 0x59dcc912, 0x3168947d,
                                   0x23a62855};

typedef struct
{
   uint32_t Private[CURVE_LEN];
   tECPt *Public;
} ECCKey;

// #define STATE_TABLE_SIZE      10
// #define STATE_TABLE_OVERFLOW  25
#define TOPOLOGY_ROOT 0xad
#define TOPOLOGY_CHILD_1 0xba
#define PROTOCOL_ID 0xcc

typedef struct
{
   uint16_t periodMaintenance;
   uint16_t maintenanceTimerId;
   opentimers_id_t timerId;
   //uint8_t                    waitConstant; //used to adapt the wait time on a hop-by-hop basis

   //curve parameters
   tECCCurveInfo *curve_info;
   tECCCurveInfo nist_p_160_my;
   //CA parameters
   ECCKey keypair_CA; //public key of the CA
   tECPt pointCA;
   uint32_t pointCA_X[CURVE_LEN];
   uint32_t pointCA_Y[CURVE_LEN];

   //Device ID, Timestamp
   uint8_t id[2];  //Node's ID
   uint8_t ts[10]; //Node's timestamp (80 bit--10 byte)

   //PKA parameters
   ECCKey myFirstKey;
   //uint32_t        				my_PrivateKey[CURVE_LEN];
   tECPt my_FirstPublicKey;
   uint32_t my_FirstPublicKey_X[CURVE_LEN];
   uint32_t my_FirstPublicKey_Y[CURVE_LEN];

   ECCKey myr;
   //uint32_t        				my_PrivateKey[CURVE_LEN];
   tECPt my_SecondPublicKey;
   uint32_t my_SecondPublicKey_X[CURVE_LEN];
   uint32_t my_SecondPublicKey_Y[CURVE_LEN];

   // Hi
   uint32_t Hi[HASHLENGTH];
   uint32_t Hi_remote[HASHLENGTH];
   uint32_t hashKey[HASHLENGTH];
   uint32_t neighbor_Hi[HASHLENGTH];

   uint8_t sig[20];
   uint8_t sigRemote[20];
   uint8_t sigRemoteCheck[20];
   uint8_t neighbor_sig[20];
   uint32_t LinkKey[16];

   //PKA parameters of the neighbor
   ECCKey neighborFirstKey;
   tECPt neighbor_FirstPublicKey;
   uint32_t neighbor_FirstPublicKey_X[CURVE_LEN];
   uint32_t neighbor_FirstPublicKey_Y[CURVE_LEN];

   ECCKey neighborSecondKey;
   tECPt neighbor_SecondPublicKey;
   uint32_t neighbor_SecondPublicKey_X[CURVE_LEN];
   uint32_t neighbor_SecondPublicKey_Y[CURVE_LEN];

   //state of the key negotiation algorithm for this mote
   uint8_t m_kmpState;

   //random numbers
   uint16_t myRand;
   uint16_t remoteRand;
   uint8_t remoteID[2];  //id of the remote node
   uint8_t remotets[10]; //ts of the remote node
   //Authentication Hashes
   uint8_t myAuth[20];     //my authentication string
   uint8_t remoteAuth[20]; //remote authentication string
   open_addr_t last_Neighbor;
} negkey_vars_t;

//=========================== define ==========================================

enum Negkey_state__enums
{ //states for the kmp state machine
   READY = 2,
   SECOND_FRAG = 3,
   SEND_AUTH = 4,
   KMP_COMPLETED = 17,
};

typedef struct
{
   uint32_t Intermediate_Hash[SHA1_SIZE / 4]; /* Message Digest */
   uint32_t Length_Low;                       /* Message length in bits */
   uint32_t Length_High;                      /* Message length in bits */
   uint16_t Message_Block_Index;              /* Index into message block array   */
   uint8_t Message_Block[64];                 /* 512-bit message blocks */
} SHA1_CTX;

//=========================== variables =======================================

//=========================== prototypes ======================================

//void pkatest_init(void);
void negkey_receive(OpenQueueEntry_t *msg);

void hmac_sha1(const unsigned char *inText,
               uint8_t inTextLength,
               unsigned char *inKey,
               uint8_t inKeyLength,
               unsigned char *outDigest);

void SHA1Init(SHA1_CTX *);
void SHA1Update(SHA1_CTX *, const uint8_t *msg, int len);
void SHA1Final(uint8_t *digest, SHA1_CTX *);
static void SHA1PadMessage(SHA1_CTX *ctx);
static void SHA1ProcessMessageBlock(SHA1_CTX *ctx);

void keyneg_init(void);
bool negkey_isKMPFinished(void);

#endif
