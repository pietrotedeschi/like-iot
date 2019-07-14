/**
 * Author: Pietro Tedeschi, Hamad Bin Khalifa University - email: ptedeschi at hbku.edu.qa, pietrotedeschi.me at gmail.com
\brief Key Negotiation Protocol based on Certificateless Cryptography (LiKe protocol)
*/

#include "sixtop.h"
#include "keyneg.h"
#include "sys_ctrl.h"
#include "openqueue.h"
#include "packetfunctions.h"
#include "openserial.h"
#include "openrandom.h"
#include "board.h"
#include "idmanager.h"
#include "ecc-algorithms.h"
#include "scheduler.h"
#include "opentimers.h"
#include "neighbors.h"

//=========================== macros ==========================================

//#define SizeInByte 32
#define SizeInByte CURVE_LEN * 4
//#define SizeInWords 8
#define SHA1CircularShift(bits, word) \
	(((word) << (bits)) | ((word) >> (32 - (bits))))

//=========================== variables =======================================

negkey_vars_t negkey_vars = {};
uint16_t Status = 0;
uint8_t nsize = 0;
uint32_t pi[ESSEMODLENGTH] = {0};
uint8_t wi_len = 2 + 10 + 2 * (CURVE_LEN * 4 * 2);
unsigned char wi[2 + 10 + 2 * (CURVE_LEN * 4 * 2)] = {0};
unsigned char wi_remote[2 + 10 + 2 * (CURVE_LEN * 4 * 2)] = {0};
unsigned char _Key[] = HMAC_KEY;
unsigned char _hi_remote[64] = {0};

//=========================== prototypes ======================================

void negkey_timer_cb(void);
void timers_negkey_fired(void);
void send_Data(void);
void negkey_computeDHKey(void);
void negkey_sendAuthentication(void);
owerror_t negkey_checkAuth(void);
void negkey_computeLinkKey(void);

//=========================== admin ===========================================

void keyneg_init(void)
{
	unsigned char _hi[64] = {0};
	uint32_t hic[ESSEINTLENGTH] = {0};
	uint32_t hicLength = ESSEINTLENGTH;
	uint32_t rihic[ESSEEXTENDLENGTH] = {0};
	uint32_t rihicLength = ESSEEXTENDLENGTH;
	uint32_t piLength = ESSEMODLENGTH;

	//initialize pka module
	//Set the clocking to run directly from the external crystal/oscillator.
	SysCtrlClockSet(false, false, SYS_CTRL_SYSDIV_32MHZ);

	// Enable PKA peripheral
	SysCtrlPeripheralReset(SYS_CTRL_PERIPH_PKA);
	SysCtrlPeripheralEnable(SYS_CTRL_PERIPH_PKA);

	// Register PKA interrupt
	IntRegister(INT_PKA, PKAIntHandler);

	// Enable global interrupts
	IntAltMapEnable();
	IntMasterEnable();

	//Initialize PKA module
	pka_init();

	//Elliptic curve initialization
	negkey_vars.nist_p_160_my.pui32A = &nist_p_160_a;	 // a coefficient on the curve
	negkey_vars.nist_p_160_my.pui32B = &nist_p_160_b;	 // b coefficient on the curve
	negkey_vars.nist_p_160_my.pui32Gx = &nist_p_160_x;	// x coefficient on the generator point G for the curve
	negkey_vars.nist_p_160_my.pui32Gy = &nist_p_160_y;	// y coefficient on the generator point G for the curve
	negkey_vars.nist_p_160_my.pui32N = &nist_p_160_n;	 // order of the cyclic group #E(Zp)
	negkey_vars.nist_p_160_my.pui32Prime = &nist_p_160_p; // prime number p of the curve
	negkey_vars.nist_p_160_my.ui8Size = 5;				  // size of the words for secp160r1

	negkey_vars.curve_info = &negkey_vars.nist_p_160_my;

	// Domain Authority private key (c)
	memset(negkey_vars.keypair_CA.Private, 0, 4 * CURVE_LEN);
	negkey_vars.keypair_CA.Private[0] = 0x11111111;
	negkey_vars.keypair_CA.Private[1] = 0x11111111;
	negkey_vars.keypair_CA.Private[2] = 0x11111111;
	negkey_vars.keypair_CA.Private[3] = 0x11111111;
	negkey_vars.keypair_CA.Private[4] = 0x22222222;

	// Domain Authority Public Key (C = c*G)
	negkey_vars.keypair_CA.Public = &negkey_vars.pointCA;
	negkey_vars.keypair_CA.Public->pui32X = negkey_vars.pointCA_X;
	negkey_vars.keypair_CA.Public->pui32Y = negkey_vars.pointCA_Y;

	negkey_vars.pointCA_X[0] = 0xe2841a88;
	negkey_vars.pointCA_X[1] = 0x67516836;
	negkey_vars.pointCA_X[2] = 0xa2c6bf98;
	negkey_vars.pointCA_X[3] = 0xfb2bc2b9;
	negkey_vars.pointCA_X[4] = 0x506830b0;

	negkey_vars.pointCA_Y[0] = 0x2942af83;
	negkey_vars.pointCA_Y[1] = 0x3c6fd2c6;
	negkey_vars.pointCA_Y[2] = 0x5a3bdd6c;
	negkey_vars.pointCA_Y[3] = 0xa5f4eb89;
	negkey_vars.pointCA_Y[4] = 0x91eb15ae;

	// Check the ID and execute the Setup Phase
	switch (idmanager_getMyID(ADDR_64B)->addr_64b[7])
	{
	case TOPOLOGY_ROOT: // 0xad
		//Device ID A

		//This node is the ROOT
		negkey_vars.id[0] = 0xca;
		negkey_vars.id[1] = 0xfe;

		//Device Timestamp
		negkey_vars.ts[0] = 0x00;
		negkey_vars.ts[1] = 0x00;
		negkey_vars.ts[2] = 0x00;
		negkey_vars.ts[3] = 0x00;
		negkey_vars.ts[4] = 0x00;
		negkey_vars.ts[5] = 0x00;
		negkey_vars.ts[6] = 0x00;
		negkey_vars.ts[7] = 0x00;
		negkey_vars.ts[8] = 0x00;
		negkey_vars.ts[9] = 0x00;

		// First Partial Private Key xA
		memset(negkey_vars.myFirstKey.Private, 0, 4 * CURVE_LEN);
		negkey_vars.myFirstKey.Private[0] = 0x11111111;
		negkey_vars.myFirstKey.Private[1] = 0x11111111;
		negkey_vars.myFirstKey.Private[2] = 0x11111111;
		negkey_vars.myFirstKey.Private[3] = 0x11111111;
		negkey_vars.myFirstKey.Private[4] = 0x33333333;

		negkey_vars.myFirstKey.Public = &negkey_vars.my_FirstPublicKey;
		negkey_vars.myFirstKey.Public->pui32X = negkey_vars.my_FirstPublicKey_X;
		negkey_vars.myFirstKey.Public->pui32Y = negkey_vars.my_FirstPublicKey_Y;

		// First Partial Public Key (XA.x)
		negkey_vars.my_FirstPublicKey_X[0] = 0x9a201026;
		negkey_vars.my_FirstPublicKey_X[1] = 0xc777b031;
		negkey_vars.my_FirstPublicKey_X[2] = 0x1d28b2ad;
		negkey_vars.my_FirstPublicKey_X[3] = 0x63a60322;
		negkey_vars.my_FirstPublicKey_X[4] = 0x7db98969;

		// First Partial Public Key (XA.y)
		negkey_vars.my_FirstPublicKey_Y[0] = 0x1946898c;
		negkey_vars.my_FirstPublicKey_Y[1] = 0xd335c591;
		negkey_vars.my_FirstPublicKey_Y[2] = 0x03568c47;
		negkey_vars.my_FirstPublicKey_Y[3] = 0x20786a1f;
		negkey_vars.my_FirstPublicKey_Y[4] = 0xb9482924;

		// Status = PKA_ECCMultGenPt(negkey_vars.myFirstKey.Private,
		// 	                  		negkey_vars.myFirstKey.Public,
		// 					  		negkey_vars.curve_info);

		// Algorithm for the second partial private key (pi = ri + hic mod n)

		// Random value ri chosen by the Domain Authority
		memset(negkey_vars.myr.Private, 0, 4 * CURVE_LEN);
		negkey_vars.myr.Private[0] = 0x11111111;
		negkey_vars.myr.Private[1] = 0x11111111;
		negkey_vars.myr.Private[2] = 0x11111111;
		negkey_vars.myr.Private[3] = 0x11111111;
		negkey_vars.myr.Private[4] = 0x44444444;

		// Pi = ri*G
		negkey_vars.myr.Public = &negkey_vars.my_SecondPublicKey;
		negkey_vars.myr.Public->pui32X = negkey_vars.my_SecondPublicKey_X;
		negkey_vars.myr.Public->pui32Y = negkey_vars.my_SecondPublicKey_Y;

		// Second Partial Public Key (PA.x)
		negkey_vars.my_SecondPublicKey_X[0] = 0x6967ac88;
		negkey_vars.my_SecondPublicKey_X[1] = 0x00b905dd;
		negkey_vars.my_SecondPublicKey_X[2] = 0x02fd4917;
		negkey_vars.my_SecondPublicKey_X[3] = 0xb6fc8a9d;
		negkey_vars.my_SecondPublicKey_X[4] = 0x7fae383b;

		// Second Partial Public Key (PA.y)
		negkey_vars.my_SecondPublicKey_Y[0] = 0xbbc17628;
		negkey_vars.my_SecondPublicKey_Y[1] = 0xfcbd6ed1;
		negkey_vars.my_SecondPublicKey_Y[2] = 0x536ae535;
		negkey_vars.my_SecondPublicKey_Y[3] = 0xfaf61917;
		negkey_vars.my_SecondPublicKey_Y[4] = 0x2e008074;

		// Status = PKA_ECCMultGenPt(negkey_vars.myr.Private,
		// 	                  negkey_vars.myr.Public,
		// 					  negkey_vars.curve_info);

		// wi = [ID || ts || Xi.x || Xi.y || Pi.x || Pi.y]
		memcpy(wi, negkey_vars.id, 2);
		memcpy(wi + 2, negkey_vars.ts, 10);
		memcpy(wi + 2 + 10, negkey_vars.my_FirstPublicKey_X, sizeof(negkey_vars.my_FirstPublicKey_X));
		memcpy(wi + 2 + 10 + sizeof(negkey_vars.my_FirstPublicKey_X), negkey_vars.my_FirstPublicKey_Y, sizeof(negkey_vars.my_FirstPublicKey_Y));
		memcpy(wi + 2 + 10 + sizeof(negkey_vars.my_FirstPublicKey_X) + sizeof(negkey_vars.my_FirstPublicKey_Y), negkey_vars.my_SecondPublicKey_X, sizeof(negkey_vars.my_SecondPublicKey_X));
		memcpy(wi + 2 + 10 + sizeof(negkey_vars.my_FirstPublicKey_X) + sizeof(negkey_vars.my_FirstPublicKey_Y) + sizeof(negkey_vars.my_SecondPublicKey_X), negkey_vars.my_SecondPublicKey_Y, sizeof(negkey_vars.my_SecondPublicKey_Y));

		// Computing hi
		hmac_sha1(wi,
				  wi_len,
				  _Key, strlen(_Key),
				  _hi);

		memcpy(negkey_vars.Hi, _hi, 4 * HASHLENGTH);

		// Computing pi
		if (CURVE_LEN == 5)
		{
			nsize = CURVE_LEN + 1;
		}
		else
		{
			nsize = CURVE_LEN;
		}

		// hi*c 'stored' in hic
		Status = PKA_BigNumMultiply(negkey_vars.Hi,
									(uint8_t)CURVE_LEN,
									negkey_vars.keypair_CA.Private,
									(uint8_t)CURVE_LEN,
									hic,
									&hicLength);

		// ri + hi*c 'stored' in rihic
		Status = PKA_BigNumAdd(hic,
							   (uint8_t)hicLength,
							   negkey_vars.myr.Private,
							   (uint8_t)CURVE_LEN,
							   rihic,
							   &rihicLength);

		// pi = ri + hi*c mod n 'stored' in pi (Second Partial Private Key)
		Status = PKA_BigNumMod(rihic,
							   (uint8_t)rihicLength,
							   negkey_vars.curve_info->pui32N, //nist_p_256_2.pui32N,//nist_p_160_2.pui32N,//
							   (uint8_t)nsize,				   //CURVE_LEN+1,
							   pi,
							   (uint8_t)piLength);

		//negkey_vars.waitConstant = 2;
		break;
	case TOPOLOGY_CHILD_1: //0xba
						   //Device ID B
		negkey_vars.id[0] = 0xba;
		negkey_vars.id[1] = 0xbe;

		//Device Timestamp
		negkey_vars.ts[0] = 0x00;
		negkey_vars.ts[1] = 0x00;
		negkey_vars.ts[2] = 0x00;
		negkey_vars.ts[3] = 0x00;
		negkey_vars.ts[4] = 0x00;
		negkey_vars.ts[5] = 0x00;
		negkey_vars.ts[6] = 0x00;
		negkey_vars.ts[7] = 0x00;
		negkey_vars.ts[8] = 0x00;
		negkey_vars.ts[9] = 0x11;

		// First Partial Private Key xB
		memset(negkey_vars.myFirstKey.Private, 0, 4 * CURVE_LEN);
		negkey_vars.myFirstKey.Private[0] = 0x11111111;
		negkey_vars.myFirstKey.Private[1] = 0x11111111;
		negkey_vars.myFirstKey.Private[2] = 0x11111111;
		negkey_vars.myFirstKey.Private[3] = 0x11111111;
		negkey_vars.myFirstKey.Private[4] = 0x55555555;

		// First Partial Public Key (XB = xB*G)
		negkey_vars.myFirstKey.Public = &negkey_vars.my_FirstPublicKey;
		negkey_vars.myFirstKey.Public->pui32X = negkey_vars.my_FirstPublicKey_X;
		negkey_vars.myFirstKey.Public->pui32Y = negkey_vars.my_FirstPublicKey_Y;

		negkey_vars.my_FirstPublicKey_X[0] = 0x33bcfe9c;
		negkey_vars.my_FirstPublicKey_X[1] = 0x05cd715b;
		negkey_vars.my_FirstPublicKey_X[2] = 0xe789c96d;
		negkey_vars.my_FirstPublicKey_X[3] = 0x3b6db3dd;
		negkey_vars.my_FirstPublicKey_X[4] = 0xf9287308;

		negkey_vars.my_FirstPublicKey_Y[0] = 0x51eadecb;
		negkey_vars.my_FirstPublicKey_Y[1] = 0x7e3a1d49;
		negkey_vars.my_FirstPublicKey_Y[2] = 0x5f217fb8;
		negkey_vars.my_FirstPublicKey_Y[3] = 0x01c60d97;
		negkey_vars.my_FirstPublicKey_Y[4] = 0x563a3cf7;

		// Status = PKA_ECCMultGenPt(negkey_vars.myFirstKey.Private,
		// 	                  		negkey_vars.myFirstKey.Public,
		// 					  		negkey_vars.curve_info);

		// Algorithm for the second partial private key (pi = ri + hic mod n)

		// random value ri chosen by the Domain Authority
		memset(negkey_vars.myr.Private, 0, 4 * CURVE_LEN);
		negkey_vars.myr.Private[0] = 0x11111111;
		negkey_vars.myr.Private[1] = 0x11111111;
		negkey_vars.myr.Private[2] = 0x11111111;
		negkey_vars.myr.Private[3] = 0x11111111;
		negkey_vars.myr.Private[4] = 0x66666666;

		// Pi = ri*G
		negkey_vars.myr.Public = &negkey_vars.my_SecondPublicKey;
		negkey_vars.myr.Public->pui32X = negkey_vars.my_SecondPublicKey_X;
		negkey_vars.myr.Public->pui32Y = negkey_vars.my_SecondPublicKey_Y;

		negkey_vars.my_SecondPublicKey_X[0] = 0x462415d8;
		negkey_vars.my_SecondPublicKey_X[1] = 0x26ccac34;
		negkey_vars.my_SecondPublicKey_X[2] = 0x0c6375a3;
		negkey_vars.my_SecondPublicKey_X[3] = 0x09978244;
		negkey_vars.my_SecondPublicKey_X[4] = 0x16e23b0;

		negkey_vars.my_SecondPublicKey_Y[0] = 0x9d847f23;
		negkey_vars.my_SecondPublicKey_Y[1] = 0xbc7ab846;
		negkey_vars.my_SecondPublicKey_Y[2] = 0x3cdd99b7;
		negkey_vars.my_SecondPublicKey_Y[3] = 0xdccb4846;
		negkey_vars.my_SecondPublicKey_Y[4] = 0x1abbcdc2;

		// Status = PKA_ECCMultGenPt(negkey_vars.myr.Private,
		// 	                  negkey_vars.myr.Public,
		// 					  negkey_vars.curve_info);

		// wi = [ID || ts || Xi.x || Xi.y || Pi.x || Pi.y]
		memcpy(wi, negkey_vars.id, 2);
		memcpy(wi + 2, negkey_vars.ts, 10);
		memcpy(wi + 2 + 10, negkey_vars.my_FirstPublicKey_X, sizeof(negkey_vars.my_FirstPublicKey_X));
		memcpy(wi + 2 + 10 + sizeof(negkey_vars.my_FirstPublicKey_X), negkey_vars.my_FirstPublicKey_Y, sizeof(negkey_vars.my_FirstPublicKey_Y));
		memcpy(wi + 2 + 10 + sizeof(negkey_vars.my_FirstPublicKey_X) + sizeof(negkey_vars.my_FirstPublicKey_Y), negkey_vars.my_SecondPublicKey_X, sizeof(negkey_vars.my_SecondPublicKey_X));
		memcpy(wi + 2 + 10 + sizeof(negkey_vars.my_FirstPublicKey_X) + sizeof(negkey_vars.my_FirstPublicKey_Y) + sizeof(negkey_vars.my_SecondPublicKey_X), negkey_vars.my_SecondPublicKey_Y, sizeof(negkey_vars.my_SecondPublicKey_Y));

		// Computing hi
		hmac_sha1(wi,
				  wi_len,
				  _Key, strlen(_Key),
				  _hi);

		memcpy(negkey_vars.Hi, _hi, 4 * HASHLENGTH);

		// Computing pi
		if (CURVE_LEN == 5)
		{
			nsize = CURVE_LEN + 1;
		}
		else
		{
			nsize = CURVE_LEN;
		}

		// hi*c 'stored' in hic
		Status = PKA_BigNumMultiply(negkey_vars.Hi,
									(uint8_t)CURVE_LEN,
									negkey_vars.keypair_CA.Private,
									(uint8_t)CURVE_LEN,
									hic,
									&hicLength);

		// ri + hi*c 'stored' in rihic
		Status = PKA_BigNumAdd(hic,
							   (uint8_t)hicLength,
							   negkey_vars.myr.Private,
							   (uint8_t)CURVE_LEN,
							   rihic,
							   &rihicLength);

		// pi = ri + hi*c mod n 'stored' in pi
		Status = PKA_BigNumMod(rihic,
							   (uint8_t)rihicLength,
							   negkey_vars.curve_info->pui32N, //nist_p_256_2.pui32N,//nist_p_160_2.pui32N,//
							   (uint8_t)nsize,				   //CURVE_LEN+1,
							   pi,
							   (uint8_t)piLength);

		break;
	// case TOPOLOGY_CHILD_2:
	//  negkey_vars.my_PrivateKey[0] = 2408198671;
	// 	negkey_vars.my_PrivateKey[1] = 2110792269;
	// 	negkey_vars.my_PrivateKey[2] = 1582306535;
	// 	negkey_vars.my_PrivateKey[3] = 437428754;
	// 	negkey_vars.my_PrivateKey[4] = 539043048;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 341896355;
	// 	negkey_vars.my_PublicKey_X[1] = 791784823;
	// 	negkey_vars.my_PublicKey_X[2] = 3705687102;
	// 	negkey_vars.my_PublicKey_X[3] = 3289307150;
	// 	negkey_vars.my_PublicKey_X[4] = 1743367137;
	// 	negkey_vars.my_PublicKey_Y[0] = 4275221217;
	// 	negkey_vars.my_PublicKey_Y[1] = 1505439863;
	// 	negkey_vars.my_PublicKey_Y[2] = 687685654;
	// 	negkey_vars.my_PublicKey_Y[3] = 717331688;
	// 	negkey_vars.my_PublicKey_Y[4] = 880220740;
	// 	negkey_vars.waitConstant = 3;
	// 	break;
	// case TOPOLOGY_CHILD_3:
	//    	negkey_vars.my_PrivateKey[0] = 4113678411;
	// 	negkey_vars.my_PrivateKey[1] = 3821285415;
	// 	negkey_vars.my_PrivateKey[2] = 4257744126;
	// 	negkey_vars.my_PrivateKey[3] = 1157336442;
	// 	negkey_vars.my_PrivateKey[4] = 2888508310;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 2716814799;
	// 	negkey_vars.my_PublicKey_X[1] = 53715461;
	// 	negkey_vars.my_PublicKey_X[2] = 1037973144;
	// 	negkey_vars.my_PublicKey_X[3] = 1353949855;
	// 	negkey_vars.my_PublicKey_X[4] = 3895046407;
	// 	negkey_vars.my_PublicKey_Y[0] = 1557580693;
	// 	negkey_vars.my_PublicKey_Y[1] = 2443361926;
	// 	negkey_vars.my_PublicKey_Y[2] = 4242859;
	// 	negkey_vars.my_PublicKey_Y[3] = 2834511285;
	// 	negkey_vars.my_PublicKey_Y[4] = 2305301951;
	// 	negkey_vars.waitConstant = 4;
	// 	break;
	// case TOPOLOGY_CHILD_4:
	//    	negkey_vars.my_PrivateKey[0] = 1286064591;
	// 	negkey_vars.my_PrivateKey[1] = 1907248398;
	// 	negkey_vars.my_PrivateKey[2] = 4223108243;
	// 	negkey_vars.my_PrivateKey[3] = 66812198;
	// 	negkey_vars.my_PrivateKey[4] = 3749571664;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 1720371484;
	// 	negkey_vars.my_PublicKey_X[1] = 1322144000;
	// 	negkey_vars.my_PublicKey_X[2] = 1210731917;
	// 	negkey_vars.my_PublicKey_X[3] = 1702704028;
	// 	negkey_vars.my_PublicKey_X[4] = 815283470;
	// 	negkey_vars.my_PublicKey_Y[0] = 4146531041;
	// 	negkey_vars.my_PublicKey_Y[1] = 3255627227;
	// 	negkey_vars.my_PublicKey_Y[2] = 3430496714;
	// 	negkey_vars.my_PublicKey_Y[3] = 3287281218;
	// 	negkey_vars.my_PublicKey_Y[4] = 1062617826;
	// 	negkey_vars.waitConstant = 5;
	// 	break;
	// case TOPOLOGY_CHILD_5:
	//    	negkey_vars.my_PrivateKey[0] = 805371085;
	// 	negkey_vars.my_PrivateKey[1] = 631554981;
	// 	negkey_vars.my_PrivateKey[2] = 2739608914;
	// 	negkey_vars.my_PrivateKey[3] = 4018882481;
	// 	negkey_vars.my_PrivateKey[4] = 2836761914;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 3123394778;
	// 	negkey_vars.my_PublicKey_X[1] = 2363747289;
	// 	negkey_vars.my_PublicKey_X[2] = 1704886989;
	// 	negkey_vars.my_PublicKey_X[3] = 970788698;
	// 	negkey_vars.my_PublicKey_X[4] = 2458926978;
	// 	negkey_vars.my_PublicKey_Y[0] = 1571095667;
	// 	negkey_vars.my_PublicKey_Y[1] = 407430784;
	// 	negkey_vars.my_PublicKey_Y[2] = 718426564;
	// 	negkey_vars.my_PublicKey_Y[3] = 590201025;
	// 	negkey_vars.my_PublicKey_Y[4] = 4037240664;
	// 	negkey_vars.waitConstant = 6;
	// 	break;
	// case TOPOLOGY_CHILD_6:
	//    	negkey_vars.my_PrivateKey[0] = 3203492740;
	// 	negkey_vars.my_PrivateKey[1] = 2569277708;
	// 	negkey_vars.my_PrivateKey[2] = 3691681783;
	// 	negkey_vars.my_PrivateKey[3] = 1193653226;
	// 	negkey_vars.my_PrivateKey[4] = 457599840;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 1273669611;
	// 	negkey_vars.my_PublicKey_X[1] = 916977857;
	// 	negkey_vars.my_PublicKey_X[2] = 1500125563;
	// 	negkey_vars.my_PublicKey_X[3] = 853708793;
	// 	negkey_vars.my_PublicKey_X[4] = 2859362292;
	// 	negkey_vars.my_PublicKey_Y[0] = 2637255893;
	// 	negkey_vars.my_PublicKey_Y[1] = 3449225077;
	// 	negkey_vars.my_PublicKey_Y[2] = 3763203740;
	// 	negkey_vars.my_PublicKey_Y[3] = 2460811410;
	// 	negkey_vars.my_PublicKey_Y[4] = 799004051;
	// 	negkey_vars.waitConstant = 7;
	// 	break;
	// case TOPOLOGY_CHILD_7:
	//    	negkey_vars.my_PrivateKey[0] = 2333808593;
	// 	negkey_vars.my_PrivateKey[1] = 2410156574;
	// 	negkey_vars.my_PrivateKey[2] = 4282375537;
	// 	negkey_vars.my_PrivateKey[3] = 2155311770;
	// 	negkey_vars.my_PrivateKey[4] = 621843714;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 3817351512;
	// 	negkey_vars.my_PublicKey_X[1] = 3407435778;
	// 	negkey_vars.my_PublicKey_X[2] = 1864557572;
	// 	negkey_vars.my_PublicKey_X[3] = 2921814114;
	// 	negkey_vars.my_PublicKey_X[4] = 1696186224;
	// 	negkey_vars.my_PublicKey_Y[0] = 4015195653;
	// 	negkey_vars.my_PublicKey_Y[1] = 3268271189;
	// 	negkey_vars.my_PublicKey_Y[2] = 1004305741;
	// 	negkey_vars.my_PublicKey_Y[3] = 1790499417;
	// 	negkey_vars.my_PublicKey_Y[4] = 4059956123;
	// 	negkey_vars.waitConstant = 8;
	// 	break;
	// case TOPOLOGY_CHILD_8:
	//    	negkey_vars.my_PrivateKey[0] = 1364039547;
	// 	negkey_vars.my_PrivateKey[1] = 1757561329;
	// 	negkey_vars.my_PrivateKey[2] = 452496724;
	// 	negkey_vars.my_PrivateKey[3] = 1639189342;
	// 	negkey_vars.my_PrivateKey[4] = 3427598059;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 4223964944;
	// 	negkey_vars.my_PublicKey_X[1] = 1069660021;
	// 	negkey_vars.my_PublicKey_X[2] = 1542908371;
	// 	negkey_vars.my_PublicKey_X[3] = 1655977419;
	// 	negkey_vars.my_PublicKey_X[4] = 1681027037;
	// 	negkey_vars.my_PublicKey_Y[0] = 3420630221;
	// 	negkey_vars.my_PublicKey_Y[1] = 2271236292;
	// 	negkey_vars.my_PublicKey_Y[2] = 1322218080;
	// 	negkey_vars.my_PublicKey_Y[3] = 3859669992;
	// 	negkey_vars.my_PublicKey_Y[4] = 4114326563;
	// 	negkey_vars.waitConstant = 9;
	// 	break;
	// case TOPOLOGY_CHILD_9:
	//    	negkey_vars.my_PrivateKey[0] = 3362162768;
	// 	negkey_vars.my_PrivateKey[1] = 306412675;
	// 	negkey_vars.my_PrivateKey[2] = 1166704105;
	// 	negkey_vars.my_PrivateKey[3] = 3887522315;
	// 	negkey_vars.my_PrivateKey[4] = 392869942;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 2264331829;
	// 	negkey_vars.my_PublicKey_X[1] = 2357813816;
	// 	negkey_vars.my_PublicKey_X[2] = 2623850661;
	// 	negkey_vars.my_PublicKey_X[3] = 4088652090;
	// 	negkey_vars.my_PublicKey_X[4] = 2861604716;
	// 	negkey_vars.my_PublicKey_Y[0] = 3803392802;
	// 	negkey_vars.my_PublicKey_Y[1] = 478582719;
	// 	negkey_vars.my_PublicKey_Y[2] = 2008914603;
	// 	negkey_vars.my_PublicKey_Y[3] = 1386403533;
	// 	negkey_vars.my_PublicKey_Y[4] = 60222069;
	// 	negkey_vars.waitConstant = 10;
	// 	break;
	// case TOPOLOGY_CHILD_10:
	//    	negkey_vars.my_PrivateKey[0] = 325152318;
	// 	negkey_vars.my_PrivateKey[1] = 2837523873;
	// 	negkey_vars.my_PrivateKey[2] = 1481979932;
	// 	negkey_vars.my_PrivateKey[3] = 4134450191;
	// 	negkey_vars.my_PrivateKey[4] = 4007547268;
	// 	negkey_vars.my_PrivateKey[5] = 536892160;
	// 	negkey_vars.my_PrivateKey[6] = 10;
	// 	negkey_vars.my_PublicKey_X[0] = 2882084669;
	// 	negkey_vars.my_PublicKey_X[1] = 1978843074;
	// 	negkey_vars.my_PublicKey_X[2] = 442850012;
	// 	negkey_vars.my_PublicKey_X[3] = 1057468984;
	// 	negkey_vars.my_PublicKey_X[4] = 3764685169;
	// 	negkey_vars.my_PublicKey_Y[0] = 788348704;
	// 	negkey_vars.my_PublicKey_Y[1] = 1276211211;
	// 	negkey_vars.my_PublicKey_Y[2] = 1977369108;
	// 	negkey_vars.my_PublicKey_Y[3] = 4264663570;
	// 	negkey_vars.my_PublicKey_Y[4] = 1553786558;
	// 	negkey_vars.waitConstant = 11;
	// 	break;
	default:
		break;
	}

	//accomodate pointers for neighbor first public key
	negkey_vars.neighborFirstKey.Public = &negkey_vars.neighbor_FirstPublicKey;
	negkey_vars.neighborFirstKey.Public->pui32X = negkey_vars.neighbor_FirstPublicKey_X; //&
	negkey_vars.neighborFirstKey.Public->pui32Y = negkey_vars.neighbor_FirstPublicKey_Y; //&

	//accomodate pointers for neighbor second public key
	negkey_vars.neighborSecondKey.Public = &negkey_vars.neighbor_SecondPublicKey;
	negkey_vars.neighborSecondKey.Public->pui32X = negkey_vars.neighbor_SecondPublicKey_X; //&
	negkey_vars.neighborSecondKey.Public->pui32Y = negkey_vars.neighbor_SecondPublicKey_Y; //&

	//set initial state to READY
	negkey_vars.m_kmpState = READY;

	//set the initial timer period
	negkey_vars.periodMaintenance = 1000;
	//launch the kmp application
	negkey_vars.maintenanceTimerId = opentimers_create();

	opentimers_scheduleIn(
		negkey_vars.maintenanceTimerId,
		negkey_vars.periodMaintenance,
		TIME_MS,
		TIMER_PERIODIC,
		negkey_timer_cb);
}

void negkey_timer_cb(void)
{
	scheduler_push_task(timers_negkey_fired, TASKPRIO_SIXTOP_NOTIF_RX);
}

void timers_negkey_fired(void)
{
	if ((idmanager_getIsDAGroot() == FALSE) && (ieee154e_isSynch() == 1) && (negkey_vars.m_kmpState == READY))
	{
		scheduler_push_task(send_Data, TASKPRIO_NONE);
	}
}

void send_Data(void)
{
	//leds_error_on_mod();
	OpenQueueEntry_t *pkt;

	// get a free packet buffer
	pkt = openqueue_getFreePacketBuffer(COMPONENT_SIXTOP);
	if (pkt == NULL)
	{
		openserial_printError(COMPONENT_SIXTOP, ERR_NO_FREE_PACKET_BUFFER,
							  (errorparameter_t)0,
							  (errorparameter_t)0);
		return;
	}

	// declare ownership over that packet
	pkt->creator = COMPONENT_SIXTOP;
	pkt->owner = COMPONENT_SIXTOP;

	// some l2 information about this packet
	pkt->l2_frameType = IEEE154_TYPE_DATA;

	if (idmanager_getIsDAGroot() == FALSE)
	{
		icmpv6rpl_getPreferredParentEui64(&(pkt->l2_nextORpreviousHop));
		if (pkt->l2_nextORpreviousHop.type == 0)
		{
			openserial_printInfo(COMPONENT_SECURITY, ERR_SECURITY,
								 (errorparameter_t)pkt->l2_nextORpreviousHop.type,
								 (errorparameter_t)334);
			return;
		}
	}
	else
	{
		memcpy(&(pkt->l2_nextORpreviousHop), &(negkey_vars.last_Neighbor), sizeof(open_addr_t));
		memcpy(&(pkt->l2_keySource), idmanager_getMyID(ADDR_64B), sizeof(open_addr_t));
	}

	// DEFINE THE START OF LIKE PROTOCOL
	// 2 bytes for the random number, 1 for the protocol ID, and wi_len for the (ID||ts||Xi||Pi)
	packetfunctions_reserveHeaderSize(pkt, 2 + 1 + wi_len * sizeof(uint8_t));
	pkt->payload[0] = PROTOCOL_ID;
	uint8_t i;
	for (i = 1; i <= wi_len; i++)
	{
		pkt->payload[i] = wi[i - 1];
	}

	negkey_vars.myRand = openrandom_get16b(); //my random number

	// Include the Random Number
	pkt->payload[i] = (negkey_vars.myRand >> (8 * 0)) & 0xff;	 //first byte
	pkt->payload[i + 1] = (negkey_vars.myRand >> (8 * 1)) & 0xff; //second byte

	sixtop_send(pkt);
}

void negkey_receive(OpenQueueEntry_t *msg)
{
	switch (negkey_vars.m_kmpState)
	{
	case READY:

		// wi = [ID || ts || Xi.x || Xi.y || Pi.x || Pi.y]
		//Save Remote ID
		negkey_vars.remoteID[0] = msg->payload[1];
		negkey_vars.remoteID[1] = msg->payload[2];

		// Save Remote timestamp
		uint8_t j;
		for (j = 3; j <= 12; j++)
		{
			negkey_vars.remotets[j - 3] = msg->payload[j];
		}

		// First Remote Public Key
		negkey_vars.neighbor_FirstPublicKey_X[0] = msg->payload[13] + (msg->payload[14] * 256) + (msg->payload[15] * 256 * 256) + (msg->payload[16] * 256 * 256 * 256);
		negkey_vars.neighbor_FirstPublicKey_X[1] = msg->payload[17] + (msg->payload[18] * 256) + (msg->payload[19] * 256 * 256) + (msg->payload[20] * 256 * 256 * 256);
		negkey_vars.neighbor_FirstPublicKey_X[2] = msg->payload[21] + (msg->payload[22] * 256) + (msg->payload[23] * 256 * 256) + (msg->payload[24] * 256 * 256 * 256);
		negkey_vars.neighbor_FirstPublicKey_X[3] = msg->payload[25] + (msg->payload[26] * 256) + (msg->payload[27] * 256 * 256) + (msg->payload[28] * 256 * 256 * 256);
		negkey_vars.neighbor_FirstPublicKey_X[4] = msg->payload[29] + (msg->payload[30] * 256) + (msg->payload[31] * 256 * 256) + (msg->payload[32] * 256 * 256 * 256);

		negkey_vars.neighbor_FirstPublicKey_Y[0] = msg->payload[33] + (msg->payload[34] * 256) + (msg->payload[35] * 256 * 256) + (msg->payload[36] * 256 * 256 * 256);
		negkey_vars.neighbor_FirstPublicKey_Y[1] = msg->payload[37] + (msg->payload[38] * 256) + (msg->payload[39] * 256 * 256) + (msg->payload[40] * 256 * 256 * 256);
		negkey_vars.neighbor_FirstPublicKey_Y[2] = msg->payload[41] + (msg->payload[42] * 256) + (msg->payload[43] * 256 * 256) + (msg->payload[44] * 256 * 256 * 256);
		negkey_vars.neighbor_FirstPublicKey_Y[3] = msg->payload[45] + (msg->payload[46] * 256) + (msg->payload[47] * 256 * 256) + (msg->payload[48] * 256 * 256 * 256);
		negkey_vars.neighbor_FirstPublicKey_Y[4] = msg->payload[49] + (msg->payload[50] * 256) + (msg->payload[51] * 256 * 256) + (msg->payload[52] * 256 * 256 * 256);

		// Second Remote Public Key

		negkey_vars.neighbor_SecondPublicKey_X[0] = msg->payload[53] + (msg->payload[54] * 256) + (msg->payload[55] * 256 * 256) + (msg->payload[56] * 256 * 256 * 256);
		negkey_vars.neighbor_SecondPublicKey_X[1] = msg->payload[57] + (msg->payload[58] * 256) + (msg->payload[59] * 256 * 256) + (msg->payload[60] * 256 * 256 * 256);
		negkey_vars.neighbor_SecondPublicKey_X[2] = msg->payload[61] + (msg->payload[62] * 256) + (msg->payload[63] * 256 * 256) + (msg->payload[64] * 256 * 256 * 256);
		negkey_vars.neighbor_SecondPublicKey_X[3] = msg->payload[65] + (msg->payload[66] * 256) + (msg->payload[67] * 256 * 256) + (msg->payload[68] * 256 * 256 * 256);
		negkey_vars.neighbor_SecondPublicKey_X[4] = msg->payload[69] + (msg->payload[70] * 256) + (msg->payload[71] * 256 * 256) + (msg->payload[72] * 256 * 256 * 256);

		negkey_vars.neighbor_SecondPublicKey_Y[0] = msg->payload[73] + (msg->payload[74] * 256) + (msg->payload[75] * 256 * 256) + (msg->payload[76] * 256 * 256 * 256);
		negkey_vars.neighbor_SecondPublicKey_Y[1] = msg->payload[77] + (msg->payload[78] * 256) + (msg->payload[79] * 256 * 256) + (msg->payload[80] * 256 * 256 * 256);
		negkey_vars.neighbor_SecondPublicKey_Y[2] = msg->payload[81] + (msg->payload[82] * 256) + (msg->payload[83] * 256 * 256) + (msg->payload[84] * 256 * 256 * 256);
		negkey_vars.neighbor_SecondPublicKey_Y[3] = msg->payload[85] + (msg->payload[86] * 256) + (msg->payload[87] * 256 * 256) + (msg->payload[88] * 256 * 256 * 256);
		negkey_vars.neighbor_SecondPublicKey_Y[4] = msg->payload[89] + (msg->payload[90] * 256) + (msg->payload[91] * 256 * 256) + (msg->payload[92] * 256 * 256 * 256);

		negkey_vars.remoteRand = msg->payload[93] + msg->payload[94] * 256;

		scheduler_push_task(negkey_computeDHKey, TASKPRIO_NONE);

		// Receiver send the second message of the protocol
		if (idmanager_getIsDAGroot() == TRUE && negkey_vars.m_kmpState == READY)
		{
			negkey_vars.last_Neighbor = msg->l2_nextORpreviousHop;
			scheduler_push_task(send_Data, TASKPRIO_NONE);
			openqueue_freePacketBuffer(msg);
			//msg->isLike = FALSE;

			// Receiver change state
			negkey_vars.m_kmpState = SECOND_FRAG;
		}
		else
		{
			scheduler_push_task(negkey_sendAuthentication, TASKPRIO_NONE);
			openqueue_freePacketBuffer(msg);
			//msg->isLike = FALSE;
			negkey_vars.m_kmpState = SECOND_FRAG;
			//Inviare Authentication Tag
		}

		break;

	case SECOND_FRAG:
		for (j = 1; j <= 20; j++)
		{
			negkey_vars.sigRemote[j - 1] = msg->payload[j];
		}
		//Controllare Authentication Tag
		if (negkey_checkAuth() == E_SUCCESS)
		{
			//Compute Session Link Key
			scheduler_push_task(negkey_computeLinkKey, TASKPRIO_NONE);
		}

		// Receiver send the fourth message of the protocol
		if (idmanager_getIsDAGroot() == TRUE && negkey_vars.m_kmpState == SECOND_FRAG)
		{
			negkey_vars.last_Neighbor = msg->l2_nextORpreviousHop;
			scheduler_push_task(negkey_sendAuthentication, TASKPRIO_NONE);
			openqueue_freePacketBuffer(msg);

			negkey_vars.m_kmpState = READY; // restart the protocol
			negkey_vars.myRand = openrandom_get16b();
		}
		else
		{
			negkey_vars.m_kmpState = KMP_COMPLETED;
		}
		break;

	case KMP_COMPLETED:
		break;

	default:
		break;
	}
}

void negkey_computeDHKey(void)
{

	memcpy(wi_remote, negkey_vars.remoteID, 2);
	memcpy(wi_remote + 2, negkey_vars.remotets, 10);
	memcpy(wi_remote + 2 + 10, negkey_vars.neighbor_FirstPublicKey_X, sizeof(negkey_vars.neighbor_FirstPublicKey_X));
	memcpy(wi_remote + 2 + 10 + sizeof(negkey_vars.neighbor_FirstPublicKey_X), negkey_vars.neighbor_FirstPublicKey_Y, sizeof(negkey_vars.neighbor_FirstPublicKey_Y));
	memcpy(wi_remote + 2 + 10 + sizeof(negkey_vars.neighbor_FirstPublicKey_X) + sizeof(negkey_vars.neighbor_FirstPublicKey_Y), negkey_vars.neighbor_SecondPublicKey_X, sizeof(negkey_vars.neighbor_SecondPublicKey_X));
	memcpy(wi_remote + 2 + 10 + sizeof(negkey_vars.neighbor_FirstPublicKey_X) + sizeof(negkey_vars.neighbor_FirstPublicKey_Y) + sizeof(negkey_vars.neighbor_SecondPublicKey_X), negkey_vars.neighbor_SecondPublicKey_Y, sizeof(negkey_vars.neighbor_SecondPublicKey_Y));

	// Computing hi
	hmac_sha1(wi_remote,
			  wi_len,
			  _Key, strlen(_Key),
			  _hi_remote);

	memcpy(negkey_vars.Hi_remote, _hi_remote, 4 * HASHLENGTH);

	// Computing pi
	if (CURVE_LEN == 5)
	{
		nsize = CURVE_LEN + 1;
	}
	else
	{
		nsize = CURVE_LEN;
	}

	tECPt HashPub;

	uint32_t HashPubX_[CURVE_LEN] = {0};
	uint32_t HashPubY_[CURVE_LEN] = {0};

	HashPub.pui32X = HashPubX_;
	HashPub.pui32Y = HashPubY_;

	tECPt HashAddPub;

	uint32_t HashAddPubX_[CURVE_LEN] = {0};
	uint32_t HashAddPubY_[CURVE_LEN] = {0};

	HashAddPub.pui32X = HashAddPubX_;
	HashAddPub.pui32Y = HashAddPubY_;

	tECPt FinalK1;

	uint32_t FinalK1_X_[CURVE_LEN] = {0};
	uint32_t FinalK1_Y_[CURVE_LEN] = {0};

	FinalK1.pui32X = FinalK1_X_;
	FinalK1.pui32Y = FinalK1_Y_;

	// hB*C 'stored' in hBC_PubKeyInt
	Status = PKA_ECCMultiply(negkey_vars.Hi_remote,
							 negkey_vars.keypair_CA.Public,
							 &HashPub,
							 negkey_vars.curve_info);

	// PB + hB*C 'stored' in pBhBC
	Status = PKA_ECCAdd(&HashPub,
						negkey_vars.neighborSecondKey.Public,
						&HashAddPub,
						negkey_vars.curve_info);

	// pA*(PB+hB*C) 'stored' in pAPBhBC
	Status = PKA_ECCMultiply(pi,
							 &HashAddPub,
							 &FinalK1,
							 negkey_vars.curve_info);
	tECPt FinalK2;

	uint32_t FinalK2_X_[CURVE_LEN] = {0};
	uint32_t FinalK2_Y_[CURVE_LEN] = {0};

	FinalK2.pui32X = FinalK2_X_;
	FinalK2.pui32Y = FinalK2_Y_;

	Status = PKA_ECCMultiply(negkey_vars.myFirstKey.Private,
							 negkey_vars.neighborFirstKey.Public,
							 &FinalK2,
							 negkey_vars.curve_info);

	unsigned char _KAB[80] = {0};
	unsigned char _skAB[20] = {0};

	memcpy(_KAB, FinalK1_X_, sizeof(FinalK1_X_));
	memcpy(_KAB + sizeof(FinalK1_X_), FinalK1_Y_, sizeof(FinalK1_Y_));
	memcpy(_KAB + sizeof(FinalK1_X_) + sizeof(FinalK1_Y_), FinalK2_X_, sizeof(FinalK2_X_));
	memcpy(_KAB + sizeof(FinalK1_X_) + sizeof(FinalK1_Y_) + sizeof(FinalK2_X_), FinalK2_Y_, sizeof(FinalK2_Y_));

	hmac_sha1(_KAB,
			  80,
			  _Key, strlen(_Key),
			  _skAB);

	memcpy(negkey_vars.hashKey, _skAB, 4 * HASHLENGTH);
}

void negkey_sendAuthentication(void)
{
	OpenQueueEntry_t *pkt;
	// get a free packet buffer
	pkt = openqueue_getFreePacketBuffer(COMPONENT_SIXTOP);
	if (pkt == NULL)
	{
		openserial_printError(COMPONENT_SIXTOP, ERR_NO_FREE_PACKET_BUFFER,
							  (errorparameter_t)0,
							  (errorparameter_t)0);
		return;
	}

	// declare ownership over that packet
	pkt->creator = COMPONENT_SIXTOP;
	pkt->owner = COMPONENT_SIXTOP;

	// some l2 information about this packet
	pkt->l2_frameType = IEEE154_TYPE_DATA;

	if (idmanager_getIsDAGroot() == FALSE)
	{
		icmpv6rpl_getPreferredParentEui64(&(pkt->l2_nextORpreviousHop));
		if (pkt->l2_nextORpreviousHop.type == 0)
		{
			return;
		}
	}
	else
	{
		memcpy(&(pkt->l2_nextORpreviousHop), &(negkey_vars.last_Neighbor), sizeof(open_addr_t));
		memcpy(&(pkt->l2_keySource), idmanager_getMyID(ADDR_64B), sizeof(open_addr_t));
	}

	// DEFINE THE START OF LIKE PROTOCOL
	// 2 bytes for the random number, 1 for the protocol ID, and wi_len for the (ID||ts||Xi||Pi)
	packetfunctions_reserveHeaderSize(pkt, 1 + 20 * sizeof(uint8_t));
	pkt->payload[0] = PROTOCOL_ID;

	// Compute sigma (Authentication TAG)
	unsigned char sigma[2 * (2 + 10 + 2 * (CURVE_LEN * 4 * 2)) + 4] = {0};
	unsigned char sigmaH[20] = {0};

	memcpy(sigma, wi, sizeof(wi));
	memcpy(sigma + sizeof(wi), wi_remote, sizeof(wi_remote));
	memcpy(sigma + sizeof(wi) + sizeof(wi_remote), negkey_vars.myRand, sizeof(uint16_t));
	memcpy(sigma + sizeof(wi) + sizeof(wi_remote) + sizeof(uint16_t), negkey_vars.remoteRand, sizeof(uint16_t));

	hmac_sha1(sigma,
			  sizeof(sigma),
			  negkey_vars.hashKey, strlen(negkey_vars.hashKey),
			  sigmaH);

	memcpy(negkey_vars.sig, sigmaH, 4 * HASHLENGTH);

	for (uint8_t i = 1; i <= 20; i++)
	{
		pkt->payload[i] = negkey_vars.sig[i - 1];
	}

	sixtop_send(pkt);
}

owerror_t negkey_checkAuth(void)
{
	// Compute sigma (Authentication TAG)
	unsigned char sigmaV[2 * (2 + 10 + 2 * (CURVE_LEN * 4 * 2)) + 4] = {0};
	unsigned char sigmaVH[20] = {0};

	memcpy(sigmaV, wi_remote, sizeof(wi_remote));
	memcpy(sigmaV + sizeof(wi_remote), wi, sizeof(wi));
	memcpy(sigmaV + sizeof(wi_remote) + sizeof(wi), negkey_vars.remoteRand, sizeof(uint16_t));
	memcpy(sigmaV + sizeof(wi_remote) + sizeof(wi) + sizeof(uint16_t), negkey_vars.myRand, sizeof(uint16_t));

	hmac_sha1(sigmaV,
			  sizeof(sigmaV),
			  negkey_vars.hashKey, strlen(negkey_vars.hashKey),
			  sigmaVH);

	memcpy(negkey_vars.sigRemoteCheck, sigmaVH, 4 * HASHLENGTH);

	if (memcmp(negkey_vars.sigRemote, negkey_vars.sigRemoteCheck, 20) == 0)
	{
		return E_SUCCESS;
	}
	else
	{
		return E_SUCCESS; //only for TEST! ---
						  //return E_FAIL;
	}
}

void negkey_computeLinkKey(void)
{
	unsigned char sessionLinkKey[30] = {0};
	unsigned char Lk[20] = {0};

	if (idmanager_getIsDAGroot() == TRUE)
	{
		memcpy(sessionLinkKey, negkey_vars.hashKey, sizeof(negkey_vars.hashKey));
		memcpy(sessionLinkKey + sizeof(negkey_vars.hashKey), negkey_vars.remoteRand, sizeof(negkey_vars.remoteRand));
		memcpy(sessionLinkKey + sizeof(negkey_vars.hashKey) + sizeof(negkey_vars.remoteRand), negkey_vars.myRand, sizeof(negkey_vars.myRand));
	}
	else
	{
		memcpy(sessionLinkKey, negkey_vars.hashKey, sizeof(negkey_vars.hashKey));
		memcpy(sessionLinkKey + sizeof(negkey_vars.hashKey), negkey_vars.myRand, sizeof(negkey_vars.myRand));
		memcpy(sessionLinkKey + sizeof(negkey_vars.hashKey) + sizeof(negkey_vars.myRand), negkey_vars.remoteRand, sizeof(negkey_vars.remoteRand));
	}

	// Computing hi
	hmac_sha1(sessionLinkKey,
			  30,
			  _Key, strlen(_Key),
			  Lk);

	memcpy(negkey_vars.LinkKey, Lk, 4 * HASHLENGTH);

	//Print the negotiated key
	openserial_printInfo(
		COMPONENT_SECURITY,
		ERR_SECURITY,
		(errorparameter_t)negkey_vars.LinkKey[0],
		(errorparameter_t)100);

	openserial_printInfo(
		COMPONENT_SECURITY,
		ERR_SECURITY,
		(errorparameter_t)negkey_vars.LinkKey[1],
		(errorparameter_t)110);

	openserial_printInfo(
		COMPONENT_SECURITY,
		ERR_SECURITY,
		(errorparameter_t)negkey_vars.LinkKey[2],
		(errorparameter_t)120);

	openserial_printInfo(
		COMPONENT_SECURITY,
		ERR_SECURITY,
		(errorparameter_t)negkey_vars.LinkKey[3],
		(errorparameter_t)130);
}

bool negkey_isKMPFinished(void)
{
	if (negkey_vars.m_kmpState == KMP_COMPLETED)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

void hmac_sha1(const unsigned char *inText,
			   uint8_t inTextLength,
			   unsigned char *inKey,
			   uint8_t inKeyLength,
			   unsigned char *outDigest)
{

	const uint8_t B = 64;
	const uint8_t L = 20;

	SHA1_CTX theSHA1Context;
	unsigned char k_ipad[B + 1]; /* inner padding - key XORd with ipad */
	unsigned char k_opad[B + 1]; /* outer padding - key XORd with opad */

	/* if key is longer than 64 bytes reset it to key=SHA1 (key) */
	if (inKeyLength > B)
	{
		SHA1Init(&theSHA1Context);
		SHA1Update(&theSHA1Context, inKey, inKeyLength);
		SHA1Final(inKey, &theSHA1Context);
		inKeyLength = L;
	}

	/* start out by storing key in pads */
	memset(k_ipad, 0, sizeof k_ipad);
	memset(k_opad, 0, sizeof k_opad);
	memcpy(k_ipad, inKey, inKeyLength);
	memcpy(k_opad, inKey, inKeyLength);

	/* XOR key with ipad and opad values */
	int i;
	for (i = 0; i < B; i++)
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/*
	* perform inner SHA1
	*/
	SHA1Init(&theSHA1Context);											/* init context for 1st pass */
	SHA1Update(&theSHA1Context, k_ipad, B);								/* start with inner pad */
	SHA1Update(&theSHA1Context, (unsigned char *)inText, inTextLength); /* then text of datagram */
	SHA1Final((unsigned char *)outDigest, &theSHA1Context);				/* finish up 1st pass */

	/*
	* perform outer SHA1
	*/
	SHA1Init(&theSHA1Context);				   /* init context for 2nd
	* pass */
	SHA1Update(&theSHA1Context, k_opad, B);	/* start with outer pad */
	SHA1Update(&theSHA1Context, outDigest, L); /* then results of 1st
	* hash */
	SHA1Final(outDigest, &theSHA1Context);	 /* finish up 2nd pass */
}

/**
 * Initialize the SHA1 context
 */
void SHA1Init(SHA1_CTX *ctx)
{
	ctx->Length_Low = 0;
	ctx->Length_High = 0;
	ctx->Message_Block_Index = 0;
	ctx->Intermediate_Hash[0] = 0x67452301;
	ctx->Intermediate_Hash[1] = 0xEFCDAB89;
	ctx->Intermediate_Hash[2] = 0x98BADCFE;
	ctx->Intermediate_Hash[3] = 0x10325476;
	ctx->Intermediate_Hash[4] = 0xC3D2E1F0;
}

/**
 * Accepts an array of octets as the next portion of the message.
 */
void SHA1Update(SHA1_CTX *ctx, const uint8_t *msg, int len)
{
	while (len--)
	{
		ctx->Message_Block[ctx->Message_Block_Index++] = (*msg & 0xFF);
		ctx->Length_Low += 8;

		if (ctx->Length_Low == 0)
			ctx->Length_High++;

		if (ctx->Message_Block_Index == 64)
			SHA1ProcessMessageBlock(ctx);

		msg++;
	}
}

/**
 * Return the 160-bit message digest into the user's array
 */
void SHA1Final(uint8_t *digest, SHA1_CTX *ctx)
{
	int i;

	SHA1PadMessage(ctx);
	memset(ctx->Message_Block, 0, 64);
	ctx->Length_Low = 0; /* and clear length */
	ctx->Length_High = 0;

	for (i = 0; i < SHA1_SIZE; i++)
	{
		digest[i] = ctx->Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03));
	}
}

/**
 * Process the next 512 bits of the message stored in the array.
 */
static void SHA1ProcessMessageBlock(SHA1_CTX *ctx)
{
	const uint32_t K[] = {/* Constants defined in SHA-1   */
						  0x5A827999,
						  0x6ED9EBA1,
						  0x8F1BBCDC,
						  0xCA62C1D6};
	int t;					 /* Loop counter                */
	uint32_t temp;			 /* Temporary word value        */
	uint32_t W[80];			 /* Word sequence               */
	uint32_t A, B, Ci, D, E; /* Word buffers                */

	/*
     *  Initialize the first 16 words in the array W
     */
	for (t = 0; t < 16; t++)
	{
		W[t] = (uint32_t)ctx->Message_Block[t * 4] << 24;
		W[t] |= (uint32_t)ctx->Message_Block[t * 4 + 1] << 16;
		W[t] |= (uint32_t)ctx->Message_Block[t * 4 + 2] << 8;
		W[t] |= (uint32_t)ctx->Message_Block[t * 4 + 3];
	}

	for (t = 16; t < 80; t++)
	{
		W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}

	A = ctx->Intermediate_Hash[0];
	B = ctx->Intermediate_Hash[1];
	Ci = ctx->Intermediate_Hash[2];
	D = ctx->Intermediate_Hash[3];
	E = ctx->Intermediate_Hash[4];

	for (t = 0; t < 20; t++)
	{
		temp = SHA1CircularShift(5, A) +
			   ((B & Ci) | ((~B) & D)) + E + W[t] + K[0];
		E = D;
		D = Ci;
		Ci = SHA1CircularShift(30, B);

		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ Ci ^ D) + E + W[t] + K[1];
		E = D;
		D = Ci;
		Ci = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++)
	{
		temp = SHA1CircularShift(5, A) +
			   ((B & Ci) | (B & D) | (Ci & D)) + E + W[t] + K[2];
		E = D;
		D = Ci;
		Ci = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ Ci ^ D) + E + W[t] + K[3];
		E = D;
		D = Ci;
		Ci = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	ctx->Intermediate_Hash[0] += A;
	ctx->Intermediate_Hash[1] += B;
	ctx->Intermediate_Hash[2] += Ci;
	ctx->Intermediate_Hash[3] += D;
	ctx->Intermediate_Hash[4] += E;
	ctx->Message_Block_Index = 0;
}

/*
 * According to the standard, the message must be padded to an even
 * 512 bits.  The first padding bit must be a '1'.  The last 64
 * bits represent the length of the original message.  All bits in
 * between should be 0.  This function will pad the message
 * according to those rules by filling the Message_Block array
 * accordingly.  It will also call the ProcessMessageBlock function
 * provided appropriately.  When it returns, it can be assumed that
 * the message digest has been computed.
 *
 * @param ctx [in, out] The SHA1 context
 */
static void SHA1PadMessage(SHA1_CTX *ctx)
{
	/*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
	if (ctx->Message_Block_Index > 55)
	{
		ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
		while (ctx->Message_Block_Index < 64)
		{
			ctx->Message_Block[ctx->Message_Block_Index++] = 0;
		}

		SHA1ProcessMessageBlock(ctx);

		while (ctx->Message_Block_Index < 56)
		{
			ctx->Message_Block[ctx->Message_Block_Index++] = 0;
		}
	}
	else
	{
		ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
		while (ctx->Message_Block_Index < 56)
		{

			ctx->Message_Block[ctx->Message_Block_Index++] = 0;
		}
	}

	/*
     *  Store the message length as the last 8 octets
     */
	ctx->Message_Block[56] = ctx->Length_High >> 24;
	ctx->Message_Block[57] = ctx->Length_High >> 16;
	ctx->Message_Block[58] = ctx->Length_High >> 8;
	ctx->Message_Block[59] = ctx->Length_High;
	ctx->Message_Block[60] = ctx->Length_Low >> 24;
	ctx->Message_Block[61] = ctx->Length_Low >> 16;
	ctx->Message_Block[62] = ctx->Length_Low >> 8;
	ctx->Message_Block[63] = ctx->Length_Low;
	SHA1ProcessMessageBlock(ctx);
}