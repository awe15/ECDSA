

#ifndef      USER_ECC_H_
#define      USER_ECC_H_

#define   CONCAT(A, B)               (A ## B)
#define   _HASH_INIT(e)              CONCAT(e, _Init)
#define   _HASH_APPEND(e)            CONCAT(e, _Append)
#define   _HASH_FINISH(e)            CONCAT(e, _Finish)

#if       ECC_HASH == SHA256
#define   HASH_INIT(x)               _HASH_INIT(SHA256)(x)
#define   HASH_FINISH(x, y, z)       _HASH_FINISH(SHA256)(x, y, z) 
#define   HASH_APPEND(x, y, z)       _HASH_APPEND(SHA256)(x, y, z) 
#define   CRL_HASH_SIZE              CRL_SHA256_SIZE
#define   HASHctx_stt                SHA256ctx_stt
#elif     ECC_HASH == SHA1
#define   HASH_INIT(x)               _HASH_INIT(SHA1)(x)
#define   HASH_FINISH(x, y, z)       _HASH_FINISH(SHA1)(x, y, z)
#define   HASH_APPEND(x, y, z)       _HASH_APPEND(SHA1)(x, y, z) 
#define   CRL_HASH_SIZE              CRL_SHA1_SIZE
#define   HASHctx_stt                SHA1ctx_stt
#elif     ECC_HASH == SHA224
#define   HASH_INIT(x)               _HASH_INIT(SHA224)(x)
#define   HASH_FINISH(x, y, z)       _HASH_FINISH(SHA224)(x, y, z)
#define   HASH_APPEND(x, y, z)       _HASH_APPEND(SHA224)(x, y, z)
#define   CRL_HASH_SIZE              CRL_SHA224_SIZE
#define   HASHctx_stt                SHA224ctx_stt
#elif     ECC_HASH == MD5
#define   HASH_INIT(x)               _HASH_INIT(MD5)(x)
#define   HASH_FINISH(x, y, z)       _HASH_FINISH(MD5)(x, y, z) 
#define   HASH_APPEND(x, y, z)       _HASH_APPEND(MD5)(x, y, z) 
#define   CRL_HASH_SIZE              CRL_MD5_SIZE
#define   HASHctx_stt                MD5ctx_stt
#else 
#error    "Not define ECC_HASH !"
#endif 

#include "stdint.h"

/*临时拉出来测试的-----------------------------------------------------------------*/
/******************************************************************************/
/******** Parameters for Elliptic Curve P-192 SHA-256 from FIPS 186-3**********/
/******************************************************************************/

/* ECSA public key */
const uint8_t P_192_a[] =
 {
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
 };

/* coefficient b */
const uint8_t P_192_b[] =
 {
   0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB, 0x72,
   0x24, 0x30, 0x49, 0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1
 };

/* prime modulus p*/
const uint8_t P_192_p[] =
 {
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
 };

/* order n*/
const uint8_t P_192_n[] =
 {
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x99,
   0xDE, 0xF8, 0x36, 0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31
 };

/* base point Gx*/
const uint8_t P_192_Gx[] =
 {
   0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6, 0x7C, 0xBF, 0x20, 0xEB, 0x43,
   0xA1, 0x88, 0x00, 0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12
 };

/* base point Gy*/
const uint8_t P_192_Gy[] =
 {
   0x07, 0x19, 0x2B, 0x95, 0xFF, 0xC8, 0xDA, 0x78, 0x63, 0x10, 0x11, 0xED, 0x6B,
   0x24, 0xCD, 0xD5, 0x73, 0xF9, 0x77, 0xA1, 0x1E, 0x79, 0x48, 0x11
 };

/* ECSA public key */
/* pub_x*/
const uint8_t pub_x_192[] =
 {
   0x9b, 0xf1, 0x2d, 0x71, 0x74, 0xb7, 0x70, 0x8a, 0x07, 0x6a, 0x38, 0xbc, 0x80,
   0xaa, 0x28, 0x66, 0x2f, 0x25, 0x1e, 0x2e, 0xd8, 0xd4, 0x14, 0xdc
 };

/* pub_y */
const uint8_t pub_y_192[] =
 {
   0x48, 0x54, 0xc8, 0xd0, 0x7d, 0xfc, 0x08, 0x82, 0x4e, 0x9e, 0x47, 0x1c, 0xa2,
   0xfe, 0xdc, 0xfc, 0xff, 0x3d, 0xdc, 0xb0, 0x11, 0x57, 0x34, 0x98
 };

/* ECDSA signature of SHA-256("....") */
/* sign_r */
const uint8_t sign_r_192[] =
 {
   0x35, 0x4a, 0xba, 0xec, 0xf4, 0x36, 0x1f, 0xea, 0x90, 0xc2, 0x9b, 0x91, 0x99,
   0x88, 0x2e, 0xdf, 0x85, 0x73, 0xe6, 0x86, 0xa8, 0x13, 0xef, 0xf8
 };

/* sign_s */
const uint8_t sign_s_192[] =
 {
   0x80, 0xf5, 0x00, 0x00, 0xac, 0x86, 0x11, 0x1c, 0x9b, 0x30, 0x47, 0x38, 0x5a,
   0x15, 0xd7, 0x8e, 0x63, 0x2c, 0x58, 0xb7, 0x94, 0x9e, 0x82, 0xc1
 };

	


/******************************************************************************/
/******** Parameters for Elliptic Curve P-256 SHA-256 from FIPS 186-3**********/
/******************************************************************************/
// const uint8_t P_256_a[] =
//   {
//     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
//   };
// const uint8_t P_256_b[] =
//   {
//     0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76,
//     0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce,
//     0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
//   };
// const uint8_t P_256_p[] =
//   {
//     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
//   };
// const uint8_t P_256_n[] =
//   {
//     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//     0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9,
//     0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
//   };
// const uint8_t P_256_Gx[] =
//   {
//     0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
//     0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1,
//     0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
//   };
// const uint8_t P_256_Gy[] =
//   {
//     0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C,
//     0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6,
//     0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
//   };







#endif





