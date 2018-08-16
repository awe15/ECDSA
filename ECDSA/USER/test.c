/**
* \page Tutorial_ECC ECC Tutorial
*
* This library supports ECC functions for:
*  - ECDSA signature verification, Public Key Verification, Scalar Multiplication 
*  - ECDSA signature generation and ECC Key generation 
*
* Unlike other functions in the library ECC objects must be initialized and freed, and to set/get their values
* the user should use special functions.
*
* The first thing to do before starting en ECC operation is to initialize a \ref EC_stt structure containing
* the parameters of the particular ECC curve that the user want to use. This is done through the function
* \ref ECCinitEC and at the end of the ECC operation it can be freed by \ref ECCfreeEC .
* ��ECC��ʼ����֮ǰ������Ҫ���ľ��ǳ�ʼ��һ��ref EC_stt�����ض���Բ���ߵĲ������û�Ҫʹ�õĽṹ��
*  ����ͨ������ref ECCinitEC����ECCĩ�������Ա�����ECCfreeEC�ͷ�
* After this initial call the user might want to initialize other objects for the functions he will call.
* For example initializing a :
* - Private key (\ref ECCprivKey_stt) with \ref ECCinitPrivKey, settings its value through 
*     \ref ECCsetPrivKeyValue and at the end of the operation, freeing it with \ref ECCfreePrivKey
*     ˽Կ(ref ECCprivKey_stt)��ref ECCinitPrivKey���ڲ���������ʱ��ͨ��������ֵECCsetPrivKeyValue����ref ECCfreePrivKey�ͷ���
*   
* - EC point (\ref ECpoint_stt), which is also a public key, is done by \ref ECCinitPoint, its coordinate
*     can be set and get through \ref ECCsetPointCoordinate and \ref ECCgetPointCoordinate and it will be freed
*     through \ref ECCfreePoint
*     EC��(ref ECpoint_stt)����Ҳ��һ����Կ����ͨ��ref ECCinitPoint��������������úͻ�ȡͨ��ref ECCsetPointCoordinate��
*     ref ECCgetPointCoordinate�������ͷŴ�Խref ECCfreePoint
*
*  - ECDSA signature (\ref ECDSAsignature_stt) must be initialized by \ref ECDSAinitSign the two signature
*     values can be set by \ref ECDSAsetSignature and get by \ref ECDSAgetSignature. At the end it should be 
*     freed through \ref ECDSAfreeSign
*     ��Բ��������ǩ��(ref ECDSAsignature_stt)����ͨ��ref ECDSAinitSign����ǩ����
*     ��ʼ��ֵ��������ref ECDSAsetSignature��ref ECDSAgetSignature���ڽ�����Ӧ�ó�Ϊ�ͷŵ�ref ECDSAfreeSign
* Please note that the functions \ref ECCkeyGen and \ref ECDSAsign, require an initialized random engine structure.
* ��ע�⣬��������ECCkeyGen��ref ECDSAsign����Ҫ��ʼ���������ṹ��
* Scalar multiplication is the ECC operation that it is used in ECDSA and in ECDH. It is also used to
* generate a public key.
* �����˷���ECC������Բ��������ǩ������Կ������ʹ�õĲ�����������������GONGԿ
* A simple usage of the ECC API for scalar multiplication to generate a public key from a known private key is shown below:
* һ���򵥵�ʹ��ECC�ı����˷���API����һ����Կ����֪��˽Կ��ʾ��
* \code*/
#include <stdio.h>
#include "crypto.h"
int main()
{
   const uint8_t ecc_160_a[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,0xFC};
   const uint8_t ecc_160_b[]={0x1C,0x97,0xBE,0xFC,0x54,0xBD,0x7A,0x8B,0x65,0xAC,0xF8,0x9F,0x81,0xD4,0xD4,0xAD,0xC5,0x65,0xFA,0x45};
   const uint8_t ecc_160_p[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,0xFF};
   const uint8_t ecc_160_n[]={0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xF4,0xC8,0xF9,0x27,0xAE,0xD3,0xCA,0x75,0x22,0x57};
   const uint8_t ecc_160_xG[]={0x4A,0x96,0xB5,0x68,0x8E,0xF5,0x73,0x28,0x46,0x64,0x69,0x89,0x68,0xC3,0x8B,0xB9,0x13,0xCB,0xFC,0x82};
   const uint8_t ecc_160_yG[]={0x23,0xA6,0x28,0x55,0x31,0x68,0x94,0x7D,0x59,0xDC,0xC9,0x12,0x04,0x23,0x51,0x37,0x7A,0xC5,0xFB,0x32};
   const uint8_t ecc_160_privkey[]={0xAA,0x37,0x4F,0xFC,0x3C,0xE1,0x44,0xE6,0xB0,0x73,0x30,0x79,0x72,0xCB,0x6D,0x57,0xB2,0xA4,0xE9,0x82};

   // ���������ַ��ع�Կ��X����
   uint8_t pubKeyX[160/8];
   // ���������ַ��ع�ԿY����
   uint8_t pubKeyY[160/8];
   // �����������������µ�����С�Ĺ�Կ��X����
   int32_t Xsize;
   // ����������ʹ���µ���Y����Ĺ�Կ�Ĵ�С
   int32_t Ysize;
   // �ṹ������ʹ��Բ���߲���(��Щֵ����)
   EC_stt ECparams;
   // ��Щ����Բ���ߵ�Ķ��� ��ECC��Կֻ����Բ���ߵ㡣
   ECpoint_stt *G = NULL, *PubKey = NULL;
   // ����ñ����˷�������ʹ�ñ���
   ECCprivKey_stt *privkey = NULL;
   int32_t retval;
   membuf_stt mb;  
   uint8_t preallocated_buffer[4096];
		 
   //����membuf_sttԤ�ȷ���Ľṹ(�ڶ�ջ)4kB�Ļ�����
   mb.mSize = sizeof(preallocated_buffer);
   mb.mUsed = 0;
   mb.pmBuf = preallocated_buffer;

   // ��ʼ��EC_stt�ṹ����ֵ֪�����ǻ�ʹ��NULL����δ֪�������г�ʼ��
   ECparams.mAsize = sizeof(ecc_160_a);
   ECparams.pmA = ecc_160_a;
   ECparams.mPsize = sizeof(ecc_160_p);
   ECparams.pmP = ecc_160_p; 
   ECparams.pmN = ecc_160_n;  
   ECparams.mNsize = sizeof(ecc_160_n);
   ECparams.pmB = NULL;    
   ECparams.mBsize = 0;
   ECparams.pmGx = ecc_160_xG;  
   ECparams.mGxsize = sizeof(ecc_160_xG);
   ECparams.pmGy = ecc_160_yG;  
   ECparams.mGysize = sizeof(ecc_160_yG);

   // ��Բ���߳�ʼ�������ĵ���
   retval = ECCinitEC(&ECparams, &mb);
   if (retval != 0)
   {
     printf("Error! ECCinitEC returned %d\n", retval);
     return(-1);
   }
   
	 //��ʼ���㣬�����������ɵ�
   retval = ECCinitPoint(&G, &ECparams, &mb);
   if (retval != 0)
   {
     printf("Error! ECCinitPoint returned %d\n", retval);
     return(-1);
   }

   //Set the coordinates of the generator point inside G �� �����������ɵ������
   retval = ECCsetPointGenerator(G, &ECparams);
   if (retval != 0)
   {
     printf("Error! ECCsetPointGenerator returned %d\n", retval);
     return(-1);
   }

   // ��ʼ���㱣������˷��Ľ��
   retval = ECCinitPoint(&PubKey, &ECparams, &mb);
   if (retval != 0)
   {
     printf("Error! ECCinitPoint returned %d\n", retval);
     return(-1);
   }

   // Initialize the private key objectר����Կ�����ʼ��
   retval = ECCinitPrivKey(&privkey, &ECparams, &mb);
   if (retval != 0)
   {
     printf("Error! ECCinitPrivKey returned %d\n", retval);
     return(-1);
   }
   //Set the private key object����ר����Կ����
   retval = ECCsetPrivKeyValue(privkey, ecc_160_privkey, sizeof(ecc_160_privkey));
   if (retval != 0)
   {
     printf("Error! ECCsetPrivKeyValue returned %d\n", retval);
     return(-1);
   }

   // All ECCscalarMul parameters are initalized and set, proceed.
	 //����ECCscalarMul������ʼ�������ã��������
   retval = ECCscalarMul(G, privkey, PubKey, &ECparams, &mb);
   if (retval != 0 )
   {
     printf("ECCscalarMul returned %d\n",retval);
     return(-1);
   }
   // Now PubKey contains the result point, we can get its coordinates through
	 //���ڹ�Կ������Ľ�������ǿ���ͨ����������
   ECCgetPointCoordinate(PubKey, E_ECC_POINT_COORDINATE_X, pubKeyX, &Xsize);
   ECCgetPointCoordinate(PubKey,  E_ECC_POINT_COORDINATE_X,pubKeyY, &Ysize);

   // Finally we free everything we initialized
	 //��������ͷŵ����ǳ�ʼ������Դ
   ECCfreePrivKey(&privkey, &mb);
   ECCfreePoint(&G, &mb);
   ECCfreePoint(&PubKey, &mb);
   ECCfreeEC(&ECparams, &mb);
 }
/* \endcode
*
* The following example will generate a key pair (both private and public key) and will use the private 
* key to generate a signature for an hash digest. It will export it and reimport it and verify the signature 
* with the public key. 
* �����ʾ��������һ����Կ��(����˽�к͹�����Կ)������ʹ��˽�м�����һ����ϣժҪ��ǩ���������䵼�������µ������֤ǩ���빫Կ
* This example will assume to have an already initialized EC_stt and RNGstate_stt.
* ��ʾ����������һ���ѳ�ʼ����EC_stt��RNGstate_stt
* \code*/
int32_t ECCkeygen_and_ECDSA_tests(EC_stt * pECparams, RNGstate_stt * pRNGstate)
{
  // SHA256("abc")
  uint8_t digest[CRL_SHA256_SIZE] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,
                                     0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,
                                     0xf2,0x00,0x15,0xad};  
  // Structure that will contain the public key  �ṹ������������Կ
  ECpoint_stt *PubKey = NULL;  
  // Structure that will contain the ECDSA signature �ṹ������������Բ��������ǩ��
  ECDSAsignature_stt *sign = NULL;
  // Structure context used to call the ECDSAverify �ṹ���������ڵ���ECDSAverify
  ECDSAverifyCtx_stt verctx;
  // Private Key Structure  ˽Կ�ṹ��
  ECCprivKey_stt *privKey = NULL;
  // Structure context used to call the ECDSAsign �ṹ���������ڵ���ECDSAsign
  ECDSAsignCtx_stt signCtx;
  // Used to check the returned values ���ڼ�鷵�ص�ֵ
  int32_t retval;
  //pointers that will keep the byte arrays of the signature object ָ�룬������ǩ��������ֽ�����
  uint8_t *signR = NULL, *signS = NULL;
  int32_t signRsize, signSsize;

  membuf_stt mb;  
  uint8_t preallocated_buffer[4096];

  //Set up the membuf_stt structure to a preallocated (on stack) buffer of 4kB
	//����membuf_sttԤ�ȷ���Ľṹ(�ڶ�ջ)4kB�Ļ�����
  mb.mSize = sizeof(preallocated_buffer);
  mb.mUsed = 0;
  mb.pmBuf = preallocated_buffer;

  //Init PubKey object ��ʼ����Կ����
  retval = ECCinitPoint(&PubKey, pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECCinitPoint returned %d\n", retval);
    goto err;
  }
  //Init Privkey object ��ʼ��˽Կ����
  retval = ECCinitPrivKey(&privKey, pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECCinitPrivKey returned %d\n", retval);
    goto err;
  }
  //Call the Key Generation Function ��Կ���ɺ����ĵ���
  retval = ECCkeyGen(privKey, PubKey, pRNGstate, pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECCkeyGen returned %d\n",retval);
  }
  
  // We proceed to sign the digest of "message" ���Ǽ���ǩ��ժҪ"message"
  // First initialize the signature that will be returned ���ȳ�ʼ��ǩ������������
  retval = ECDSAinitSign(&sign,pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECDSAinitSign returned %d\n",retval);
  }
  //Then fill the structure used to call to ECDSAsign function Ȼ����д�ýṹ���ڶ�ECDSAsign�����ĵ���
  // fill the EC_stt �EC_stt
  signCtx.pmEC = pECparams;
  // Fill the privkey �privkey
  signCtx.pmPrivKey = privKey;
  //Fill the random engine state ����������״̬
  signCtx.pmRNG = pRNGstate;

  // Call the signature generature function ǩ��generature�����ĵ���
  retval = ECDSAsign(digest, CRL_SHA256_SIZE, sign, &signCtx, &mb);
  if (retval != 0)
  {
    printf("Error! ECDSAsign returned %d\n",retval);
  }
	
  //The signature now it's inside object sign, let's export it to byte arrays
  //First, allocate the needed size, which is the size of the curve's order (N)
	//���ڵ��ڲ�����ǩ���ǩ�������ǽ��䵼�����ֽ�����
	//���ȣ����������Ĵ�С�����Ǹ����ߵĶ����Ĵ�С(N)
  signR = malloc (pECparams->mNsize);
  signS = malloc (pECparams->mNsize);
  if (signR == NULL || signS ==NULL ) { ... ERROR... }
  
  // Now export the signature  ���ڵ�����ǩ��
  retval = ECDSAgetSignature(sign,E_ECDSA_SIGNATURE_R_VALUE, signR, &signRsize);
  retval |= ECDSAgetSignature(sign,E_ECDSA_SIGNATURE_S_VALUE, signS, &signSsize);
  if (retval != 0) { ... ERROR... }
  
  // Free the signature structure, reinit and reimport signature, this is just for testing...
	//���ǩ���ṹ�����³�ʼ�������µ���ǩ������ֻ�ǲ���..��
  ECDSAfreeSign(&sign, &mb);

  retval = ECDSAinitSign(&sign, pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECDSAinitSign returned %d\n",retval);
  }
  retval = ECDSAsetSignature(sign,E_ECDSA_SIGNATURE_R_VALUE, signR, signRsize);
  retval |= ECDSAsetSignature(sign,E_ECDSA_SIGNATURE_S_VALUE, signS, signSsize);
  if (retval != 0) { ... ERROR... }

  // We now have the signature of the message, we try to verify it������������Ϣ��ǩ�������ǳ�����֤��
  // First set the parameters for the verification structure��һ����֤�ṹ�Ĳ���
  verctx.pmEC = pECparams;
  verctx.pmPubKey = PubKey;
 
  // then we can call the verification functionȻ�����ǿ��Ե�����֤����
  retval = ECDSAverify(digest, CRL_SHA256_SIZE, sign, &verctx, &mb);
  
  if (retval == SIGNATURE_VALID)
  {
    printf("Signature VALID\n");
  }
  else
  {
    printf("Error! ECDSAverify returned %d\n",retval);
  }

  // Before returing clean the memory by freeing the signature and the public key �ӱ���ǰ�����ڴ��ͷ�ǩ���͹�Կ
  ECDSAfreeSign(sign, &mb);
  ECCfreePoint(PubKey, &mb);
  ECCfreePrivKey(privKey, &mb);

  return(retval);
 }
// \endcode
*/