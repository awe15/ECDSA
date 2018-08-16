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
* 在ECC开始操作之前，首先要做的就是初始化一个ref EC_stt包含特定椭圆曲线的参数·用户要使用的结构。
*  这是通过功能ref ECCinitEC，在ECC末操作可以被裁判ECCfreeEC释放
* After this initial call the user might want to initialize other objects for the functions he will call.
* For example initializing a :
* - Private key (\ref ECCprivKey_stt) with \ref ECCinitPrivKey, settings its value through 
*     \ref ECCsetPrivKeyValue and at the end of the operation, freeing it with \ref ECCfreePrivKey
*     私钥(ref ECCprivKey_stt)和ref ECCinitPrivKey，在操作结束的时候通过设置其值ECCsetPrivKeyValue，用ref ECCfreePrivKey释放它
*   
* - EC point (\ref ECpoint_stt), which is also a public key, is done by \ref ECCinitPoint, its coordinate
*     can be set and get through \ref ECCsetPointCoordinate and \ref ECCgetPointCoordinate and it will be freed
*     through \ref ECCfreePoint
*     EC点(ref ECpoint_stt)，这也是一个公钥，是通过ref ECCinitPoint，其坐标可用设置和获取通过ref ECCsetPointCoordinate和
*     ref ECCgetPointCoordinate，它会释放穿越ref ECCfreePoint
*
*  - ECDSA signature (\ref ECDSAsignature_stt) must be initialized by \ref ECDSAinitSign the two signature
*     values can be set by \ref ECDSAsetSignature and get by \ref ECDSAgetSignature. At the end it should be 
*     freed through \ref ECDSAfreeSign
*     椭圆曲线数字签名(ref ECDSAsignature_stt)必须通过ref ECDSAinitSign两个签名的
*     初始化值可以设置ref ECDSAsetSignature把ref ECDSAgetSignature。在结束它应该成为释放到ref ECDSAfreeSign
* Please note that the functions \ref ECCkeyGen and \ref ECDSAsign, require an initialized random engine structure.
* 请注意，函数引用ECCkeyGen和ref ECDSAsign，需要初始化随机引擎结构。
* Scalar multiplication is the ECC operation that it is used in ECDSA and in ECDH. It is also used to
* generate a public key.
* 标量乘法是ECC是在椭圆曲线数字签名和密钥交换中使用的操作。它还用于生成GONG钥
* A simple usage of the ECC API for scalar multiplication to generate a public key from a known private key is shown below:
* 一个简单的使用ECC的标量乘法的API生成一个公钥从已知的私钥所示：
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

   // 缓冲区保持返回公钥的X坐标
   uint8_t pubKeyX[160/8];
   // 缓冲区保持返回公钥Y坐标
   uint8_t pubKeyY[160/8];
   // 整数，它将保留重新调整大小的公钥的X坐标
   int32_t Xsize;
   // 整数，它将使重新调整Y坐标的公钥的大小
   int32_t Ysize;
   // 结构，它将使椭圆曲线参数(这些值以上)
   EC_stt ECparams;
   // 这些是椭圆曲线点的对象。 在ECC公钥只是椭圆曲线点。
   ECpoint_stt *G = NULL, *PubKey = NULL;
   // 这会让标量乘法运算中使用标量
   ECCprivKey_stt *privkey = NULL;
   int32_t retval;
   membuf_stt mb;  
   uint8_t preallocated_buffer[4096];
		 
   //设置membuf_stt预先分配的结构(在堆栈)4kB的缓冲区
   mb.mSize = sizeof(preallocated_buffer);
   mb.mUsed = 0;
   mb.pmBuf = preallocated_buffer;

   // 初始化EC_stt结构与已知值。我们还使用NULL和零未知参数进行初始化
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

   // 椭圆曲线初始化函数的调用
   retval = ECCinitEC(&ECparams, &mb);
   if (retval != 0)
   {
     printf("Error! ECCinitEC returned %d\n", retval);
     return(-1);
   }
   
	 //初始化点，它将包含生成点
   retval = ECCinitPoint(&G, &ECparams, &mb);
   if (retval != 0)
   {
     printf("Error! ECCinitPoint returned %d\n", retval);
     return(-1);
   }

   //Set the coordinates of the generator point inside G 集 团内设置生成点的坐标
   retval = ECCsetPointGenerator(G, &ECparams);
   if (retval != 0)
   {
     printf("Error! ECCsetPointGenerator returned %d\n", retval);
     return(-1);
   }

   // 初始化点保存标量乘法的结果
   retval = ECCinitPoint(&PubKey, &ECparams, &mb);
   if (retval != 0)
   {
     printf("Error! ECCinitPoint returned %d\n", retval);
     return(-1);
   }

   // Initialize the private key object专用密钥对象初始化
   retval = ECCinitPrivKey(&privkey, &ECparams, &mb);
   if (retval != 0)
   {
     printf("Error! ECCinitPrivKey returned %d\n", retval);
     return(-1);
   }
   //Set the private key object设置专用密钥对象
   retval = ECCsetPrivKeyValue(privkey, ecc_160_privkey, sizeof(ecc_160_privkey));
   if (retval != 0)
   {
     printf("Error! ECCsetPrivKeyValue returned %d\n", retval);
     return(-1);
   }

   // All ECCscalarMul parameters are initalized and set, proceed.
	 //所有ECCscalarMul参数初始化和设置，请继续。
   retval = ECCscalarMul(G, privkey, PubKey, &ECparams, &mb);
   if (retval != 0 )
   {
     printf("ECCscalarMul returned %d\n",retval);
     return(-1);
   }
   // Now PubKey contains the result point, we can get its coordinates through
	 //现在公钥包含点的结果，我们可以通过它的坐标
   ECCgetPointCoordinate(PubKey, E_ECC_POINT_COORDINATE_X, pubKeyX, &Xsize);
   ECCgetPointCoordinate(PubKey,  E_ECC_POINT_COORDINATE_X,pubKeyY, &Ysize);

   // Finally we free everything we initialized
	 //最后我们释放的我们初始化的资源
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
* 下面的示例将生成一个密钥对(包括私有和公共密钥)，并将使用私有键生成一个哈希摘要的签名。它将其导出并重新导入和验证签名与公钥
* This example will assume to have an already initialized EC_stt and RNGstate_stt.
* 本示例将假设有一个已初始化的EC_stt和RNGstate_stt
* \code*/
int32_t ECCkeygen_and_ECDSA_tests(EC_stt * pECparams, RNGstate_stt * pRNGstate)
{
  // SHA256("abc")
  uint8_t digest[CRL_SHA256_SIZE] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,
                                     0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,
                                     0xf2,0x00,0x15,0xad};  
  // Structure that will contain the public key  结构，它将包含公钥
  ECpoint_stt *PubKey = NULL;  
  // Structure that will contain the ECDSA signature 结构，它将包含椭圆曲线数字签名
  ECDSAsignature_stt *sign = NULL;
  // Structure context used to call the ECDSAverify 结构上下文用于调用ECDSAverify
  ECDSAverifyCtx_stt verctx;
  // Private Key Structure  私钥结构体
  ECCprivKey_stt *privKey = NULL;
  // Structure context used to call the ECDSAsign 结构上下文用于调用ECDSAsign
  ECDSAsignCtx_stt signCtx;
  // Used to check the returned values 用于检查返回的值
  int32_t retval;
  //pointers that will keep the byte arrays of the signature object 指针，它将把签名对象的字节数组
  uint8_t *signR = NULL, *signS = NULL;
  int32_t signRsize, signSsize;

  membuf_stt mb;  
  uint8_t preallocated_buffer[4096];

  //Set up the membuf_stt structure to a preallocated (on stack) buffer of 4kB
	//设置membuf_stt预先分配的结构(在堆栈)4kB的缓冲区
  mb.mSize = sizeof(preallocated_buffer);
  mb.mUsed = 0;
  mb.pmBuf = preallocated_buffer;

  //Init PubKey object 初始化公钥对象
  retval = ECCinitPoint(&PubKey, pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECCinitPoint returned %d\n", retval);
    goto err;
  }
  //Init Privkey object 初始化私钥对象
  retval = ECCinitPrivKey(&privKey, pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECCinitPrivKey returned %d\n", retval);
    goto err;
  }
  //Call the Key Generation Function 密钥生成函数的调用
  retval = ECCkeyGen(privKey, PubKey, pRNGstate, pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECCkeyGen returned %d\n",retval);
  }
  
  // We proceed to sign the digest of "message" 我们继续签署摘要"message"
  // First initialize the signature that will be returned 首先初始化签名，它将返回
  retval = ECDSAinitSign(&sign,pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECDSAinitSign returned %d\n",retval);
  }
  //Then fill the structure used to call to ECDSAsign function 然后填写该结构用于对ECDSAsign函数的调用
  // fill the EC_stt 填补EC_stt
  signCtx.pmEC = pECparams;
  // Fill the privkey 填补privkey
  signCtx.pmPrivKey = privKey;
  //Fill the random engine state 填充随机引擎状态
  signCtx.pmRNG = pRNGstate;

  // Call the signature generature function 签名generature函数的调用
  retval = ECDSAsign(digest, CRL_SHA256_SIZE, sign, &signCtx, &mb);
  if (retval != 0)
  {
    printf("Error! ECDSAsign returned %d\n",retval);
  }
	
  //The signature now it's inside object sign, let's export it to byte arrays
  //First, allocate the needed size, which is the size of the curve's order (N)
	//现在的内部对象签署的签名，我们将其导出到字节数组
	//首先，分配出所需的大小，这是该曲线的订单的大小(N)
  signR = malloc (pECparams->mNsize);
  signS = malloc (pECparams->mNsize);
  if (signR == NULL || signS ==NULL ) { ... ERROR... }
  
  // Now export the signature  现在导出的签名
  retval = ECDSAgetSignature(sign,E_ECDSA_SIGNATURE_R_VALUE, signR, &signRsize);
  retval |= ECDSAgetSignature(sign,E_ECDSA_SIGNATURE_S_VALUE, signS, &signSsize);
  if (retval != 0) { ... ERROR... }
  
  // Free the signature structure, reinit and reimport signature, this is just for testing...
	//免费签名结构，重新初始化和重新导入签名，这只是测试..。
  ECDSAfreeSign(&sign, &mb);

  retval = ECDSAinitSign(&sign, pECparams, &mb);
  if (retval != 0)
  {
    printf("Error! ECDSAinitSign returned %d\n",retval);
  }
  retval = ECDSAsetSignature(sign,E_ECDSA_SIGNATURE_R_VALUE, signR, signRsize);
  retval |= ECDSAsetSignature(sign,E_ECDSA_SIGNATURE_S_VALUE, signS, signSsize);
  if (retval != 0) { ... ERROR... }

  // We now have the signature of the message, we try to verify it我们现在有消息的签名，我们尝试验证它
  // First set the parameters for the verification structure第一组验证结构的参数
  verctx.pmEC = pECparams;
  verctx.pmPubKey = PubKey;
 
  // then we can call the verification function然后我们可以调用验证函数
  retval = ECDSAverify(digest, CRL_SHA256_SIZE, sign, &verctx, &mb);
  
  if (retval == SIGNATURE_VALID)
  {
    printf("Signature VALID\n");
  }
  else
  {
    printf("Error! ECDSAverify returned %d\n",retval);
  }

  // Before returing clean the memory by freeing the signature and the public key 从报表前清理内存释放签名和公钥
  ECDSAfreeSign(sign, &mb);
  ECCfreePoint(PubKey, &mb);
  ECCfreePrivKey(privKey, &mb);

  return(retval);
 }
// \endcode
*/