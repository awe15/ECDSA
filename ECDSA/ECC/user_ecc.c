#include "ecc_cfg.h"
#include "user_ecc.h"
#include "string.h"	
	




//extern const uint8_t InputMessage_192[8*1024];
//extern const uint8_t InputMessage_192[16*1024];
/**************************************************************************/	
//分配存储空间
static uint8_t preallocated_buffer[ECC_STORE_SPACE]; 			

#ifdef   ECC_TEST
// uint8_t P_key[200];
// uint8_t result[128];
// uint8_t result1[128];

// uint8_t InputMessage_192[] =
// {
//    1,2,3,4,5,6,7,8,9,10,11,12
// };
// /******************************************************************
// *	函数名：	 ECCSign
// *	函数说明：对输入的数据进行签名
// * 输入参数：str					要签名的数组
// 					 len					签名数组的长度
// * 输出参数：return_value 返回值，为0表示成功，其它为错误码
// *******************************************************************/	
// int32_t ECCSign(void) 
// {
// 		int32_t	return_value=0;	
// 		//相关参数
// 	  EC_Para EC;
// 	  Pub_Key_Para pub_key;
// 	  Sign_Para sign;
// 	  Digest_Para digest;
// 	  InputMsg_Para inputMsg;
// 	  Digest_Para digest1;
// 	  Priv_Key_Para priv_key;	
// 	
// 		Crypto_DeInit();	
// 		EC_paraTestInit(&EC, &pub_key, &sign, &inputMsg, &digest);
// 	  inputMsg.input_msg = InputMessage_192;
// 	  inputMsg.inputMsg_size = sizeof(InputMessage_192);
// 	 
// 	  digest1.digt = result1;
// 	  priv_key.priv = P_key;
//     return_value = ECCKeyPairSignGenerate(&EC, &inputMsg, &digest1, &pub_key, &priv_key, &sign);  //生成
// 	
// 		return_value = ECCKeyPairSignGenerate(&EC, &inputMsg, &digest1, &pub_key, &priv_key, &sign); //认证

// 		return return_value;
// }


/******************************************************************
* 函数名：EC_paraTestInit
* 函数说明：EC初始化测试
* 输入参数： ec                   椭圆参数'
*            pub_key              公钥参数         in
* 输出参数：无
*******************************************************************/	
uint8_t MessDigest_t1[CRL_HASH_SIZE];
uint8_t pub_x[50];
uint8_t pub_y[50];
uint8_t sign_r[50];
uint8_t sign_s[50];
void	EC_paraTestInit(EC_Para *ec, Pub_Key_Para *pub_key, Sign_Para *sign, 
	                    InputMsg_Para *inputMsg, Digest_Para *digest)
{
		ec->p_a = (uint8_t *)P_192_a;
    ec->p_b = (uint8_t *)P_192_b;
    ec->p_p = (uint8_t *)P_192_p;
    ec->p_n = (uint8_t *)P_192_n;
    ec->p_Gx = (uint8_t *)P_192_Gx;
    ec->p_Gy = (uint8_t *)P_192_Gy;
    ec->a_size = sizeof(P_192_a);
    ec->b_size = sizeof(P_192_b);
		ec->n_size = sizeof(P_192_n);
		ec->p_size = sizeof(P_192_p);
		ec->Gx_size = sizeof(P_192_Gx);
		ec->Gy_size = sizeof(P_192_Gy);
	
	
		pub_key->pub_x = (uint8_t *)pub_x_192;
    pub_key->pub_y = (uint8_t *)pub_y_192;		
		sign->sign_r = (uint8_t *)sign_r_192;
    sign->sign_s = (uint8_t *)sign_s_192;
    pub_key->pub_xSize = sizeof(pub_x_192);
    pub_key->pub_ySize = sizeof(pub_y_192);
		sign->sign_rSize = sizeof(sign_r_192);
    sign->sign_sSize = sizeof(sign_s_192);
		
		digest->digt = MessDigest_t1;
		digest->digest_size = 0;
}
	
void fun_print(uint8_t *str)
{
		while (*str)
		{
				printf("%x ", *str++);
		}
}

void prinfInfo(Pub_Key_Para *pub_key, Sign_Para *sign, Priv_Key_Para *priv_key,Digest_Para *digest)
{
		printf("public key:	x_size:%d		y_size:%d\r\n",pub_key->pub_xSize,pub_key->pub_ySize);
		printf("x:");
		fun_print(pub_key->pub_x);
		printf("\r\n");
		printf("y:");
		fun_print(pub_key->pub_y);		
		printf("\r\n");

	  printf("priv key:	size:%d\r\n",priv_key->priv_size);
		fun_print(priv_key->priv);	
		printf("\r\n");	
	
		printf("sign:		r_size:%d		s_size:%d\r\n",sign->sign_rSize,sign->sign_sSize);
		printf("r:");
		fun_print(sign->sign_r);	
		printf("\r\n");
		printf("s:");
		fun_print(sign->sign_s);	
		printf("\r\n");		
	
	  printf("digest:		digest_size:%d\r\n",digest->digest_size);
		fun_print(digest->digt);	
		printf("\r\n");	
}

#endif


	
/******************************************************************
* 函数名：HASH_DigestCompute
* 函数说明：初始化RNG引擎
* 输入参数：InputMessage         指向需要进行HASH计算的的输入消息指针
*          InputMessageLength   输入消息长度
*          MessageDigest        指向输出参数，它将处理消息摘要
*          MessageDigestLength  输出摘要长度
* 输出参数：错误码
*******************************************************************/		
static int32_t RNG_init_for_sign(RNGstate_stt *P_pRNGstat)
{
		RNGinitInput_stt RNGinit_st;

	  int32_t error_sta = RNG_ERR_UNINIT_STATE;
	
		uint8_t entropy_data[32] =
    {
      0x9d, 0x20, 0x1a, 0x18, 0x9b, 0x6d, 0x1a, 0xa7, 0x0e, 0x79, 0x57, 0x6f, 0x36,
      0xb6, 0xaa, 0x88, 0x55, 0xfd, 0x4a, 0x7f, 0x97, 0xe9, 0x71, 0x69, 0xb6, 0x60,
      0x88, 0x78, 0xe1, 0x9c, 0x8b, 0xa5
    };
		
		/* 随机数 */
		uint8_t nonce[4] = {0, 1, 2, 3};
			
		//Random number generation (RNG) 初始化随机数引擎
		RNGinit_st.pmEntropyData = entropy_data;
		RNGinit_st.mEntropyDataSize = sizeof(entropy_data);
		RNGinit_st.pmNonce = nonce;
		RNGinit_st.mNonceSize = sizeof(nonce);	
		RNGinit_st.mPersDataSize = 0;
		RNGinit_st.pmPersData = NULL;
			
		error_sta = RNGinit((const RNGinitInput_stt *)&RNGinit_st, C_DRBG_AES128, P_pRNGstat);
		if (error_sta != RNG_SUCCESS)
		{
			return error_sta;
		} 
		
		return error_sta;
}	
	
	
	
	
	
/******************************************************************
* 函数名：HASH_DigestCompute
* 函数说明：ecc的哈希计算
* 输入参数：InputMessage         指向需要进行HASH计算的的输入消息指针
*          InputMessageLength   输入消息长度
*          MessageDigest        指向输出参数，它将处理消息摘要
*          MessageDigestLength  输出摘要长度
* 输出参数：错误码
*******************************************************************/			
static int32_t HASH_DigestCompute(const uint8_t* InputMessage, uint32_t InputMessageLength,
                           uint8_t *MessageDigest, int32_t* MessageDigestLength)
{
		HASHctx_stt           HASHctx;        
		int32_t error_sta  =  HASH_SUCCESS;

		HASHctx.mFlags = E_HASH_DEFAULT;
		HASHctx.mTagSize = CRL_HASH_SIZE;   //设置摘要大小 1~CRL_HASH_SIZE的范围内
	
		//HASH初始化   
		error_sta = HASH_INIT(&HASHctx);
		if (error_sta != HASH_SUCCESS)
		{
			return error_sta;
		}
		
		//处理输入数据并将更新的哈希算法结构体
		error_sta = HASH_APPEND(&HASHctx, InputMessage, InputMessageLength);
		if (error_sta != HASH_SUCCESS)
		{
			return error_sta;
		}
		
		//Hash算法完成函数,产生HASH算法输出
		error_sta = HASH_FINISH(&HASHctx, MessageDigest, MessageDigestLength);
		if (error_sta != HASH_SUCCESS)
		{	
			return error_sta;
		}

		return error_sta;
}	 
	


/******************************************************************
* 函数名：ECCSignVerify
* 函数说明：ECDSA签名认证
* 输入参数： ecc                  椭圆参数          in
*           pub_key              公钥参数          in
*           sign                 签名参数          in
*           inputMsg             输入数据          in
*           digest               摘要参数          out
* 输出参数：错误码     
*          如果都正确返回  AUTHENTICATION_SUCCESSFUL  1003
*---------------------------------------------------------
* 调试说明：ECDSA已通过P-192认证
*******************************************************************/
int32_t ECCSignVerify(const EC_Para *ec, const Pub_Key_Para *pub_key, const Sign_Para *sign, 
                      const InputMsg_Para *inputMsg, Digest_Para *digest)
{
		int32_t error_sta  = ECC_SUCCESS;
	
		const	uint8_t * InputMessage;
		uint32_t InputLength = NULL;

		EC_stt                ECctx;
		membuf_stt            ECDSAMem_ctx;
	
		ECpoint_stt *PubKey = NULL; 

		ECDSAsignature_stt *  ECDSAsignature_ctx = NULL;
		
		ECDSAverifyCtx_stt verctx;

	  const uint8_t * pub_x;
		const uint8_t * pub_y;
	  const uint8_t * sign_r;
		const uint8_t * sign_s;
		int32_t pub_x_size = 0x00;
		int32_t pub_y_size = 0x00;
		int32_t signRsize = 0x00;
		int32_t signSsize = 0x00;
		
		ECctx.pmA = ec->p_a;
    ECctx.pmB = ec->p_b;
    ECctx.pmP = ec->p_p;
    ECctx.pmN =  ec->p_n;
    ECctx.pmGx = ec->p_Gx;
    ECctx.pmGy =  ec->p_Gy;
    ECctx.mAsize = ec->a_size;
    ECctx.mBsize = ec->b_size;
		ECctx.mNsize = ec->n_size;
		ECctx.mPsize = ec->p_size;
		ECctx.mGxsize = ec->Gx_size;
		ECctx.mGysize = ec->Gy_size;
		
		pub_x = pub_key->pub_x;
    pub_y = pub_key->pub_y;		
		sign_r = sign->sign_r;
    sign_s = sign->sign_s;
    pub_x_size = pub_key->pub_xSize;
    pub_y_size = pub_key->pub_ySize;
		signRsize = sign->sign_rSize;
    signSsize = sign->sign_sSize;
		InputMessage =  inputMsg->input_msg;
		InputLength = inputMsg->inputMsg_size;

	  //HASH初始化  
		error_sta = HASH_DigestCompute(InputMessage, InputLength, 
			        digest->digt, &digest->digest_size);                    
		if (error_sta != HASH_SUCCESS)   
			return  error_sta;
	
		ECDSAMem_ctx.mSize = sizeof(preallocated_buffer);
    ECDSAMem_ctx.mUsed = 0;
    ECDSAMem_ctx.pmBuf = preallocated_buffer;
		
		//ecc初始化                                        
		error_sta = ECCinitEC(&ECctx, &ECDSAMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			return error_sta;
		}
		
		//初始化ECC点
 		error_sta =ECCinitPoint(&PubKey, &ECctx, &ECDSAMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCVerify_L1;
		}
		
		//设置值的ECC点的坐标之一  初始化点，导入公钥
		ECCsetPointCoordinate(PubKey, E_ECC_POINT_COORDINATE_X, pub_x, pub_x_size);
    ECCsetPointCoordinate(PubKey, E_ECC_POINT_COORDINATE_Y, pub_y, pub_y_size);
	
		//验证
		error_sta = ECCvalidatePubKey(PubKey, &ECctx, &ECDSAMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCVerify_L2;
		}
 		
		//初始化签名结构体
		error_sta = ECDSAinitSign(&ECDSAsignature_ctx, &ECctx, &ECDSAMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCVerify_L2;
		}
		
		//导入签名    
		error_sta = ECDSAsetSignature(ECDSAsignature_ctx, E_ECDSA_SIGNATURE_R_VALUE, sign_r, signRsize);
		error_sta |= ECDSAsetSignature(ECDSAsignature_ctx, E_ECDSA_SIGNATURE_S_VALUE, sign_s, signSsize);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCVerify_L3;
		}
		
		 /*编写结构对椭圆曲线数字签名验证*/
		verctx.pmEC = &ECctx;
		verctx.pmPubKey = PubKey;
		error_sta = ECDSAverify(digest->digt, digest->digest_size, ECDSAsignature_ctx, &verctx, &ECDSAMem_ctx);
		
ECCVerify_L3:		
		ECDSAfreeSign(&ECDSAsignature_ctx, &ECDSAMem_ctx);
		
ECCVerify_L2:
		ECCfreePoint(&PubKey, &ECDSAMem_ctx);

ECCVerify_L1:		
		ECCfreeEC(&ECctx, &ECDSAMem_ctx);
				
		return error_sta;
}
 



 
 
/******************************************************************
* 函数名：ECCKeyPairSignGenerate
* 函数说明：ecdsa的生成Key pair 以及签名
* 输入参数： ecc                  椭圆参数     in
*           inputMsg             输入数据     in
*           digest               摘要参数     out
*           pub_key              公钥参数     out
*						priv_key             私钥参数     out
*           sign                 签名参数     out 
* 输出参数：错误码 
*          没有错误就为成功
*---------------------------------------------------------
* 调试说明：ECDSA已通过P-192认证
*******************************************************************/
int32_t ECCKeyPairSignGenerate(const EC_Para *ec,const InputMsg_Para *inputMsg, Digest_Para *digest, 
 		                      Pub_Key_Para *pub_key, Priv_Key_Para *priv_key, Sign_Para *signature)
{
		int32_t error_sta  = ECC_SUCCESS;
		RNGstate_stt         RNGstate;
	
		const	uint8_t * InputMessage;
		uint32_t InputLength = NULL;
	
		EC_stt                ECctx;
		membuf_stt            ECCMem_ctx;       

		ECpoint_stt *PubKey = NULL;
	
		ECCprivKey_stt *PrivKey = NULL;
	
		ECDSAsignature_stt *sign = NULL;
		ECDSAsignCtx_stt signCtx;
	

		//HASH初始化 
		InputMessage =  inputMsg->input_msg;
		InputLength = inputMsg->inputMsg_size;	
		error_sta = HASH_DigestCompute(InputMessage, InputLength, 
			        digest->digt, &digest->digest_size);                    
		if (error_sta != HASH_SUCCESS)   
			return  error_sta;
	
		//初始随机数引擎
		error_sta = RNG_init_for_sign(&RNGstate);
		if (error_sta != ECC_SUCCESS)
    {
			return RNG_SUCCESS;
		}
		
	  ECCMem_ctx.pmBuf =  preallocated_buffer;
		ECCMem_ctx.mUsed = 0;
		ECCMem_ctx.mSize = sizeof(preallocated_buffer);	
		
			
		ECctx.pmA = ec->p_a;
    ECctx.pmB = ec->p_b;
    ECctx.pmP = ec->p_p;
    ECctx.pmN =  ec->p_n;
    ECctx.pmGx = ec->p_Gx;
    ECctx.pmGy =  ec->p_Gy;
    ECctx.mAsize = ec->a_size;
    ECctx.mBsize = ec->b_size;
		ECctx.mNsize = ec->n_size;
		ECctx.mPsize = ec->p_size;
		ECctx.mGxsize = ec->Gx_size;
		ECctx.mGysize = ec->Gy_size;
		error_sta = ECCinitEC(&ECctx, &ECCMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCKeyGen_L1;
		}
		
 		//初始化公钥
 		error_sta = ECCinitPoint(&PubKey, &ECctx, &ECCMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCKeyGen_L2;
		}		
		
 		//初始化私钥
 		error_sta = ECCinitPrivKey(&PrivKey, &ECctx, &ECCMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCKeyGen_L3;
		}		

		//生成ECC密钥对
		error_sta = ECCkeyGen(PrivKey, PubKey, &RNGstate, &ECctx, &ECCMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCKeyGen_L4;
		}						
		
		 /* 初始化ECDSA 签名结构体*/
     error_sta = ECDSAinitSign(&sign, &ECctx, &ECCMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCKeyGen_L4;
		}		
		
		 /* 生成签名 */
		signCtx.pmEC = &ECctx;
		signCtx.pmPrivKey = PrivKey;
		signCtx.pmRNG = &RNGstate;
		error_sta = ECDSAsign(digest->digt, digest->digest_size, sign, &signCtx, &ECCMem_ctx);
		if (error_sta != ECC_SUCCESS)
		{ 
			goto ECCKeyGen_L5;
		}
		
		/* 认证 这个可以不要 
		verctx.pmEC = &ECctx;
		verctx.pmPubKey = PubKey;
		error_sta = ECDSAverify(digest->digt, digest->digest_size, sign, &verctx, &ECCMem_ctx);
		if (error_sta != AUTHENTICATION_SUCCESSFUL)
		{ 
			goto ECCKeyGen_L5;
		}*/
		
		/* 导出信息 */	
		error_sta = ECCgetPointCoordinate(PubKey, E_ECC_POINT_COORDINATE_X, pub_key->pub_x, &pub_key->pub_xSize);
		error_sta |= ECCgetPointCoordinate(PubKey, E_ECC_POINT_COORDINATE_Y, pub_key->pub_y, &pub_key->pub_ySize);
		
		error_sta = ECCgetPrivKeyValue(PrivKey, priv_key->priv, &priv_key->priv_size);
	
		
		error_sta = ECDSAgetSignature(sign, E_ECDSA_SIGNATURE_R_VALUE, signature->sign_r, &signature->sign_rSize);
		error_sta |= ECDSAgetSignature(sign, E_ECDSA_SIGNATURE_S_VALUE, signature->sign_s, &signature->sign_sSize);
		
		
ECCKeyGen_L5:		
		ECDSAfreeSign(&sign, &ECCMem_ctx);
		
ECCKeyGen_L4:
		ECCfreePrivKey(&PrivKey, &ECCMem_ctx);

ECCKeyGen_L3:
 		ECCfreePoint(&PubKey, &ECCMem_ctx);
		
ECCKeyGen_L2:
 		 ECCfreeEC(&ECctx, &ECCMem_ctx);
 		
ECCKeyGen_L1:		
 		 RNGfree(&RNGstate);
		
		return error_sta;
}
