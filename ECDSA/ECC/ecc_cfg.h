
#ifndef      ECC_CFG_H_
#define      ECC_CFG_H_

#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"

//ecc测试
#define          ECC_TEST       

//ecc需要用到的空间
#define          ECC_STORE_SPACE             4096


// hash算法里面有MD5, SHA1, SHA224 or SHA256
#define          ECC_HASH                    SHA256     //定义HASH算法为SHA256  
// #define         ECC_HASH                    SHA1
// #define         ECC_HASH                    SHA256
// #define         ECC_HASH                    MD5


//签名方式
#define          ECC_SIGN_ALGORITHM          ECDSA
//#define          ECC_SIGN_ALGORITHM          ED25519


//定义椭圆参数的结构体
//参数a，p，n是必须的，GX，GY也是必须的，
//指针无值需要赋值为空, 长度为0
typedef struct EC_Para
{
	uint8_t *p_a;
	uint8_t *p_p;
	uint8_t *p_b;
	uint8_t *p_n;
	uint8_t *p_Gx;
	uint8_t *p_Gy;
	int32_t a_size;
	int32_t b_size;	
	int32_t p_size;
	int32_t n_size;
	int32_t Gx_size;
	int32_t Gy_size;
}EC_Para;


//公钥结构体
typedef struct Pub_Key_Para
{
	uint8_t *pub_x;
	uint8_t *pub_y;
	int32_t pub_xSize;
	int32_t pub_ySize;
}Pub_Key_Para;


//私钥结构体
typedef struct Priv_Key_Para
{
	uint8_t *priv;
	int32_t priv_size;
}Priv_Key_Para;


//签名结构体
typedef struct Sign_Para 
{
	uint8_t *sign_r;
	uint8_t *sign_s;
	int32_t sign_rSize;
	int32_t sign_sSize;
}Sign_Para;


//摘要结构体
typedef struct  Digest_Para
{
	uint8_t *digt;
	int32_t digest_size;
}Digest_Para;


//输入信息结构体
typedef struct  InputMsg_Para
{
	uint8_t *input_msg;
	int32_t inputMsg_size;
}InputMsg_Para;




#ifdef   ECC_TEST
//ecc测试的初始化程序
int32_t ECCSign(void);
void	EC_paraTestInit(EC_Para *ec, Pub_Key_Para *pub_key, Sign_Para *sign, 
	                    InputMsg_Para *inputMsg, Digest_Para *digest);
#endif


//ECDSA签名认证
int32_t ECCSignVerify(const EC_Para *ec, const Pub_Key_Para *pub_key, const Sign_Para *sign, 
                      const InputMsg_Para *inputMsg, Digest_Para *digest);


//生成Key pair 以及签名
int32_t ECCKeyPairSignGenerate(const EC_Para *ec,const InputMsg_Para *inputMsg, Digest_Para *digest, 
 		                      Pub_Key_Para *pub_key, Priv_Key_Para *priv_key, Sign_Para *signature);

void prinfInfo(Pub_Key_Para *pub_key, Sign_Para *sign, Priv_Key_Para *priv_key,Digest_Para *digest);




#endif

