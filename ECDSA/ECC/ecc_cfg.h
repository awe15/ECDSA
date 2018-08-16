
#ifndef      ECC_CFG_H_
#define      ECC_CFG_H_

#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"

//ecc����
#define          ECC_TEST       

//ecc��Ҫ�õ��Ŀռ�
#define          ECC_STORE_SPACE             4096


// hash�㷨������MD5, SHA1, SHA224 or SHA256
#define          ECC_HASH                    SHA256     //����HASH�㷨ΪSHA256  
// #define         ECC_HASH                    SHA1
// #define         ECC_HASH                    SHA256
// #define         ECC_HASH                    MD5


//ǩ����ʽ
#define          ECC_SIGN_ALGORITHM          ECDSA
//#define          ECC_SIGN_ALGORITHM          ED25519


//������Բ�����Ľṹ��
//����a��p��n�Ǳ���ģ�GX��GYҲ�Ǳ���ģ�
//ָ����ֵ��Ҫ��ֵΪ��, ����Ϊ0
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


//��Կ�ṹ��
typedef struct Pub_Key_Para
{
	uint8_t *pub_x;
	uint8_t *pub_y;
	int32_t pub_xSize;
	int32_t pub_ySize;
}Pub_Key_Para;


//˽Կ�ṹ��
typedef struct Priv_Key_Para
{
	uint8_t *priv;
	int32_t priv_size;
}Priv_Key_Para;


//ǩ���ṹ��
typedef struct Sign_Para 
{
	uint8_t *sign_r;
	uint8_t *sign_s;
	int32_t sign_rSize;
	int32_t sign_sSize;
}Sign_Para;


//ժҪ�ṹ��
typedef struct  Digest_Para
{
	uint8_t *digt;
	int32_t digest_size;
}Digest_Para;


//������Ϣ�ṹ��
typedef struct  InputMsg_Para
{
	uint8_t *input_msg;
	int32_t inputMsg_size;
}InputMsg_Para;




#ifdef   ECC_TEST
//ecc���Եĳ�ʼ������
int32_t ECCSign(void);
void	EC_paraTestInit(EC_Para *ec, Pub_Key_Para *pub_key, Sign_Para *sign, 
	                    InputMsg_Para *inputMsg, Digest_Para *digest);
#endif


//ECDSAǩ����֤
int32_t ECCSignVerify(const EC_Para *ec, const Pub_Key_Para *pub_key, const Sign_Para *sign, 
                      const InputMsg_Para *inputMsg, Digest_Para *digest);


//����Key pair �Լ�ǩ��
int32_t ECCKeyPairSignGenerate(const EC_Para *ec,const InputMsg_Para *inputMsg, Digest_Para *digest, 
 		                      Pub_Key_Para *pub_key, Priv_Key_Para *priv_key, Sign_Para *signature);

void prinfInfo(Pub_Key_Para *pub_key, Sign_Para *sign, Priv_Key_Para *priv_key,Digest_Para *digest);




#endif

