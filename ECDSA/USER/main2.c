#include "sys.h"
#include "led.h"
#include "delay.h"
#include "usart.h"	
#include "crypto.h"
#include "ecc_cfg.h"
#include "timer.h"

uint8_t P_key[200];
uint8_t result[128];
uint8_t result1[128];

uint8_t InputMessage_192[] =
{
   1,2,3,4,5,6,7,8,9,10,11,12
};
/******************************************************************
*	��������	 ECCSign
*	����˵��������������ݽ���ǩ��
* ���������str					Ҫǩ��������
					 len					ǩ������ĳ���
* ���������return_value ����ֵ��Ϊ0��ʾ�ɹ�������Ϊ������
*******************************************************************/	
int32_t ECCSign(void) 
{
		int32_t	return_value=0;	
		//��ز���
	  EC_Para EC;
	  Pub_Key_Para pub_key;
	  Sign_Para sign;
	  Digest_Para digest;
	  InputMsg_Para inputMsg;
	  Digest_Para digest1;
	  Priv_Key_Para priv_key;	
	
		Crypto_DeInit();	
		EC_paraTestInit(&EC, &pub_key, &sign, &inputMsg, &digest);
	  inputMsg.input_msg = InputMessage_192;
	  inputMsg.inputMsg_size = sizeof(InputMessage_192);
	 
	  digest1.digt = result1;
	  priv_key.priv = P_key;
    return_value = ECCKeyPairSignGenerate(&EC, &inputMsg, &digest1, &pub_key, &priv_key, &sign);  //����
	
		return_value = ECCKeyPairSignGenerate(&EC, &inputMsg, &digest1, &pub_key, &priv_key, &sign); //��֤

		return return_value;
}


uint8_t result_pubkey[64];

int main(void)
{

		SystemInit(); 			 //ϵͳʱ�ӳ�ʼ��Ϊ72M	  SYSCLK_FREQ_72MHz	
		delay_init(72);	

		LED_Init();

		ECCSign();


		
		while(1)
		{
				LED0 = !LED0;
				delay_ms(75);				
				LED1 = !LED1;
				delay_ms(75);				
				LED2 = !LED2;
				delay_ms(75);
		}
}

 
