#ifndef __LED_H
#define __LED_H	 
#include "stm32f10x.h"
//Mini STM32������
//LED��������			 
//����ԭ��@ALIENTEK
//2012/2/27

//LED�˿ڶ���
#define LED0 PBout(0)// PB0
#define LED1 PCout(4)// PC4
#define LED2 PCout(3)// PC3

void LED_Init(void);//��ʼ��

		 				    
#endif
