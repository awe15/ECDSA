#ifndef __LED_H
#define __LED_H	 
#include "stm32f10x.h"
//Mini STM32开发板
//LED驱动代码			 
//正点原子@ALIENTEK
//2012/2/27

//LED端口定义
#define LED0 PBout(0)// PB0
#define LED1 PCout(4)// PC4
#define LED2 PCout(3)// PC3

void LED_Init(void);//初始化

		 				    
#endif
