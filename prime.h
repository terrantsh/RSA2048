/*****************************************************************************
Filename: main.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-8-27 10:12:46
Description :基本实现了RSA2048加密解密的各项功能，并能够进行最大2048位的加密操作
*****************************************************************************/

#ifndef __PRIME_H__
#define __PRIME_H__

#include <stdint.h>

#include "bignum.h"

void initialize_rand(void);
void generate_rand(uint8_t *block, uint32_t block_len);
int generate_prime(bn_t *a, bn_t *lower, bn_t *upper, bn_t *d, uint32_t digits);

#endif  // __PRIME_H__
