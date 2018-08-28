/*****************************************************************************
Filename    : rsa.h
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-8-28 10:29:29
Description : 加密解密函数的实现
*****************************************************************************/

#ifndef __RSA_H__
#define __RSA_H__

#include <stdint.h>

// RSA key lengths
#define RSA_MIN_MODULUS_BITS                508
#define RSA_MAX_MODULUS_BITS                2048
#define RSA_MAX_MODULUS_LEN                 ((RSA_MAX_MODULUS_BITS + 7) / 8)
#define RSA_MAX_PRIME_BITS                  ((RSA_MAX_MODULUS_BITS + 1) / 2)
#define RSA_MAX_PRIME_LEN                   ((RSA_MAX_PRIME_BITS + 7) / 8)

// Error codes
#define ERR_WRONG_DATA                      0x1001
#define ERR_WRONG_LEN                       0x1002


typedef struct {
    uint32_t bits;
    uint8_t  modulus            [RSA_MAX_MODULUS_LEN];
    uint8_t  exponent           [RSA_MAX_MODULUS_LEN];
} rsa_pk_t;

typedef struct {
    uint32_t bits;
    uint8_t  modulus            [RSA_MAX_MODULUS_LEN];
    uint8_t  public_exponet     [RSA_MAX_MODULUS_LEN];
    uint8_t  exponent           [RSA_MAX_MODULUS_LEN];
    uint8_t  prime1             [RSA_MAX_PRIME_LEN];
    uint8_t  prime2             [RSA_MAX_PRIME_LEN];
    uint8_t  prime_exponent1    [RSA_MAX_PRIME_LEN];
    uint8_t  prime_exponent2    [RSA_MAX_PRIME_LEN];
    uint8_t  coefficient        [RSA_MAX_PRIME_LEN];
} rsa_sk_t;

int rsa_get_sk_from_file(char *file, rsa_sk_t *sk);
int rsa_generate_keys(rsa_pk_t *pk, rsa_sk_t *sk, uint32_t key_bits);
int rsa_public_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
int rsa_public_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
int rsa_private_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);
int rsa_private_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);

#endif  // __RSA_H__
