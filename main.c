/*****************************************************************************
Filename: main.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-8-27 10:12:46
Description :基本实现了RSA2048加密解密的各项功能，并能够进行最大2048位的加密操作
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "bignum.h"
#include "rsa.h"
#include "keys.h"

#define BUF_SIZE 2048
void print_bn(char *TAG, bn_t *bn, uint32_t bn_size)
{
    uint8_t buf[BUF_SIZE];
    int i;

    memset(buf, 0, BUF_SIZE);
    bn_encode(buf, BUF_SIZE, bn, bn_size);
    printf("%s[%d]: ", TAG, bn_size);

    i = 0;
    while(buf[i] == 0) {
        i++;
    }

    for(; i<BUF_SIZE; i++) {
        printf("%02X", buf[i]);
    }

    printf("\n");
}

void print_bn_arr(char *TAG, uint8_t *array, int len)
{
    int i = 0;

    printf("%s", TAG);
    while(array[i] == 0) {
        i++;
    }
    for(; i<len; i++) {
        printf("%02X", array[i]);
    }
    printf("\n");
}

void print_array(char *TAG, uint8_t *array, int len)
{
    int i;

    printf("%s[%d]: ", TAG, len);
    for(i=0; i<len; i++) {
        printf("%02X", array[i]);
    }
    printf("\n");
}

void print_pk(rsa_pk_t *pk)
{
    printf("PK[%d]:\n", pk->bits);
    print_bn_arr("  modulus: ", pk->modulus, RSA_MAX_MODULUS_LEN);
    print_bn_arr("  exponent: ", pk->exponent, RSA_MAX_MODULUS_LEN);
}

void print_sk(rsa_sk_t *sk)
{
    printf("SK[%d]:\n", sk->bits);
    print_bn_arr("  modulus: ", sk->modulus, RSA_MAX_MODULUS_LEN);
    print_bn_arr("  public_exponet: ", sk->public_exponet, RSA_MAX_MODULUS_LEN);
    print_bn_arr("  exponent: ", sk->exponent, RSA_MAX_MODULUS_LEN);
    print_bn_arr("  prime1: ", sk->prime1, RSA_MAX_PRIME_LEN);
    print_bn_arr("  prime2: ", sk->prime2, RSA_MAX_PRIME_LEN);
    print_bn_arr("  primeExponent1: ", sk->prime_exponent1, RSA_MAX_PRIME_LEN);
    print_bn_arr("  primeExponent2: ", sk->prime_exponent2, RSA_MAX_PRIME_LEN);
    print_bn_arr("  coefficient: ", sk->coefficient, RSA_MAX_PRIME_LEN);
}

static int test1(void)
{
    int ret;
    rsa_pk_t pk;
    rsa_sk_t sk;
    uint8_t output[256];
    uint8_t input[256] = "test";
    uint8_t msg[256];
    unsigned int outputLen, inputLen, msg_len;

    printf("hello world!\n");

    ret = rsa_generate_keys(&pk, &sk, 512);
    if(ret == 0) {
        print_pk(&pk);
        printf("\n");
        print_sk(&sk);
    } else {
        printf("rsa_generate_keys, ret: %04X\n", ret);
        return -1;
    }

    inputLen = strlen((const char *)input);
    print_array("MSG", input, inputLen);
    ret = rsa_public_encrypt(output, &outputLen, input, inputLen, &pk);
    if(ret == 0) {
        print_array("PK ENC", output, outputLen);
    } else {
        printf("rsa_public_encrypt, ret: %04X\n", ret);
        return -1;
    }

    ret = rsa_private_decrypt(msg, &msg_len, output, outputLen, &sk);
    if(ret == 0) {
        print_array("SK DEC", msg, msg_len);
        printf("DEC: %s\n", msg);
    } else {
        printf("rsa_private_decrypt, ret: %04X\n", ret);
        return -1;
    }

    ret = rsa_private_encrypt(output, &outputLen, input, inputLen, &sk);
    if(ret == 0) {
        print_array("SK ENC", output, outputLen);
    } else {
        printf("rsa_private_encrypt, ret: %04X\n", ret);
        return -1;
    }

    ret = rsa_public_decrypt(msg, &msg_len, output, outputLen, &pk);
    if(ret == 0) {
        print_array("PK DEC", msg, msg_len);
        printf("DEC: %s\n", msg);
    } else {
        printf("rsa_public_decrypt, ret: %04X\n", ret);
        return -1;
    }

    return 0;
}

static void write_sk(char *file, rsa_sk_t *sk)
{
    FILE *fp;
    fp = fopen(file, "w");
    if(fp == NULL) {
        printf("CAN NOT OPEN FILE\n");
        return;
    }
    fwrite((uint8_t *)sk, 1, sizeof(rsa_sk_t), fp);
    fclose(fp);
}

static int test2(void)
{
    int ret;
    rsa_pk_t pk = {0};
    rsa_sk_t sk = {0};

    uint8_t msg[256] = {0};
    uint32_t msg_len;

    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus[RSA_MAX_MODULUS_LEN-sizeof(key_m)], key_m, sizeof(key_m));
    memcpy(&pk.exponent[RSA_MAX_MODULUS_LEN-sizeof(key_e)], key_e, sizeof(key_e));

    sk.bits = KEY_M_BITS;
    memcpy(&sk.modulus[RSA_MAX_MODULUS_LEN-sizeof(key_m)], key_m, sizeof(key_m));
    memcpy(&sk.public_exponet[RSA_MAX_MODULUS_LEN-sizeof(key_e)], key_e, sizeof(key_e));
    memcpy(&sk.exponent[RSA_MAX_MODULUS_LEN-sizeof(key_pe)], key_pe, sizeof(key_pe));
    memcpy(&sk.prime1[RSA_MAX_PRIME_LEN-sizeof(key_p1)], key_p1, sizeof(key_p1));
    memcpy(&sk.prime2[RSA_MAX_PRIME_LEN-sizeof(key_p2)], key_p2, sizeof(key_p2));
    memcpy(&sk.prime_exponent1[RSA_MAX_PRIME_LEN-sizeof(key_e1)], key_e1, sizeof(key_e1));
    memcpy(&sk.prime_exponent2[RSA_MAX_PRIME_LEN-sizeof(key_e2)], key_e2, sizeof(key_e2));
    memcpy(&sk.coefficient[RSA_MAX_PRIME_LEN-sizeof(key_c)], key_c, sizeof(key_c));

    print_pk(&pk);
    printf("\n");
    print_sk(&sk);
    write_sk("sk.prv", &sk);
    ret = rsa_private_decrypt(msg, &msg_len, hex_array, sizeof(hex_array), &sk);
    if(ret == 0) {
        print_array("DEC", msg, msg_len);
        printf("DEC: %s\n", msg);
    } else {
        printf("rsa_private_decrypt, ret: %04X\n", ret);
        return -1;
    }

    return 0;
}

static int test3(void)
{
    rsa_sk_t sk;
    uint8_t msg[256] = {0};
    uint32_t msg_len;
    int ret;

    rsa_get_sk_from_file("sk.prv", &sk);
    ret = rsa_private_decrypt(msg, &msg_len, hex_array, sizeof(hex_array), &sk);
    if(ret == 0) {
        print_array("DEC", msg, msg_len);
        printf("DEC: %s\n", msg);
    } else {
        printf("rsa_private_decrypt, ret: %04X\n", ret);
        return -1;
    }
    return 0;
}

int main(int argc, char const *argv[])
{
    clock_t start, finish;
    double  duration;

    start = clock();
    test1();
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "%f seconds\n\n", duration );

    start = clock();
    test2();
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "%f seconds\n", duration );

    start = clock();
    test3();
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "%f seconds\n", duration );

    return 0;
}
