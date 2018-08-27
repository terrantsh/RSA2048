/*****************************************************************************
Filename    : prime.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-8-27 10:12:46
Description : 实现了对于公钥私钥的计算
*****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "prime.h"
#include "rsa.h"

const uint8_t SMALL_PRIMES[] = {3, 5, 7, 11};
#define SMALL_PRIME_COUNT 4

static int probable_prime(bn_t *a, uint32_t digits);
static int small_factor(bn_t *a, uint32_t digits);
static int fermat_test(bn_t *a, uint32_t digits);

void initialize_rand(void)
{
    srand((unsigned)time(NULL));
}

void generate_rand(uint8_t *block, uint32_t block_len)
{
    uint32_t i;
    for(i=0; i<block_len; i++) {
        block[i] = rand();
    }
}

int generate_prime(bn_t *a, bn_t *lower, bn_t *upper, bn_t *d, uint32_t digits)
{
    uint8_t block[BN_MAX_DIGITS*BN_DIGIT_LEN];
    bn_t t[BN_MAX_DIGITS], u[BN_MAX_DIGITS];

    generate_rand(block, digits*BN_DIGIT_LEN);

    bn_decode(a, digits, block, digits*BN_DIGIT_LEN);
    bn_sub(t, upper, lower, digits);
    BN_ASSIGN_DIGIT(u, 1, digits);
    bn_add(t, t, u, digits);
    bn_mod(a, a, digits, t, digits);
    bn_add(a, a, lower, digits);

    bn_mod(t, a, digits, d, digits);
    bn_sub(a, a, t, digits);
    bn_add(a, a, u, digits);
    if(bn_cmp(a, lower, digits) < 0) {
        bn_add(a, a, d, digits);
    }
    if(bn_cmp(a, upper, digits) > 0) {
        bn_sub(a, a, d, digits);
    }

    bn_assign(t, upper, digits);
    bn_sub(t, t, d, digits);
    while(!probable_prime(a, digits)) {
        if(bn_cmp(a, t, digits) > 0) {
            return ERR_WRONG_DATA;
        }
        bn_add(a, a, d, digits);
    }

    return 0;
}

static int probable_prime(bn_t *a, uint32_t digits)
{
    return (!small_factor(a, digits) && fermat_test(a, digits));
}

static int small_factor(bn_t *a, uint32_t digits)
{
    int status;
    bn_t t[1];
    uint32_t i;

    status = 0;

    for(i=0; i<SMALL_PRIME_COUNT; i++) {
        BN_ASSIGN_DIGIT(t, SMALL_PRIMES[i], 1);
        if((digits == 1) && BN_EQUAL(a, t, 1)) {
            break;
        }

        bn_mod(t, a, digits, t, 1);
        if(bn_is_zero(t, 1)) {
            status = 1;
            break;
        }
    }

    // Clear potentially sensitive information
    i = 0;
    memset((uint8_t *)t, 0, sizeof(t));

    return status;
}

static int fermat_test(bn_t *a, uint32_t digits)
{
    int status;
    bn_t t[BN_MAX_DIGITS], u[BN_MAX_DIGITS];

    BN_ASSIGN_DIGIT(t, 2, digits);
    bn_mod_exp(u, t, a, digits, a, digits);

    status = BN_EQUAL(t, u, digits);

    // Clear potentially sensitive information
    memset((uint8_t *)u, 0, sizeof(u));
    return status;
}
