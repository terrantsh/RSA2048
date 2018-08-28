/*****************************************************************************
Filename    : rsa.h
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-8-28 10:29:49
Description : 加密解密函数的实现
*****************************************************************************/

#include <string.h>
#include <stdio.h>

#include "rsa.h"
#include "bignum.h"

static int rsa_filter(bn_t *a, uint32_t adigits, bn_t *b, uint32_t bdigits);
static int relatively_prime(bn_t *a, uint32_t adigits, bn_t *b, uint32_t bdigits);
static int public_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
static int private_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);


// RSA从文件中得到秘钥
int rsa_get_sk_from_file(char *file, rsa_sk_t *sk)
{
    FILE *fp;
    fp = fopen(file, "r");
    if(fp == NULL) {
        return -1;
    }

    fread((uint8_t *)sk, 1, sizeof(rsa_sk_t), fp);
    fclose(fp);
    return 0;
}


// RSA生成秘钥
int rsa_generate_keys(rsa_pk_t *pk, rsa_sk_t *sk, uint32_t key_bits)
{
    int status;
    uint32_t ndigits, pbits, pdigits, qbits;
    bn_t n          [BN_MAX_DIGITS], d          [BN_MAX_DIGITS], e      [BN_MAX_DIGITS], p      [BN_MAX_DIGITS], q[BN_MAX_DIGITS];
    bn_t dp         [BN_MAX_DIGITS], dq         [BN_MAX_DIGITS], phi_n  [BN_MAX_DIGITS], q_inv  [BN_MAX_DIGITS];
    bn_t p_minus1   [BN_MAX_DIGITS], q_minus1   [BN_MAX_DIGITS];
    bn_t t          [BN_MAX_DIGITS], u          [BN_MAX_DIGITS], v      [BN_MAX_DIGITS];

    if((key_bits < RSA_MIN_MODULUS_BITS) || (key_bits > RSA_MAX_MODULUS_BITS))
        return ERR_WRONG_LEN;

    ndigits = (key_bits + BN_DIGIT_BITS - 1) / BN_DIGIT_BITS;
    pdigits = (ndigits  + 1) / 2;
    pbits   = (key_bits + 1) / 2;
    qbits   =  key_bits - pbits;

    initialize_rand();

    BN_ASSIGN_DIGIT(e, (bn_t)65537, ndigits);
    bn_assign_2exp(t, pbits-1, pdigits);
    bn_assign_2exp(u, pbits-2, pdigits);
    bn_add(t, t, u, pdigits);
    BN_ASSIGN_DIGIT(v, 1, pdigits);
    bn_sub(v, t, v, pdigits);
    bn_add(u, u, v, pdigits);
    BN_ASSIGN_DIGIT(v, 2, pdigits);

    do {
        status = generate_prime(p, t, u, v, pdigits);
        if(status != 0) {
            return status;
        }
    } while(!rsa_filter(p, pdigits, e, 1));

    bn_assign_2exp(t, qbits-1, pdigits);
    bn_assign_2exp(u, qbits-2, pdigits);
    bn_add(t, t, u, pdigits);
    BN_ASSIGN_DIGIT(v, 1, pdigits);
    bn_sub(v, t, v, pdigits);
    bn_add(u, u, v, pdigits);
    BN_ASSIGN_DIGIT(v, 2, pdigits);

    do {
        status = generate_prime(q, t, u, v, pdigits);
        if(status != 0) {
            return status;
        }
    } while(!rsa_filter(q, pdigits, e, 1));

    if(bn_cmp(p, q, pdigits) < 0) {
        bn_assign(t, p, pdigits);
        bn_assign(p, q, pdigits);
        bn_assign(q, t, pdigits);
    }

    bn_mul(n, p, q, pdigits);
    bn_mod_inv(q_inv, q, p, pdigits);

    BN_ASSIGN_DIGIT(t, 1, pdigits);
    bn_sub(p_minus1, p, t, pdigits);
    bn_sub(q_minus1, q, t, pdigits);
    bn_mul(phi_n, p_minus1, q_minus1, pdigits);

    bn_mod_inv(d, e, phi_n, ndigits);
    bn_mod(dp, d, ndigits, p_minus1, pdigits);
    bn_mod(dq, d, ndigits, q_minus1, pdigits);

    pk->bits = sk->bits = key_bits;
    bn_encode(pk->modulus,  RSA_MAX_MODULUS_LEN, n, ndigits);
    bn_encode(pk->exponent, RSA_MAX_MODULUS_LEN, e, 1);

    memcpy((uint8_t *)sk->modulus, (uint8_t *)pk->modulus, RSA_MAX_MODULUS_LEN);
    memcpy((uint8_t *)sk->public_exponet, (uint8_t *)pk->exponent, RSA_MAX_MODULUS_LEN);
    bn_encode(sk->exponent,        RSA_MAX_MODULUS_LEN, d, ndigits);
    bn_encode(sk->prime1,          RSA_MAX_PRIME_LEN, p, pdigits);
    bn_encode(sk->prime2,          RSA_MAX_PRIME_LEN, q, pdigits);
    bn_encode(sk->prime_exponent1, RSA_MAX_PRIME_LEN, dp, pdigits);
    bn_encode(sk->prime_exponent2, RSA_MAX_PRIME_LEN, dq, pdigits);
    bn_encode(sk->coefficient,     RSA_MAX_PRIME_LEN, q_inv, pdigits);

    // Clear potentially sensitive information
    memset((uint8_t *)d,        0, sizeof(d));
    memset((uint8_t *)dp,       0, sizeof(dp));
    memset((uint8_t *)dq,       0, sizeof(dq));
    memset((uint8_t *)p,        0, sizeof(p));
    memset((uint8_t *)q,        0, sizeof(q));
    memset((uint8_t *)phi_n,    0, sizeof(phi_n));
    memset((uint8_t *)q_inv,    0, sizeof(q_inv));
    memset((uint8_t *)p_minus1, 0, sizeof(p_minus1));
    memset((uint8_t *)q_minus1, 0, sizeof(q_minus1));
    memset((uint8_t *)t,        0, sizeof(t));

    return 0;
}

// RSA公钥加密函数
int rsa_public_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    int status;
    uint8_t byte, pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len;

    modulus_len = (pk->bits + 7) / 8;
    if(in_len + 11 > modulus_len) {
        return ERR_WRONG_LEN;
    }

    pkcs_block[0] = 0;
    pkcs_block[1] = 2;
    for(i=2; i<modulus_len-in_len-1; i++) {
        do {
            generate_rand(&byte, 1);
        } while(byte == 0);
        pkcs_block[i] = byte;
    }

    pkcs_block[i++] = 0;

    memcpy((uint8_t *)&pkcs_block[i], (uint8_t *)in, in_len);
    status = public_block_operation(out, out_len, pkcs_block, modulus_len, pk);

    // Clear potentially sensitive information
    byte = 0;
    memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}


// RSA公钥解密函数
int rsa_public_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len, pkcs_block_len;

    modulus_len = (pk->bits + 7) / 8;
    if(in_len > modulus_len)
        return ERR_WRONG_LEN;

    status = public_block_operation(pkcs_block, &pkcs_block_len, in, in_len, pk);
    if(status != 0)
        return status;

    if(pkcs_block_len != modulus_len)
        return ERR_WRONG_LEN;

    if((pkcs_block[0] != 0) || (pkcs_block[1] != 1))
        return ERR_WRONG_DATA;

    for(i=2; i<modulus_len-1; i++) {
        if(pkcs_block[i] != 0xFF)   break;
    }

    if(pkcs_block[i++] != 0)
        return ERR_WRONG_DATA;

    *out_len = modulus_len - i;
    if(*out_len + 11 > modulus_len)
        return ERR_WRONG_DATA;

    memcpy((uint8_t *)out, (uint8_t *)&pkcs_block[i], *out_len);

    // Clear potentially sensitive information
    memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}


// RSA 私钥加密函数
int rsa_private_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len;

    modulus_len = (sk->bits + 7) / 8;
    if(in_len + 11 > modulus_len)
        return ERR_WRONG_LEN;

    pkcs_block[0] = 0;
    pkcs_block[1] = 1;
    for(i=2; i<modulus_len-in_len-1; i++) {
        pkcs_block[i] = 0xFF;
    }

    pkcs_block[i++] = 0;

    memcpy((uint8_t *)&pkcs_block[i], (uint8_t *)in, in_len);

    status = private_block_operation(out, out_len, pkcs_block, modulus_len, sk);

    // Clear potentially sensitive information
    memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}


// RSA私钥解密函数
int rsa_private_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len, pkcs_block_len;

    modulus_len = (sk->bits + 7) / 8;
    if(in_len > modulus_len)
        return ERR_WRONG_LEN;

    status = private_block_operation(pkcs_block, &pkcs_block_len, in, in_len, sk);
    if(status != 0)
        return status;

    if(pkcs_block_len != modulus_len)
        return ERR_WRONG_LEN;

    if((pkcs_block[0] != 0) || (pkcs_block[1] != 2))
        return ERR_WRONG_DATA;

    for(i=2; i<modulus_len-1; i++) {
        if(pkcs_block[i] == 0)  break;
    }

    i++;
    if(i >= modulus_len)
        return ERR_WRONG_DATA;

    *out_len = modulus_len - i;
    if(*out_len + 11 > modulus_len)
        return ERR_WRONG_DATA;

    memcpy((uint8_t *)out, (uint8_t *)&pkcs_block[i], *out_len);

    // Clear potentially sensitive information
    memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}



static int public_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    uint32_t edigits, ndigits;
    bn_t c[BN_MAX_DIGITS], e[BN_MAX_DIGITS], m[BN_MAX_DIGITS], n[BN_MAX_DIGITS];

    bn_decode(m, BN_MAX_DIGITS, in, in_len);
    bn_decode(n, BN_MAX_DIGITS, pk->modulus, RSA_MAX_MODULUS_LEN);
    bn_decode(e, BN_MAX_DIGITS, pk->exponent, RSA_MAX_MODULUS_LEN);

    ndigits = bn_digits(n, BN_MAX_DIGITS);
    edigits = bn_digits(e, BN_MAX_DIGITS);

    if(bn_cmp(m, n, ndigits) >= 0) {
        return ERR_WRONG_DATA;
    }

    bn_mod_exp(c, m, e, edigits, n, ndigits);

    *out_len = (pk->bits + 7) / 8;
    bn_encode(out, *out_len, c, ndigits);

    // Clear potentially sensitive information
    memset((uint8_t *)c, 0, sizeof(c));
    memset((uint8_t *)m, 0, sizeof(m));

    return 0;
}


// 私有块处理
static int private_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk)
{
    uint32_t cdigits, ndigits, pdigits;
    bn_t c [BN_MAX_DIGITS], cp[BN_MAX_DIGITS], cq[BN_MAX_DIGITS];
    bn_t dp[BN_MAX_DIGITS], dq[BN_MAX_DIGITS], mp[BN_MAX_DIGITS], mq   [BN_MAX_DIGITS];
    bn_t n [BN_MAX_DIGITS], p [BN_MAX_DIGITS], q [BN_MAX_DIGITS], q_inv[BN_MAX_DIGITS], t[BN_MAX_DIGITS];

    bn_decode(c,     BN_MAX_DIGITS, in, in_len);
    bn_decode(n,     BN_MAX_DIGITS, sk->modulus, RSA_MAX_MODULUS_LEN);
    bn_decode(p,     BN_MAX_DIGITS, sk->prime1, RSA_MAX_PRIME_LEN);
    bn_decode(q,     BN_MAX_DIGITS, sk->prime2, RSA_MAX_PRIME_LEN);
    bn_decode(dp,    BN_MAX_DIGITS, sk->prime_exponent1, RSA_MAX_PRIME_LEN);
    bn_decode(dq,    BN_MAX_DIGITS, sk->prime_exponent2, RSA_MAX_PRIME_LEN);
    bn_decode(q_inv, BN_MAX_DIGITS, sk->coefficient, RSA_MAX_PRIME_LEN);

    cdigits = bn_digits(c, BN_MAX_DIGITS);
    ndigits = bn_digits(n, BN_MAX_DIGITS);
    pdigits = bn_digits(p, BN_MAX_DIGITS);

    if(bn_cmp(c, n, ndigits) >= 0)
        return ERR_WRONG_DATA;

    bn_mod(cp, c, cdigits, p, pdigits);
    bn_mod(cq, c, cdigits, q, pdigits);
    bn_mod_exp(mp, cp, dp, pdigits, p, pdigits);
    bn_assign_zero(mq, ndigits);
    bn_mod_exp(mq, cq, dq, pdigits, q, pdigits);

    if(bn_cmp(mp, mq, pdigits) >= 0) {
        bn_sub(t, mp, mq, pdigits);
    } else {
        bn_sub(t, mq, mp, pdigits);
        bn_sub(t, p, t, pdigits);
    }

    bn_mod_mul(t, t, q_inv, p, pdigits);
    bn_mul(t, t, q, pdigits);
    bn_add(t, t, mq, ndigits);

    *out_len = (sk->bits + 7) / 8;
    bn_encode(out, *out_len, t, ndigits);

    // Clear potentially sensitive information
    memset((uint8_t *)c,  0, sizeof(c));
    memset((uint8_t *)cp, 0, sizeof(cp));
    memset((uint8_t *)cq, 0, sizeof(cq));
    memset((uint8_t *)dp, 0, sizeof(dp));
    memset((uint8_t *)dq, 0, sizeof(dq));
    memset((uint8_t *)mp, 0, sizeof(mp));
    memset((uint8_t *)mq, 0, sizeof(mq));
    memset((uint8_t *)p,  0, sizeof(p));
    memset((uint8_t *)q,  0, sizeof(q));
    memset((uint8_t *)q_inv, 0, sizeof(q_inv));
    memset((uint8_t *)t,  0, sizeof(t));

    return 0;
}


// RSA过滤器？？
static int rsa_filter(bn_t *a, uint32_t adigits, bn_t *b, uint32_t bdigits)
{
    int status;
    bn_t a_minus1[BN_MAX_DIGITS], t[BN_MAX_DIGITS];

    BN_ASSIGN_DIGIT(t, 1, adigits);
    bn_sub(a_minus1, a, t, adigits);

    status = relatively_prime(a_minus1, adigits, b, bdigits);

    // Clear potentially sensitive information
    memset((uint8_t *)a_minus1, 0, sizeof(a_minus1));

    return status;
}


// 互质数？？
static int relatively_prime(bn_t *a, uint32_t adigits, bn_t *b, uint32_t bdigits)
{
    int status;
    bn_t t[BN_MAX_DIGITS], u[BN_MAX_DIGITS];

    bn_assign_zero(t, adigits);
    bn_assign(t, b, bdigits);
    bn_gcd(t, a, t, adigits);
    BN_ASSIGN_DIGIT(u, 1, adigits);

    status = BN_EQUAL(t, u, adigits);

    // Clear potentially sensitive information
    memset((uint8_t *)t, 0, sizeof(t));

    return status;
}
