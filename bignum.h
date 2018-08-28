/*****************************************************************************
Filename    : bigInt.h
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-8-28 10:29:55
Description : 完成各个数学符号使用函数表示的方法
*****************************************************************************/

#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <stdint.h>

typedef uint64_t dbn_t;
typedef uint32_t bn_t;
typedef uint16_t bnh_t;


#define BN_DIGIT_BITS               32  // For uint32_t
#define BN_HALF_DIGIT_BITS          16  // For uint16_t
#define BN_DIGIT_LEN                4   // uint32_t / uint8_t = 4

#define BN_MAX_DIGITS               65  // RSA_MAX_MODULUS_LEN + 1

#define BN_MAX_DIGIT                0xFFFFFFFF
#define BN_MAX_HALF_DIGIT           0xFFFF

#define LOW_HALF(x)                 ((x) & BN_MAX_HALF_DIGIT)
#define HIGH_HALF(x)                (((x) >> BN_HALF_DIGIT_BITS) & BN_MAX_HALF_DIGIT)
#define TO_HIGH_HALF(x)             (((bn_t)(x)) << BN_HALF_DIGIT_BITS)
#define DIGIT_MSB(x)                (uint32_t)(((x) >> (BN_DIGIT_BITS - 1)) & 0x01)
#define DIGIT_2MSB(x)               (uint32_t)(((x) >> (BN_DIGIT_BITS - 2)) & 0x03)


void bn_decode(bn_t *bn, uint32_t digits, uint8_t *hexarr, uint32_t size);
void bn_encode(uint8_t *hexarr, uint32_t size, bn_t *bn, uint32_t digits);

void bn_assign(bn_t *a, bn_t *b, uint32_t digits);                                       // a = b
void bn_assign_zero(bn_t *a, uint32_t digits);                                           // a = 0
void bn_assign_2exp(bn_t *a, uint32_t b, uint32_t digits);                               // a = 2^b


bn_t bn_add(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                 // a = b + c, return carry
bn_t bn_sub(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                 // a = b - c, return borrow
void bn_mul(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                 // a = b * c
void bn_div(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits);     // a = b / c, d = b % c
bn_t bn_shift_l(bn_t *a, bn_t *b, uint32_t c, uint32_t digits);                          // a = b << c (a = b * 2^c)
bn_t bn_shift_r(bn_t *a, bn_t *b, uint32_t c, uint32_t digits);                          // a = b >> c (a = b / 2^c)

void bn_mod(bn_t *a, bn_t *b, uint32_t bdigits, bn_t *c, uint32_t cdigits);              // a = b mod c
void bn_mod_mul(bn_t *a, bn_t *b, bn_t *c, bn_t *d, uint32_t digits);                    // a = b * c mod d
void bn_mod_exp(bn_t *a, bn_t *b, bn_t *c, uint32_t cdigits, bn_t *d, uint32_t ddigits); // a = b ^ c mod d
void bn_mod_inv(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                             // a = 1/b mod c
void bn_gcd(bn_t *a, bn_t *b, bn_t *c, uint32_t digits);                                 // a = gcd(b, c)

int bn_cmp(bn_t *a, bn_t *b, uint32_t digits);                                           // returns sign of a - b
int bn_is_zero(bn_t *a, uint32_t digits);                                                // returns 1 if a = 0

uint32_t bn_bits(bn_t *a, uint32_t digits);                                              // returns significant length of a in bits
uint32_t bn_digits(bn_t *a, uint32_t digits);                                            // returns significant length of a in digits

#define BN_ASSIGN_DIGIT(a, b, digits)   {bn_assign_zero(a, digits); a[0] = b;}
#define BN_EQUAL(a, b, digits)          (!bn_cmp(a, b, digits))
#define BN_EVEN(a, digits)              (((digits) == 0) || !(a[0] & 0x01))

#endif  // __BIGNUM_H__
