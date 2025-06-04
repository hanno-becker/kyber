#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../kem.h"
#include "../params.h"
#include "../indcpa.h"
#include "../polyvec.h"
#include "../poly.h"
#include "../randombytes.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 300
#define NITERATIONS 500
#define NWARMUP 50

#define BENCH(code, msg)			\
    for(i=0; i < NTESTS; i++)	{		\
	for (j=0; j < NWARMUP; j++) {		\
	    code;				\
	}					\
        t0 = cpucycles();			\
	for (j=0; j < NITERATIONS; j++) {	\
	    code;				\
	}					\
	t1 = cpucycles();			\
	t[i] = (t1 - t0) / NITERATIONS;		\
    }					        \
    print_results(msg, t, NTESTS)

uint64_t t[NTESTS];
uint8_t seed[KYBER_SYMBYTES] = {0};

int main(void)
{
  enable_cyclecounter();
  unsigned int i, j;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key[CRYPTO_BYTES];
  uint8_t coins32[KYBER_SYMBYTES];
  uint8_t coins64[2*KYBER_SYMBYTES];
  polyvec matrix[KYBER_K];
  poly ap;
  uint64_t t0, t1;

  randombytes(coins32, KYBER_SYMBYTES);
  randombytes(coins64, 2*KYBER_SYMBYTES);

  BENCH(crypto_kem_keypair_derand(pk, sk, coins64), "keypair");
  BENCH(crypto_kem_enc_derand(ct, key, pk, coins32), "enc");
  BENCH(crypto_kem_dec(key, ct, sk), "dec");

  return 0;
}
