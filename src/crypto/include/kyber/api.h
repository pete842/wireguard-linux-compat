#ifndef KYBER_API_H
#define KYBER_API_H

#include "params.h"

#define PQCRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define PQCRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define PQCRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define PQCRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#define PQCRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define PQCRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define PQCRYPTO_ALGNAME "Kyber1024"
#endif

int kyber_mod_init(void);
bool crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

bool crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

bool crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#endif
