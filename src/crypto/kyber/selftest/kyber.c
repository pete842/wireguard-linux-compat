#include <kyber/api.h>

#define NTESTS 10

static int test_keys(void) {
    unsigned int i;
    unsigned char *pk, *sk;
    unsigned char ct[PQCRYPTO_CIPHERTEXTBYTES];
    unsigned char key_a[PQCRYPTO_BYTES];
    unsigned char key_b[PQCRYPTO_BYTES];

    pk = kmalloc(PQCRYPTO_PUBLICKEYBYTES * sizeof(char), GFP_KERNEL);
    if (!pk)
        return false;
    sk = kmalloc(PQCRYPTO_SECRETKEYBYTES * sizeof(char), GFP_KERNEL);
    if (!sk) {
        kfree(pk);
        return false;
    }

    for (i = 0; i < NTESTS; i++) {
        //Alice generates a public key
        if (!crypto_kem_keypair(pk, sk)) {
            pr_err("ERROR failed to generate keypair\n");
            return false;
        }

        //Bob derives a secret key and creates a response
        if (!crypto_kem_enc(ct, key_b, pk)) {
            pr_err("ERROR failed to encrypt\n");
            return false;
        }

        //Alice uses Bobs response to get her shared key
        if (!crypto_kem_dec(key_a, ct, sk)) {
            pr_err("ERROR failed to decrypt\n");
            return false;
        }

        if (memcmp(key_a, key_b, PQCRYPTO_BYTES)) {
            pr_err("ERROR invalid keys\n");
            return false;
        }
    }

    kfree(sk);
    kfree(pk);
    return true;
}

static int test_invalid_sk_a(void) {
    unsigned int i;
    unsigned char *pk, *sk;
    unsigned char ct[PQCRYPTO_CIPHERTEXTBYTES];
    unsigned char key_a[PQCRYPTO_BYTES];
    unsigned char key_b[PQCRYPTO_BYTES];

    pk = kmalloc(PQCRYPTO_PUBLICKEYBYTES * sizeof(char), GFP_KERNEL);
    if (!pk)
        return false;
    sk = kmalloc(PQCRYPTO_SECRETKEYBYTES * sizeof(char), GFP_KERNEL);
    if (!sk) {
        kfree(pk);
        return false;
    }

    for (i = 0; i < NTESTS; i++) {
        //Alice generates a public key
        crypto_kem_keypair(pk, sk);

        //Bob derives a secret key and creates a response
        crypto_kem_enc(ct, key_b, pk);


        if (!memcmp(key_a, key_b, PQCRYPTO_BYTES)) {
            pr_err("ERROR invalid sk\n");
            return false;
        }
    }

    kfree(sk);
    kfree(pk);
    return true;
}

static int test_invalid_ciphertext(void) {
    unsigned int i;
    unsigned char *pk, *sk;
    unsigned char ct[PQCRYPTO_CIPHERTEXTBYTES];
    unsigned char key_a[PQCRYPTO_BYTES];
    unsigned char key_b[PQCRYPTO_BYTES];
    size_t pos;

    pk = kmalloc(PQCRYPTO_PUBLICKEYBYTES * sizeof(char), GFP_KERNEL);
    if (!pk)
        return false;
    sk = kmalloc(PQCRYPTO_SECRETKEYBYTES * sizeof(char), GFP_KERNEL);
    if (!sk) {
        kfree(pk);
        return false;
    }

    for (i = 0; i < NTESTS; i++) {
        get_random_bytes((unsigned char *) &pos, sizeof(size_t));

        //Alice generates a public key
        crypto_kem_keypair(pk, sk);

        //Bob derives a secret key and creates a response
        crypto_kem_enc(ct, key_b, pk);

        //Change some byte in the ciphertext (i.e., encapsulated key)
        ct[pos % PQCRYPTO_CIPHERTEXTBYTES] ^= 23;

        //Alice uses Bobs response to get her shared key
        crypto_kem_dec(key_a, ct, sk);

        if (!memcmp(key_a, key_b, PQCRYPTO_BYTES)) {
            pr_err("ERROR invalid ciphertext\n");
            return false;
        }
    }

    kfree(sk);
    kfree(pk);
    return true;
}

static bool __init kyber_selftest(void) {
    return test_keys()
           && test_invalid_sk_a()
           && test_invalid_ciphertext();
}
