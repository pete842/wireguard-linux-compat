#include <linux/types.h>
#include <linux/string.h>
#include <linux/random.h>
#include <kyber/params.h>
#include <kyber/indcpa.h>
#include <kyber/poly.h>
#include <kyber/polyvec.h>
#include <kyber/ntt.h>
#include <kyber/symmetric.h>


/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r:          pointer to the output serialized public key
*              polyvec *pk:         pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES]) {
    size_t i;
    polyvec_tobytes(r, pk);
    for (i = 0; i < KYBER_SYMBYTES; i++)
        r[i + KYBER_POLYVECBYTES] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:             pointer to output public-key
*                                         polynomial vector
*              - uint8_t *seed:           pointer to output seed to generate
*                                         matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
    size_t i;
    polyvec_frombytes(pk, packedpk);
    for (i = 0; i < KYBER_SYMBYTES; i++)
        seed[i] = packedpk[i + KYBER_POLYVECBYTES];
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r:  pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
    polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:             pointer to output vector of
*                                         polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk,
                      const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk:   pointer to the input vector of polynomials b
*              poly *v:    pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES],
                            polyvec *b,
                            poly *v) {
    polyvec_compress(r, b);
    poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b:       pointer to the output vector of polynomials b
*              - poly *v:          pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b,
                              poly *v,
                              const uint8_t c[KYBER_INDCPA_BYTES]) {
    polyvec_decompress(b, c);
    poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r:          pointer to output buffer
*              - unsigned int len:    requested number of 16-bit integers
*                                     (uniform mod q)
*              - const uint8_t *buf:  pointer to input buffer
*                                     (assumed to be uniform random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val;

    ctr = pos = 0;
    while (ctr < len && pos + 2 <= buflen) {
        val = buf[pos] | ((uint16_t) buf[pos + 1] << 8);
        pos += 2;

        if (val < 19 * KYBER_Q) {
            val -= (val >> 12) * KYBER_Q; // Barrett reduction
            r[ctr++] = (int16_t) val;
        }
    }

    return ctr;
}

#define gen_a_row(A, B, row) gen_matrix_row(A,B,row,0)
#define gen_at_row(A, B, row) gen_matrix_row(A,B,row,1)

/*************************************************
* Name:        gen_matrix_row
*
* Description: Deterministically generate requested row (transposed) matrix A
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a:          pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - size_t row:          requested row number
*              - int transposed:      boolean deciding whether A or A^T
*                                     is generated
**************************************************/
#define GEN_MATRIX_NBLOCKS ((2*KYBER_N*(1U << 16)/(19*KYBER_Q) \
                             + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

static void gen_matrix_row(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], size_t row, bool transpose) {
    unsigned int ctr, j;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    for (j = 0; j < KYBER_K; j++) {
        if (transpose)
            xof_absorb(&state, seed, row, j);
        else
            xof_absorb(&state, seed, j, row);

        xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
        ctr = rej_uniform(a->vec[j].coeffs, KYBER_N, buf, sizeof(buf));

        while (ctr < KYBER_N) {
            xof_squeezeblocks(buf, 1, &state);
            ctr += rej_uniform(a->vec[j].coeffs + ctr, KYBER_N - ctr, buf,
                               XOF_BLOCKBYTES);
        }
    }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
*
* Return:      - bool : true if successful, false otherwise
**************************************************/
bool indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec *a, *e, *pkpv, *skpv;
    bool success = false;

    a = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!a)
        goto out;

    e = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!e)
        goto out;

    pkpv = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!pkpv)
        goto out;

    skpv = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!skpv)
        goto out;

    get_random_bytes(buf, KYBER_SYMBYTES);
    hash_g(buf, buf, KYBER_SYMBYTES);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(&skpv->vec[i], noiseseed, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(&e->vec[i], noiseseed, nonce++);

    polyvec_ntt(skpv);
    polyvec_ntt(e);

    for (i = 0; i < KYBER_K; i++) {
        gen_a_row(a, publicseed, i);
        polyvec_pointwise_acc_montgomery(&pkpv->vec[i], a, skpv);
        poly_tomont(&pkpv->vec[i]);
    }

    polyvec_add(pkpv, pkpv, e);
    polyvec_reduce(pkpv);

    pack_sk(sk, skpv);
    pack_pk(pk, pkpv, publicseed);
    success = true;
out:
    if (a) {
        memzero_explicit(a, sizeof(polyvec));
        kfree(a);
    }
    if (e) {
        memzero_explicit(e, sizeof(polyvec));
        kfree(e);
    }
    if (pkpv) {
        memzero_explicit(pkpv, sizeof(polyvec));
        kfree(pkpv);
    }
    if (skpv) {
        memzero_explicit(skpv, sizeof(polyvec));
        kfree(skpv);
    }

    return success;
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c:           pointer to output ciphertext
*                                      (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m:     pointer to input message
*                                      (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk:    pointer to input public key
*                                      (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins
*                                      used as seed (of length KYBER_SYMBYTES)
*                                      to deterministically generate all
*                                      randomness
*
* Return:      - bool : true if successful, false otherwise
**************************************************/
bool indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec *sp, *pkpv, *ep, *at, *bp;
    poly v, k, epp;
    bool success = false;

    at = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!at)
        goto out;

    ep = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!ep)
        goto out;

    pkpv = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!pkpv)
        goto out;

    bp = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!bp)
        goto out;

    sp = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!sp)
        goto out;

    unpack_pk(pkpv, seed, pk);
    poly_frommsg(&k, m);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(sp->vec + i, coins, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(ep->vec + i, coins, nonce++);
    poly_getnoise(&epp, coins, nonce++);

    polyvec_ntt(sp);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++) {
        gen_at_row(at, seed, i); // (pete842) generate each row at a time to save a LOT of space
        polyvec_pointwise_acc_montgomery(&bp->vec[i], at, sp);
    }

    polyvec_pointwise_acc_montgomery(&v, pkpv, sp);

    polyvec_invntt_tomont(bp);
    poly_invntt_tomont(&v);

    polyvec_add(bp, bp, ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce(bp);
    poly_reduce(&v);

    pack_ciphertext(c, bp, &v);
    success = true;
out:
    if (at) {
        memzero_explicit(at, sizeof(polyvec));
        kfree(at);
    }
    if (ep) {
        memzero_explicit(ep, sizeof(polyvec));
        kfree(ep);
    }
    if (bp) {
        memzero_explicit(bp, sizeof(polyvec));
        kfree(bp);
    }
    if (sp) {
        memzero_explicit(sp, sizeof(polyvec));
        kfree(sp);
    }
    if (pkpv) {
        memzero_explicit(pkpv, sizeof(polyvec));
        kfree(pkpv);
    }
    return success;
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m:        pointer to output decrypted message
*                                   (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c:  pointer to input ciphertext
*                                   (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
bool indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec *bp, *skpv;
    poly v, mp;
    bool success = false;

    bp = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!bp)
        goto out;
    skpv = kmalloc(sizeof(polyvec), GFP_KERNEL);
    if (!skpv)
        goto out;

    unpack_ciphertext(bp, &v, c);
    unpack_sk(skpv, sk);

    polyvec_ntt(bp);
    polyvec_pointwise_acc_montgomery(&mp, skpv, bp);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);

    success = true;
out:
    if (bp) {
        memzero_explicit(bp, sizeof(polyvec));
        kfree(bp);
    }
    if (skpv) {
        memzero_explicit(skpv, sizeof(polyvec));
        kfree(skpv);
    }
    return success;
}
