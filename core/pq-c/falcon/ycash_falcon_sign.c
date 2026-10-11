/*
 * Copyright (c) 2026 The Ycash developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php .
 *
 * Derived from PQClean crypto_sign/falcon-padded-512/clean/pqclean.c
 * (crypto_sign_keypair, do_sign, crypto_sign_signature; the Falcon code is
 * MIT-licensed, see LICENSE in this directory). The only change is that the
 * randomness PQClean reads from randombytes() is passed in by the caller.
 * Wallet code: never linked into a consensus path.
 */

#include <string.h>

#include "ycash_falcon.h"
#include "inner.h"

#define NONCELEN YCASH_FALCON512_NONCEBYTES

/* Ycash: a wipe the compiler cannot elide (stores through a volatile pointer). */
static void
wipe(void *p, size_t n) {
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n-- > 0) {
        *q++ = 0;
    }
}

int
ycash_falcon512_keygen_from_seed(uint8_t *pk, uint8_t *sk,
                                 const uint8_t *seed, size_t seedlen) {
    union {
        uint8_t b[FALCON_KEYGEN_TEMP_9];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[512], g[512], F[512];
    uint16_t h[512];
    inner_shake256_context rng;
    size_t u, v;
    int ret = -1;

    /*
     * Generate key pair.
     */
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, seedlen);
    inner_shake256_flip(&rng);
    PQCLEAN_FALCONPADDED512_CLEAN_keygen(&rng, f, g, F, NULL, h, 9, tmp.b);
    inner_shake256_ctx_release(&rng);

    /*
     * Encode private key.
     */
    sk[0] = 0x50 + 9;
    u = 1;
    v = PQCLEAN_FALCONPADDED512_CLEAN_trim_i8_encode(
            sk + u, YCASH_FALCON512_SECRETKEYBYTES - u,
            f, 9, PQCLEAN_FALCONPADDED512_CLEAN_max_fg_bits[9]);
    if (v == 0) {
        goto done;
    }
    u += v;
    v = PQCLEAN_FALCONPADDED512_CLEAN_trim_i8_encode(
            sk + u, YCASH_FALCON512_SECRETKEYBYTES - u,
            g, 9, PQCLEAN_FALCONPADDED512_CLEAN_max_fg_bits[9]);
    if (v == 0) {
        goto done;
    }
    u += v;
    v = PQCLEAN_FALCONPADDED512_CLEAN_trim_i8_encode(
            sk + u, YCASH_FALCON512_SECRETKEYBYTES - u,
            F, 9, PQCLEAN_FALCONPADDED512_CLEAN_max_FG_bits[9]);
    if (v == 0) {
        goto done;
    }
    u += v;
    if (u != YCASH_FALCON512_SECRETKEYBYTES) {
        goto done;
    }

    /*
     * Encode public key.
     */
    pk[0] = 0x00 + 9;
    v = PQCLEAN_FALCONPADDED512_CLEAN_modq_encode(
            pk + 1, YCASH_FALCON512_PUBLICKEYBYTES - 1,
            h, 9);
    if (v != YCASH_FALCON512_PUBLICKEYBYTES - 1) {
        goto done;
    }
    ret = 0;

done:
    /* Ycash: wipe the secret polynomials and the keygen scratch. */
    wipe(f, sizeof f);
    wipe(g, sizeof g);
    wipe(F, sizeof F);
    wipe(tmp.b, sizeof tmp.b);
    return ret;
}

int
ycash_falcon512_sign(uint8_t *sigout, const uint8_t *m, size_t mlen,
                     const uint8_t *sk, const uint8_t *nonce,
                     const uint8_t *seed) {
    union {
        uint8_t b[72 * 512];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[512], g[512], F[512], G[512];
    struct {
        int16_t sig[512];
        uint16_t hm[512];
    } r;
    inner_shake256_context sc;
    size_t u, v;
    uint8_t *sigbuf = sigout + 1 + NONCELEN;
    size_t sigbuflen = YCASH_FALCON512_SIGBYTES - NONCELEN - 1;
    int ret = -1;

    /*
     * Decode the private key.
     */
    if (sk[0] != 0x50 + 9) {
        return -1;
    }
    u = 1;
    v = PQCLEAN_FALCONPADDED512_CLEAN_trim_i8_decode(
            f, 9, PQCLEAN_FALCONPADDED512_CLEAN_max_fg_bits[9],
            sk + u, YCASH_FALCON512_SECRETKEYBYTES - u);
    if (v == 0) {
        goto done;
    }
    u += v;
    v = PQCLEAN_FALCONPADDED512_CLEAN_trim_i8_decode(
            g, 9, PQCLEAN_FALCONPADDED512_CLEAN_max_fg_bits[9],
            sk + u, YCASH_FALCON512_SECRETKEYBYTES - u);
    if (v == 0) {
        goto done;
    }
    u += v;
    v = PQCLEAN_FALCONPADDED512_CLEAN_trim_i8_decode(
            F, 9, PQCLEAN_FALCONPADDED512_CLEAN_max_FG_bits[9],
            sk + u, YCASH_FALCON512_SECRETKEYBYTES - u);
    if (v == 0) {
        goto done;
    }
    u += v;
    if (u != YCASH_FALCON512_SECRETKEYBYTES) {
        goto done;
    }
    if (!PQCLEAN_FALCONPADDED512_CLEAN_complete_private(G, f, g, F, 9, tmp.b)) {
        goto done;
    }

    /*
     * The nonce (40 bytes), supplied by the caller.
     */
    memmove(sigout + 1, nonce, NONCELEN);

    /*
     * Hash message nonce + message into a vector.
     */
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCONPADDED512_CLEAN_hash_to_point_ct(&sc, r.hm, 9, tmp.b);
    inner_shake256_ctx_release(&sc);

    /*
     * Initialize a RNG from the caller's 48-byte seed.
     */
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, seed, YCASH_FALCON512_SIGN_SEEDBYTES);
    inner_shake256_flip(&sc);

    /*
     * Compute the signature. This loops until a signature value is found
     * that fits in the padded buffer.
     */
    for (;;) {
        PQCLEAN_FALCONPADDED512_CLEAN_sign_dyn(r.sig, &sc, f, g, F, G, r.hm, 9, tmp.b);
        v = PQCLEAN_FALCONPADDED512_CLEAN_comp_encode(sigbuf, sigbuflen, r.sig, 9);
        if (v != 0) {
            inner_shake256_ctx_release(&sc);
            memset(sigbuf + v, 0, sigbuflen - v);
            break;
        }
    }
    sigout[0] = 0x30 + 9;
    ret = 0;

done:
    /* Ycash: wipe the secret polynomials and the signing scratch. */
    wipe(f, sizeof f);
    wipe(g, sizeof g);
    wipe(F, sizeof F);
    wipe(G, sizeof G);
    wipe(tmp.b, sizeof tmp.b);
    return ret;
}
