/*
 * Copyright (c) 2026 The Ycash developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php .
 *
 * Derived from PQClean crypto_sign/falcon-padded-512/clean/pqclean.c
 * (do_verify and crypto_sign_verify, unchanged in logic; the Falcon code is
 * MIT-licensed, see LICENSE in this directory). Consensus code: it reaches
 * only modq_decode, comp_decode (codec.c), to_ntt_monty, verify_raw
 * (vrfy.c), hash_to_point_ct (common.c) and SHAKE256 (fips202.c), all
 * integer-only.
 */

#include "ycash_falcon.h"
#include "inner.h"

#define NONCELEN YCASH_FALCON512_NONCEBYTES

static int
do_verify(
    const uint8_t *nonce, const uint8_t *sigbuf, size_t sigbuflen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    union {
        uint8_t b[2 * 512];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    uint16_t h[512], hm[512];
    int16_t sig[512];
    inner_shake256_context sc;
    size_t v;

    /*
     * Decode public key.
     */
    if (pk[0] != 0x00 + 9) {
        return -1;
    }
    if (PQCLEAN_FALCONPADDED512_CLEAN_modq_decode(h, 9,
            pk + 1, YCASH_FALCON512_PUBLICKEYBYTES - 1)
            != YCASH_FALCON512_PUBLICKEYBYTES - 1) {
        return -1;
    }
    PQCLEAN_FALCONPADDED512_CLEAN_to_ntt_monty(h, 9);

    /*
     * Decode signature.
     */
    if (sigbuflen == 0) {
        return -1;
    }

    v = PQCLEAN_FALCONPADDED512_CLEAN_comp_decode(sig, 9, sigbuf, sigbuflen);
    if (v == 0) {
        return -1;
    }
    if (v != sigbuflen) {
        if (sigbuflen == YCASH_FALCON512_SIGBYTES - NONCELEN - 1) {
            while (v < sigbuflen) {
                if (sigbuf[v++] != 0) {
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }

    /*
     * Hash nonce + message into a vector.
     */
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCONPADDED512_CLEAN_hash_to_point_ct(&sc, hm, 9, tmp.b);
    inner_shake256_ctx_release(&sc);

    /*
     * Verify signature.
     */
    if (!PQCLEAN_FALCONPADDED512_CLEAN_verify_raw(hm, sig, h, 9, tmp.b)) {
        return -1;
    }
    return 0;
}

int
ycash_falcon512_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk) {
    if (siglen < 1 + NONCELEN) {
        return -1;
    }
    if (sig[0] != 0x30 + 9) {
        return -1;
    }
    return do_verify(sig + 1,
                     sig + 1 + NONCELEN, siglen - 1 - NONCELEN, m, mlen, pk);
}
