/* Copyright (c) 2026 The Ycash developers
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 * wasm32-unknown-unknown only (core/build.rs adds this directory there): that target has no C
 * library, so the vendored Falcon's <stdlib.h> is these three declarations. malloc / free / exit
 * are renamed yew_pq_* and implemented in Rust (src/pq_wasm_libc.rs), as secp256k1-sys and
 * sqlite-wasm-rs do for their C. Only fips202.c's heap SHAKE contexts call them. */
#ifndef YEW_PQ_WASM_STDLIB_H
#define YEW_PQ_WASM_STDLIB_H
#include <stddef.h>
#define malloc yew_pq_malloc
#define free yew_pq_free
#define exit yew_pq_exit
void *yew_pq_malloc(size_t size);
void yew_pq_free(void *ptr);
_Noreturn void yew_pq_exit(int status);
#endif
