/* Copyright (c) 2026 The Ycash developers
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 * wasm32-unknown-unknown only (see stdlib.h here): the memory functions the vendored Falcon calls.
 * Rust's compiler-builtins defines them on that target. */
#ifndef YEW_PQ_WASM_STRING_H
#define YEW_PQ_WASM_STRING_H
#include <stddef.h>
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
#endif
