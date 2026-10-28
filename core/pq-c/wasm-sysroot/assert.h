/* Copyright (c) 2026 The Ycash developers
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 *
 * wasm32-unknown-unknown only (see stdlib.h here). The vendored Falcon includes <assert.h> but
 * asserts nothing; NDEBUG semantics. */
#ifndef YEW_PQ_WASM_ASSERT_H
#define YEW_PQ_WASM_ASSERT_H
#define assert(x) ((void)0)
#endif
