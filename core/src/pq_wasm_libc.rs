// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The C library the vendored Falcon needs on wasm32-unknown-unknown, which has none
//! (`pq-c/wasm-sysroot/stdlib.h` renames `malloc` / `free` / `exit` to these). Only `fips202.c`'s
//! heap SHAKE contexts call them; the Falcon sign and verify paths keep their context inline
//! (`pq-c/README.md`, the local patch). Native and mobile builds link the platform's libc instead.

use std::alloc::{alloc, dealloc, Layout};

/// C's `max_align_t` on wasm32; the block's size is stored in the header ahead of the pointer.
const ALIGN: usize = 16;

#[no_mangle]
pub unsafe extern "C" fn yew_pq_malloc(size: usize) -> *mut u8 {
    let Some(total) = size.checked_add(ALIGN) else {
        return std::ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, ALIGN) else {
        return std::ptr::null_mut();
    };
    let base = alloc(layout);
    if base.is_null() {
        return base;
    }
    (base as *mut usize).write(total);
    base.add(ALIGN)
}

#[no_mangle]
pub unsafe extern "C" fn yew_pq_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let base = ptr.sub(ALIGN);
    let total = (base as *const usize).read();
    dealloc(base, Layout::from_size_align_unchecked(total, ALIGN));
}

/// `fips202.c` exits only when `malloc` fails; trap, as an out-of-memory abort would.
#[no_mangle]
pub extern "C" fn yew_pq_exit(_status: i32) -> ! {
    core::arch::wasm32::unreachable()
}
