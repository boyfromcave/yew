//! The bridge surface (plan §3.4): the small, synchronous-from-Dart set of calls exposed to the
//! Flutter app through `flutter_rust_bridge` (feature `bridge`, wired in Phase W3).
//! No transaction byte is produced outside this crate; screens render only `preview` objects.
