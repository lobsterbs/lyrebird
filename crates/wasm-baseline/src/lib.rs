//! Compile-only: the pinned rustls builds for wasm32-unknown-unknown with
//! the ring provider. Ran by CI so a fingerprint that breaks the wasm target
//! cannot land quietly.

pub use rustls;
