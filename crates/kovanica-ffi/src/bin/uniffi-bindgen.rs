//! Bindings-generation helper binary. Wraps `uniffi::uniffi_bindgen_main` so
//! the workspace is self-contained: no global `uniffi-bindgen` install needed.
fn main() {
    uniffi::uniffi_bindgen_main()
}
