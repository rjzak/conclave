// SPDX-License-Identifier: Apache-2.0

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("server.ico").set_language(0x0009);
        res.compile().unwrap();
    }
}
