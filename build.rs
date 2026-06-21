fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=assets/remzar.ico");

        winresource::WindowsResource::new()
            .set_icon("assets/remzar.ico")
            .compile()
            .expect("failed to embed Remzar icon");
    }
}
