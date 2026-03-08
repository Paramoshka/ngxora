fn main() {
    println!("cargo:rerun-if-changed=proto/control.proto");

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to locate vendored protoc");
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/control.proto"], &["proto"])
        .expect("failed to compile control.proto");
}
