//! Generates Rust types from the language-neutral protocol in `spec/proto`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = "../../spec/proto";
    let protos = [
        "../../spec/proto/gimmecores/peer/v1/peer.proto",
        "../../spec/proto/gimmecores/local/v1/local.proto",
    ];
    for p in &protos {
        println!("cargo:rerun-if-changed={p}");
    }
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    config.compile_protos(&protos, &[root])?;
    Ok(())
}
