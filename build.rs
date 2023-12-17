use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from("src");
    tonic_build::configure()
    .out_dir(out_dir)
    .compile(&[
        "src/proto/ecdsa_agent_grpc.proto",
        "src/proto/ecdsa_manager_grpc.proto"
    ], &["src"])
    .unwrap();
}