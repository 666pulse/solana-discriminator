use hex;
use heck::ToSnakeCase;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

fn main() -> () {
    let mut namespace = "global".to_string();
    let mut name = None;
    for arg in std::env::args().skip(1) {
        if arg == "-n" {
            namespace = std::env::args().nth(2).expect("no namespace given");
        } else {
            name = Some(arg);
        }
    }
    let name = name.expect("no name given");
    let hash = get_hash(&namespace, &name);
    let hash_hex = hex::encode(hash);
    let base64_val = BASE64.encode(&hash);

    // print result
    println!("namespace: {}", namespace);
    println!("instruction: {}", name);
    println!("hash: {:?}", hash);
    println!("hex: 0x{}", hash_hex);
    println!("base64: {}\n", base64_val);
    ()
}

pub fn get_hash(namespace: &str, name: &str) -> [u8; 8] {
    let snake_name: String = name.to_snake_case();
    print!("snake_name: {}\n", snake_name);

    let preimage = format!("{}:{}", namespace, snake_name);
    let mut sighash = [0u8; 8];
    sighash.copy_from_slice(
        &anchor_lang::solana_program::hash::hash(preimage.as_bytes()).to_bytes()[..8],
    );
    sighash
}
