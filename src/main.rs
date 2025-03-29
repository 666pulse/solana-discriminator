use heck::ToSnakeCase;

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

    // print result
    println!("namespace: {}", namespace);
    println!("instruction: {}", name);
    println!("hash: {:?}", hash);
    println!("hex: 0x{}\n", hash_hex);
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
