use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::Parser;
use heck::ToSnakeCase;
use hex;
use std::fs::read_to_string;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(required_unless_present = "file")]
    ins_name: Option<String>,

    #[arg(short = 'n', long, default_value = "global")]
    namespace: String,

    #[arg(short = 'f', long, value_parser = validate_file_type)]
    file: Option<String>,
}

/// 验证文件类型
fn validate_file_type(path: &str) -> Result<String, String> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(format!("文件不存在：{}", path.display()));
    }

    if !path.is_file() {
        return Err(format!("不是文件：{}", path.display()));
    }

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => Ok(path.to_string_lossy().into_owned()),
        Some(ext) => Err(format!("不支持的文件类型：.{}，只支持 json 格式", ext)),
        None => Err("文件没有扩展名".to_string()),
    }
}

fn is_json_file(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

fn print_discriminator(json: &serde_json::Value, namespace: &str) {
    if let Some(instructions) = json.get("instructions") {
        if let Some(instructions_array) = instructions.as_array() {
            println!("\n找到 instructions 节点，包含以下指令：");
            for (_, instruction) in instructions_array.iter().enumerate() {
                if let Some(name) = instruction.get("name").and_then(|n| n.as_str()) {
                    // println!("{}. {}", index + 1, name);
                    print_hash(namespace, name);
                }
            }
        } else {
            println!("\ninstructions 节点不是数组格式");
        }
    } else {
        println!("\n未找到 instructions 节点");
    }
}

/// 读取文件内容
fn read_file_content(path: &str) -> Result<String, String> {
    read_to_string(path).map_err(|e| format!("Error reading file: {}", e))
}

/// 解析 JSON 内容
fn parse_json_content(content: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(content).map_err(|e| format!("Invalid JSON content: {}", e))
}

/// 处理 JSON 文件并打印指令信息
fn process_json_file(path: &str, namespace: &str) -> Result<(), String> {
    if !is_json_file(path) {
        return Err("不是 JSON 文件".to_string());
    }

    let content = read_file_content(path)?;
    let json = parse_json_content(&content)?;
    print_discriminator(&json, namespace);
    Ok(())
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

pub fn print_hash(namespace: &str, name: &str) {
    let hash = get_hash(namespace, name);
    let hash_hex = hex::encode(hash);
    let base64_val = BASE64.encode(&hash);

    println!("namespace: {}", namespace);
    println!("instruction: {}", name);
    println!("hash: {:?}", hash);
    println!("hex: 0x{}", hash_hex);
    println!("base64: {}", base64_val);
    println!();
    ()
}

fn main() -> () {
    let args = Args::parse();

    if let Some(ins_name) = args.ins_name {
        print_hash(&args.namespace, &ins_name);
    }

    if let Some(path) = args.file {
        if let Err(e) = process_json_file(&path, &args.namespace) {
            eprintln!("{}", e);
        }
    }
    ()
}
