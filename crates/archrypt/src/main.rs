use std::{process, path::PathBuf};
use clap::{Arg, ArgAction, ArgGroup, Command};
use archrypto_core::{compress_files, extract_files};
use config::Config;
use std::fs;
mod config;


fn main() {
    let matches = build_cli().get_matches();
    
    match matches.subcommand() {
        Some(("pubkey", sub_m)) => {
            // 設定ファイルを読み込む
            let mut config = Config::load().unwrap_or_else(|e| {
                eprintln!("Failed to load configuration: {}", e);
                process::exit(1);
            });

            if sub_m.get_flag("list") {
                // 登録されている公開鍵の一覧を表示
                if config.public_keys.is_empty() {
                    println!("No public keys registered.");
                } else {
                    println!("Registered public keys:");
                    for (i, key) in config.public_keys.iter().enumerate() {
                        if let Some(default_index) = config.default_public_key_index {
                            if i == default_index {
                                println!("  {}: {:?} [default]", i, key);
                            } else {
                                println!("  {}: {:?}", i, key);
                            }
                        } else {
                            println!("  {}: {:?}", i, key);
                        }
                    }
                }
            } else if let Some(new_key) = sub_m.get_one::<PathBuf>("add") {
                let absolute_path = fs::canonicalize(new_key).unwrap_or_else(|e|{
                    eprintln!("Error occured {}",e);
                    process::exit(1);
                });
                // 公開鍵を追加
                config.public_keys.push(absolute_path);
                // もしデフォルトが未設定なら、最初の登録をデフォルトにするなどの処理
                if config.default_public_key_index.is_none() {
                    config.default_public_key_index = Some(0);
                }
                config.save().unwrap_or_else(|e| {
                    eprintln!("Failed to save configuration: {}", e);
                    process::exit(1);
                });
                println!("Added public key: {:?}", new_key);
            } else if let Some(&index) = sub_m.get_one::<usize>("set") {
                // 指定したインデックスをデフォルトに設定
                if index >= config.public_keys.len() {
                    eprintln!("Invalid index: {}. There are only {} keys registered.", index, config.public_keys.len());
                    process::exit(1);
                }
                config.default_public_key_index = Some(index);
                config.save().unwrap_or_else(|e| {
                    eprintln!("Failed to save configuration: {}", e);
                    process::exit(1);
                });
                println!("Set default public key to index {}", index);
            } else if let Some(&index) = sub_m.get_one::<usize>("delete") {
                if index >= config.public_keys.len(){
                    eprintln!("Invalid index: {}. There are only {} keys registered.", index, config.public_keys.len());
                    process::exit(1);
                }
                config.remove_public_key(index).unwrap_or_else(|e|{
                    eprintln!("{}",e);
                    process::exit(1);
                });

            }  else if sub_m.get_flag("clear") {
                config.clear_public_key().unwrap_or_else(|e|{
                    eprintln!("{}",e);
                    process::exit(1);
                })
            } else {
                eprintln!("No valid pubkey option was provided.");
                process::exit(1);
            }
        }
        Some(("privatekey", sub_m)) => {
            // 設定ファイルを読み込む
            let mut config = Config::load().unwrap_or_else(|e| {
                eprintln!("Failed to load configuration: {}", e);
                process::exit(1);
            });

            if sub_m.get_flag("list") {
                // 登録されている公開鍵の一覧を表示
                if config.private_keys.is_empty() {
                    println!("No private keys registered.");
                } else {
                    println!("Registered private keys:");
                    for (i, key) in config.private_keys.iter().enumerate() {
                        if let Some(default_index) = config.default_private_key_index {
                            if i == default_index {
                                println!("  {}: {:?} [default]", i, key);
                            } else {
                                println!("  {}: {:?}", i, key);
                            }
                        } else {
                            println!("  {}: {:?}", i, key);
                        }
                    }
                }
            } else if let Some(new_key) = sub_m.get_one::<PathBuf>("add") {
                // 秘密鍵を追加
                let absolute_path = fs::canonicalize(new_key).unwrap_or_else(|e|{
                    eprintln!("Error occured {}",e);
                    process::exit(1);
                });
                config.private_keys.push(absolute_path);
                // もしデフォルトが未設定なら、最初の登録をデフォルトにするなどの処理
                if config.default_private_key_index.is_none() {
                    config.default_private_key_index = Some(0);
                }
                config.save().unwrap_or_else(|e| {
                    eprintln!("Failed to save configuration: {}", e);
                    process::exit(1);
                });
                println!("Added private key: {:?}", new_key);
            } else if let Some(&index) = sub_m.get_one::<usize>("set") {
                // 指定したインデックスをデフォルトに設定
                if index >= config.private_keys.len() {
                    eprintln!("Invalid index: {}. There are only {} keys registered.", index, config.private_keys.len());
                    process::exit(1);
                }
                config.default_private_key_index = Some(index);
                config.save().unwrap_or_else(|e| {
                    eprintln!("Failed to save configuration: {}", e);
                    process::exit(1);
                });
                println!("Set default private key to index {}", index);
            } else if let Some(&index) = sub_m.get_one::<usize>("delete") {
                if index >= config.private_keys.len(){
                    eprintln!("Invalid index: {}. There are only {} keys registered.", index, config.private_keys.len());
                    process::exit(1);
                }
                config.remove_private_key(index).unwrap_or_else(|e|{
                    eprintln!("{}",e);
                    process::exit(1);
                });
            } else if sub_m.get_flag("clear") {
                config.clear_private_key().unwrap_or_else(|e|{
                    eprintln!("{}",e);
                    process::exit(1);
                })
            } else {
                eprintln!("No valid privatekey option was provided.");
                process::exit(1);
            }
        }
        _=>{
            //メインコマンド引数処理
            let output_path: PathBuf = matches.get_one::<PathBuf>("output").unwrap().clone();
        
            //configload
            let cfg = Config::load().unwrap_or_else(|e| {
                eprintln!("Failed to load configuration: {}", e);
                process::exit(1);
            });
        
            if  let Some(specify_files) = matches.get_many::<PathBuf>("compress"){
                let files: Vec<PathBuf> = specify_files.cloned().collect();
                let public_key: PathBuf = if let Some(pk) = matches.get_one::<PathBuf>("public-key") {
                    pk.clone()
                } else if let Some(default_pk) = cfg.default_public_key() {
                    default_pk.clone().to_path_buf()
                } else {
                    eprintln!("Public key is not specified and no default is set.");
                    process::exit(1);
                };
                
                
                if let Err(e) = compress_files(&output_path,&public_key ,&files) {
                    eprintln!("Compression failed: {}", e);
                    process::exit(1);
                }
            }else if let Some(extract_file) = matches.get_one::<PathBuf>("extract") {
                
                let private_key: PathBuf = if let Some(pk) = matches.get_one::<PathBuf>("private-key") {
                    pk.clone()
                } else if let Some(default_pk) = cfg.default_private_key() {
                    default_pk.clone().to_path_buf()
                } else {
                    eprintln!("Private key is not specified and no configuration file found.");
                    process::exit(1);
                };
                if let Err(e) = extract_files(extract_file,&private_key, &output_path) {
                    eprintln!("Extraction failed: {}", e);
                    process::exit(1);
                }
            }

        }
    }

}


///コマンドのオプションの設定
/// 
fn build_cli() -> Command {
    let matches = Command::new("acrp")
    .version("0.1")
    .subcommand_negates_reqs(true)
    .about("File compression and encryption tool")
    .arg(Arg::new("compress")
        .short('c')
        .long("compress")
        .help("Compress files")
        .num_args(1..)
        .value_parser(clap::value_parser!(PathBuf))
        .conflicts_with("extract")) // compressとextractは同時に使えない
    .arg(Arg::new("extract")
        .short('x')
        .long("extract")
        .value_parser(clap::value_parser!(PathBuf))
        .help("Extract files")
        .conflicts_with("compress"))// compressとextractは同時に使えない
    .arg(Arg::new("output")
        .short('o')
        .long("output")
        .value_parser(clap::value_parser!(PathBuf))
        .required(true)
        .help("Output path for compressed file or extraction directory"))
    .arg(Arg::new("public-key")
        .short('p')
        .long("public-key")
        .value_parser(clap::value_parser!(PathBuf))
        //.required_if_eq("compress", "true")
        .help("Path to the public key used for encryption"))
    .arg(Arg::new("private-key")
        .short('k')
        .long("private-key")
        .value_parser(clap::value_parser!(PathBuf))
        .required_if_eq("extract", "true")
        .help("Path to the private key used for decryption"))
    .group(ArgGroup::new("mode")
        .args(&["compress", "extract"])
        .required(true))// グループ全体として必須
    .subcommand(
        Command::new("pubkey")
        .about("Manage public key configuration")
        .arg(Arg::new("list")
            .short('l')
            .long("list")
            .action(ArgAction::SetTrue)
            .help("List registered public keys and the current default"))
        .arg(Arg::new("add")
            .short('a')
            .long("add")
            .value_parser(clap::value_parser!(PathBuf))
            .help("Add a public key to the configuration"))
        .arg(Arg::new("set")
            .short('s')
            .long("set")
            .value_parser(clap::value_parser!(usize))
            .help("Set the default public key by index"))
        .arg(Arg::new("delete")
            .short('d')
            .long("delte")
            .value_parser(clap::value_parser!(usize))
            .help("Delete private key by index"))
        .arg(Arg::new("clear")
            .short('c')
            .long("clear")
            .action(ArgAction::SetTrue)
            .help("All publickey setting remove"))
    ).subcommand(
        Command::new("privatekey")
        .about("Manage private key configuration")
        .arg(Arg::new("list")
            .short('l')
            .long("list")
            .action(ArgAction::SetTrue)
            .help("List registered private keys and the current default"))
        .arg(Arg::new("add")
            .short('a')
            .long("add")
            .value_parser(clap::value_parser!(PathBuf))
            .help("Add a private key to the configuration"))
        .arg(Arg::new("set")
            .short('s')
            .long("set")
            .value_parser(clap::value_parser!(usize))
            .help("Set the default private key by index"))
        .arg(Arg::new("delete")
            .short('d')
            .long("delte")
            .value_parser(clap::value_parser!(usize))
            .help("Delete private key by index"))
        .arg(Arg::new("clear")
            .short('c')
            .long("clear")
            .action(ArgAction::SetTrue)
            .help("All privatekey setting remove"))
    );
    
    return matches;
}

