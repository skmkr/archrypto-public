use std::fs::{self, canonicalize, create_dir_all, File};
use std::io::{BufReader, BufWriter, Write, Read, copy};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zip::{ZipArchive,write::{SimpleFileOptions, ZipWriter}};
use rsa::{RsaPrivateKey,RsaPublicKey,pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey,Pkcs1v15Encrypt,rand_core::OsRng};
use aes_gcm::{Aes256Gcm, Nonce}; // AES-GCM
use aes_gcm::aead::{generic_array::{GenericArray,typenum::U12,typenum::U32},Aead, AeadCore, KeyInit,Payload}; // AES-GCMのユーティリティ
use anyhow::{anyhow, Ok, Result};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle};
use tempfile::NamedTempFile;

const EXTENTION: &str = "acrp";
const PROGRESS_SETTING: &str = "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})";
const PROGRESS_BAR_CHAR: &str = "#>-";

/// 指定されたファイルまたはディレクトリ群をZIP圧縮し、
/// さらに指定した公開鍵を用いて暗号化した結果を output_crypted に保存します.
///
/// 圧縮処理では、対象パスがファイルの場合はそのまま、ディレクトリの場合は再帰的に中身を含めます。
/// 進捗バーで処理の進捗も表示されます。
///
/// # Arguments
///
/// * `output_crypted` - 暗号化後のZIPファイルの出力先パス。拡張子は ".acrp" である必要があります。
/// * `public_key_path` - 暗号化に使用する公開鍵ファイルのパス。
/// * `target_pathes` - 圧縮対象となるファイルまたはディレクトリのパスのリスト。
///
/// # Errors
///
/// * output_crypted の拡張子が ".acrp" でない場合。
/// * 各ファイル・ディレクトリの読み込み、ZIP圧縮、暗号化処理、または進捗バーの更新に失敗した場合にエラーを返します。
pub fn compress_files(
    output_crypted: &PathBuf,
    public_key_path: &PathBuf,
    target_pathes: &[PathBuf],
) -> Result<()> {
    // 出力拡張子チェック
    if !validate_extension(output_crypted)? {
        return Err(anyhow!("outputpath extention does not \".{}\"", EXTENTION));
    }
    
    // 圧縮対象の総ファイル数 + 暗号化工程用に1件追加して進捗バーを作成
    let total_files = count_files_in_paths(target_pathes)?;
    let pb = ProgressBar::new(u64::try_from(total_files + 1)?);
    pb.set_style(
        ProgressStyle::with_template(PROGRESS_SETTING)
            .unwrap()
            .progress_chars(PROGRESS_BAR_CHAR),
    );

    // 一時ZIPファイルをシステム一時ディレクトリに作成
    let mut temp_zip_file = NamedTempFile::new()?;
    {
        let writer = BufWriter::new(temp_zip_file.as_file_mut());
        let mut zip = ZipWriter::new(writer);
        let options = SimpleFileOptions::default();
        
        // 各対象パスごとに処理
        for target in target_pathes {
            if target.is_file() {
                let mut file = File::open(target)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
        
                // ファイル名を安全に取得（非UTF-8は to_string_lossy で変換）
                let file_name = target.file_name().unwrap().to_string_lossy();
                zip.start_file(&file_name, options)?;
                zip.write_all(&buffer)?;
                pb.inc(1);
            } else if target.is_dir() {
                // ディレクトリの場合は、ディレクトリ自体の名前をベースとして利用
                let base_name = target
                    .file_name()
                    .ok_or_else(|| anyhow!("Failed to get directory name"))?
                    .to_string_lossy()
                    .to_string();
    
                // WalkDirで再帰的にファイルを追加
                for entry in WalkDir::new(target) {
                    let entry = entry?;
                    if entry.file_type().is_file() {
                        // 対象ディレクトリを除いた相対パスを取得
                        let relative_path = entry.path()
                            .strip_prefix(target)
                            .map_err(|_| anyhow!("Failed to strip prefix"))?;
                        let zip_entry_path = Path::new(&base_name).join(relative_path);
                        let relative_path_str = zip_entry_path.to_string_lossy();
                                    
                        zip.start_file(&relative_path_str, options)?;
                        let mut file = File::open(entry.path())?;
                        let mut buffer = Vec::new();
                        file.read_to_end(&mut buffer)?;
                        zip.write_all(&buffer)?;
                        pb.inc(1);
                    }
                }
            } else {
                return Err(anyhow!("Target path is neither file nor directory: {:?}", target.display()));
            }
        }
        zip.finish()?;
    }
    // 暗号化処理：一時ZIPファイルのパスを用いて暗号化処理を実行
    encrypt_file_with_public_key(temp_zip_file.path(), public_key_path, output_crypted)?;
    pb.inc(1);
    pb.finish();
    println!("Complete!");
    println!("{}", canonicalize(output_crypted)?.display());
    Ok(())
}

/// 指定された暗号化ZIPファイルを復号し、
/// 出力ディレクトリに展開します。
///
/// 復号化したZIPファイルは一時ファイルまたはインメモリバッファを用いて処理されます。
///
/// # Arguments
///
/// * `input_encrypted_file` - 暗号化されたZIPファイルのパス。拡張子は ".acrp" である必要があります。
/// * `private_key_path` - 復号に使用する秘密鍵ファイルのパス。
/// * `output_dir` - 展開先のディレクトリパス。
///
/// # Errors
///
/// * 入力ファイルの拡張子が正しくない場合、
/// * 復号化処理、ZIP解凍、またはファイル書き出しに失敗した場合にエラーを返します。
pub fn extract_files(
    input_encrypted_file: &Path,
    private_key_path: &PathBuf,
    output_dir: &Path,
) -> Result<()> {
    if !validate_extension(input_encrypted_file)? {
        return Err(anyhow!("inputpath extention does not \".{}\"", EXTENTION));
    }
    let pb = ProgressBar::new(u64::try_from(1)?);
    pb.set_style(
        ProgressStyle::with_template(PROGRESS_SETTING)
            .unwrap()
            .progress_chars(PROGRESS_BAR_CHAR),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    // 復号処理：暗号化されたZIPファイルを復号し、Vec<u8>として取得
    let decrypted_zip = decrypt_zip_with_rsa(input_encrypted_file, private_key_path)?;
    
    // 一時ファイルに復号結果を書き出す
    let mut temp_zip_file = NamedTempFile::new()?;
    temp_zip_file.as_file_mut().write_all(&decrypted_zip)?;
    
    // ZIPファイル内のファイル総数をカウントして進捗バーの総数を設定
    let total_files = count_files_in_zip(&temp_zip_file)?;
    pb.inc(1);
    pb.set_length(u64::try_from(total_files)? + 1);

    let file = File::open(&temp_zip_file)?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = output_dir.join(file.name());
    
        if file.name().ends_with('/') {
            create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            copy(&mut file, &mut outfile)?;
        }
        pb.inc(1);
    }
    pb.finish();
    println!("Complete!");
    println!("{}", canonicalize(output_dir)?.display());
    Ok(())
}

/// 指定されたZIPファイル（未暗号化）の公開鍵による暗号化を行い、
/// 結果を encrypted_path に保存します.
///
/// # Arguments
///
/// * `input_zip` - 暗号化対象のZIPファイルのパス。
/// * `public_key_path` - 暗号化に使用する公開鍵ファイルのパス。
/// * `encrypted_path` - 暗号化結果の出力パス。拡張子は ".acrp" である必要があります。
///
/// # Errors
///
/// 暗号化処理に失敗した場合、またはファイル読み書きに失敗した場合にエラーを返します。
fn encrypt_file_with_public_key(
    input_zip: &Path,
    public_key_path: &Path,
    encrypted_path: &Path,
) -> Result<()> {
    let mut rng = OsRng;
        
    // 公開鍵の読み込み
    let public_key_pem = fs::read_to_string(public_key_path)?;
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem)?;

    // ZIPファイルの読み込み
    let mut zip_data = Vec::new();
    let mut zip_file = File::open(input_zip)?;
    zip_file.read_to_end(&mut zip_data)?;

    // AES-GCM用の鍵とNonceの生成
    let aes_key = Aes256Gcm::generate_key(&mut rng);
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    
    // AES-GCM によるZIPファイルの暗号化
    let cipher = Aes256Gcm::new(&aes_key);
    let encrypted_zip = cipher.encrypt(&nonce, Payload::from(zip_data.as_ref()))
        .map_err(|e| anyhow!(e.to_string()))?;
    // 公開鍵によるAES鍵の暗号化
    let encrypted_key = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key)?;
    let key_size = encrypted_key.len() as u16;

    // 暗号化データの保存: Nonce, AES鍵のサイズ, 暗号化されたAES鍵, 暗号化ZIPデータの順に出力
    let mut encrypted_file = File::create(encrypted_path)?;
    encrypted_file.write_all(&nonce)?;
    encrypted_file.write_all(&key_size.to_be_bytes())?;
    encrypted_file.write_all(&encrypted_key)?;
    encrypted_file.write_all(&encrypted_zip)?;

    Ok(())
}

/// 暗号化されたZIPファイルを復号し、その復号結果を Vec<u8> として返します.
///
/// # Arguments
///
/// * `encrypted_path` - 暗号化されたZIPファイルのパス。
/// * `private_key_path` - 復号に使用する秘密鍵ファイルのパス。
///
/// # Errors
///
/// ファイルの読み込み、秘密鍵のパース、暗号化・復号の各工程で失敗した場合にエラーを返します。
fn decrypt_zip_with_rsa(
    encrypted_path: &Path,
    private_key_path: &Path,
) -> Result<Vec<u8>> {
    let mut encrypted_data = Vec::new();
    File::open(encrypted_path)?.read_to_end(&mut encrypted_data)?;

    // 秘密鍵の読み込み
    let private_key_pem = fs::read_to_string(private_key_path)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)?;

    // 先頭からNonce（12バイト）を取得
    let nonce = extract_nonce(&encrypted_data)?;

    // RSAで暗号化されたAES鍵のサイズを取得
    let key_size = u16::from_be_bytes([encrypted_data[12], encrypted_data[13]]) as usize;
    let encrypted_key = &encrypted_data[14..14 + key_size];

    // AES鍵の復号
    let aes_key_bytes = private_key.decrypt(Pkcs1v15Encrypt, encrypted_key)?;
    let aes_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&aes_key_bytes);

    // 残りの部分がAES-GCMで暗号化されたZIPデータ
    let encrypted_zip = &encrypted_data[14 + key_size..];

    // AES-GCMで復号
    let cipher = Aes256Gcm::new_from_slice(&aes_key)?;
    let decrypted_zip = cipher.decrypt(&nonce, encrypted_zip)
        .map_err(|e| anyhow!("Decyption failed: {}", e.to_string()))?;

    Ok(decrypted_zip)
}

/// 暗号化されたデータから、最初の12バイトをNonceとして取得します.
///
/// # Arguments
///
/// * `encrypted_data` - 暗号化されたデータのバイトスライス。
///
/// # Errors
///
/// データの長さが12バイト未満の場合にエラーを返します。
fn extract_nonce(encrypted_data: &[u8]) -> Result<Nonce<U12>> {
    let nonce_slice = encrypted_data
        .get(0..12)
        .ok_or_else(|| anyhow!("暗号化データが短すぎます。Nonceを取得できません。"))?;
    Ok(Nonce::<U12>::clone_from_slice(nonce_slice))
}

/// 指定されたパスの拡張子が、定数 EXTENTION で指定された文字列と一致するかをチェックします.
///
/// # Arguments
///
/// * `check_path` - 拡張子を検証する対象のパス。
///
/// # Returns
///
/// 拡張子が一致すれば Ok(true)、一致しなければ Ok(false) を返します。
fn validate_extension(check_path: &Path) -> Result<bool> {
    let ext = check_path
        .extension()
        .and_then(|ext| ext.to_string_lossy().to_lowercase().into());
    // ここでは to_string_lossy() を利用して安全に文字列変換
    if check_path.extension().and_then(|ext| Some(ext.to_string_lossy().to_string())) != Some(EXTENTION.to_string()) {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// 指定されたパス配下の全てのファイル数を再帰的にカウントして返します.
///
/// # Arguments
///
/// * `path` - カウント対象のディレクトリまたはファイルのパス。
///
/// # Returns
///
/// パス配下に存在する全てのファイル数を返します。ディレクトリの場合は再帰的にカウントします。
///
/// # Errors
///
/// ファイルシステムの読み込みに失敗した場合にエラーを返します。
fn count_files(path: &Path) -> Result<usize> {
    let mut count = 0;
    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() {
            count += 1;
        }
    }
    Ok(count)
}

/// 複数の PathBuf に対して、各パス内のファイル数の総計を返します.
///
/// # Arguments
///
/// * `paths` - カウント対象の複数のパスのスライス。
///
/// # Returns
///
/// 指定された全てのパス内のファイル数の総計を返します。
///
/// # Errors
///
/// いずれかのパスでファイル数のカウントに失敗した場合、エラーを返します。
fn count_files_in_paths(paths: &[PathBuf]) -> Result<usize> {
    let mut total = 0;
    for path in paths {
        total += count_files(path)?;
    }
    Ok(total)
}

/// 指定されたZIPファイル内のファイル数（ディレクトリを除く）をカウントして返します.
///
/// # Arguments
///
/// * `zip_path` - 対象のZIPファイルを指す NamedTempFile への参照。
///
/// # Returns
///
/// ZIPファイル内のファイルの総数を返します。
///
/// # Errors
///
/// ZIPファイルの読み込みに失敗した場合、またはファイルのカウント中にエラーが発生した場合にエラーを返します。
fn count_files_in_zip(zip_path: &NamedTempFile) -> Result<usize> {
    let file = File::open(zip_path)?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader)?;

    let mut count = 0;
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        if !entry.name().ends_with('/') {
            count += 1;
        }
    }
    Ok(count)
}
