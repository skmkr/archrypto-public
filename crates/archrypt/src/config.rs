use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{fs, io};
use anyhow::{anyhow, Context, Result};

/// Config は archrypt アプリケーションの設定情報を保持します。
/// 公開鍵および秘密鍵のパスのリストと、各リストにおけるデフォルトのインデックスを管理します。
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// 登録されている公開鍵のパスのリスト
    pub public_keys: Vec<PathBuf>,
    /// public_keys 内でのデフォルト公開鍵のインデックス
    pub default_public_key_index: Option<usize>,
    /// 登録されている秘密鍵のパスのリスト
    pub private_keys: Vec<PathBuf>,
    /// private_keys 内でのデフォルト秘密鍵のインデックス
    pub default_private_key_index: Option<usize>,
}

impl Config {
    /// 設定ファイルのパスを返します。
    ///
    /// 設定ファイルはホームディレクトリの `.archrypt/config.json` にあります。
    ///
    /// # Errors
    ///
    /// ホームディレクトリを取得できなかった場合、エラーを返します。
    pub fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Cannot determine home directory")?;
        Ok(home.join(".archrypt").join("config.json"))
    }

    /// 設定ファイルから設定情報を読み込みます。
    ///
    /// ファイルが存在しない場合は、空の設定（空の鍵リスト、デフォルト未設定）を返します。
    ///
    /// # Errors
    ///
    /// 設定ファイルの読み込みまたはパースに失敗した場合、エラーを返します。
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Config {
                public_keys: Vec::new(),
                default_public_key_index: None,
                private_keys: Vec::new(),
                default_private_key_index: None,
            });
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        let config: Config = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path))?;
        Ok(config)
    }

    /// 現在の設定を設定ファイルに書き出します。
    ///
    /// 必要なディレクトリも作成されます。
    ///
    /// # Errors
    ///
    /// 書き出しに失敗した場合、エラーを返します。
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {:?}", path))?;
        Ok(())
    }

    /// 登録されている全ての公開鍵をクリアし、デフォルトの公開鍵設定をリセットします。
    ///
    /// その後、設定をファイルに保存します。
    ///
    /// # Errors
    ///
    /// 設定の保存に失敗した場合、エラーを返します。
    pub fn clear_public_key(&mut self) -> Result<()> {
        self.public_keys = Vec::new();
        self.default_public_key_index = None;
        self.save()?;
        Ok(())
    }

    /// 登録されている全ての秘密鍵をクリアし、デフォルトの秘密鍵設定をリセットします。
    ///
    /// その後、設定をファイルに保存します。
    ///
    /// # Errors
    ///
    /// 設定の保存に失敗した場合、エラーを返します。
    pub fn clear_private_key(&mut self) -> Result<()> {
        self.private_keys = Vec::new();
        self.default_private_key_index = None;
        self.save()?;
        Ok(())
    }

    /// 指定されたインデックスの公開鍵を削除します。
    ///
    /// 削除したキーがデフォルトの場合、デフォルト設定は解除され、削除したキーより後ろにある場合はインデックスが調整されます。
    ///
    /// # Parameters
    ///
    /// - `index`: 削除する公開鍵のインデックス
    ///
    /// # Errors
    ///
    /// インデックスが無効であるか、設定の保存に失敗した場合、エラーを返します。
    pub fn remove_public_key(&mut self, index: usize) -> Result<()> {
        if index >= self.public_keys.len() {
            return Err(anyhow!(
                "Invalid index: {}. There are only {} public keys registered.",
                index,
                self.public_keys.len()
            ));
        }
        self.public_keys.remove(index);

        if let Some(default_index) = self.default_public_key_index {
            if default_index == index {
                self.default_public_key_index = None;
            } else if default_index > index {
                self.default_public_key_index = Some(default_index - 1);
            }
        }

        self.save()?;
        Ok(())
    }

    /// 指定されたインデックスの秘密鍵を削除します。
    ///
    /// 削除したキーがデフォルトの場合、デフォルト設定は解除され、削除したキーより後ろにある場合はインデックスが調整されます。
    ///
    /// # Parameters
    ///
    /// - `index`: 削除する秘密鍵のインデックス
    ///
    /// # Errors
    ///
    /// インデックスが無効であるか、設定の保存に失敗した場合、エラーを返します。
    pub fn remove_private_key(&mut self, index: usize) -> Result<()> {
        if index >= self.private_keys.len() {
            return Err(anyhow!(
                "Invalid index: {}. There are only {} private keys registered.",
                index,
                self.private_keys.len()
            ));
        }
        self.private_keys.remove(index);

        if let Some(default_index) = self.default_private_key_index {
            if default_index == index {
                self.default_private_key_index = None;
            } else if default_index > index {
                self.default_private_key_index = Some(default_index - 1);
            }
        }

        self.save()?;
        Ok(())
    }

    /// デフォルトの公開鍵への参照を返します。
    ///
    /// デフォルトの公開鍵は `default_public_key_index` に基づいて決定されます。
    pub fn default_public_key(&self) -> Option<&PathBuf> {
        self.default_public_key_index.and_then(|i| self.public_keys.get(i))
    }

    /// デフォルトの秘密鍵への参照を返します。
    ///
    /// デフォルトの秘密鍵は `default_private_key_index` に基づいて決定されます。
    pub fn default_private_key(&self) -> Option<&PathBuf> {
        self.default_private_key_index.and_then(|i| self.private_keys.get(i))
    }
}
