// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use std::{
    fs,
    io::{stdin, stdout, Write},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use crossterm::{
    execute,
    terminal::{Clear, ClearType},
};
use otpauth::TOTP;
use rand_core::RngCore;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use reqwest::{multipart, StatusCode};

#[derive(Serialize, Deserialize)]
struct Account {
    name: String,
    issuer: String,
    secret: String,
}

fn file_path(filename: &str) -> Result<String, String> {
    let app_data = std::env::var("APPDATA").map_err(|_| "Could not find APPDATA".to_string())?;
    let file_path = format!("{}\\mpass_data\\{}.enc", app_data, filename);
    Ok(file_path)
}

fn check_path() -> Result<(), String> {
    let app_data = std::env::var("APPDATA").map_err(|_| "Could not find APPDATA".to_string())?;
    let folder_path = format!("{}\\mpass_data\\", app_data);

    if !std::path::Path::new(&folder_path).exists() {
        fs::create_dir_all(&folder_path).map_err(|e| format!("Couldn't create directory: {}", e))?;
        println!("Directory created at {}", folder_path);
    }
    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    Ok(key)
}

fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if data.len() < 12 {
        return Err("Encrypted data too short".into());
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = &data[..12];
    let ciphertext = &data[12..];

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

// --- COMMANDS ---

#[tauri::command]
async fn register(mail: &str, password: &str) -> Result<String, String> {
    if mail.is_empty() || password.is_empty() {
        return Err("Email and password cannot be empty".to_string());
    }
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }

    check_path()?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let safe_filename = mail.replace(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-', "_");
    
    let server_filename = format!("{}.enc", mail);

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt).map_err(|_| "Failed to derive key".to_string())?;

    let empty_accounts: Vec<Account> = Vec::new();
    let data = serde_json::to_vec(&empty_accounts).map_err(|e| format!("Serialization failed: {}", e))?;
    
    let encrypted_data = encrypt_data(&data, &key).map_err(|e| format!("Encryption failed: {}", e))?;

    let mut file_content = salt.to_vec();
    file_content.extend_from_slice(&encrypted_data);
    
    let local_path = file_path(&safe_filename)?;
    fs::write(&local_path, &file_content).map_err(|e| format!("Failed to write local file: {}", e))?;

    let form = multipart::Form::new()
        .part("file", multipart::Part::bytes(file_content).file_name(server_filename));

    let res = client.post("https://localhost:3000/register")
        .multipart(form)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = res.status();
    if status == reqwest::StatusCode::CONFLICT {
        Err("User with this email already exists".to_string())
    } else if status.is_success() {
        Ok(format!("Registration successful for {}", mail))
    } else {
        let error_text = res.text().await.unwrap_or_default();
        Err(format!("Server returned error {}: {}", status, error_text))
    }
}

#[tauri::command]
async fn login(mail: String, password: String) -> Result<String, String> {
    
    check_path()?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;

    println!("Attempting login for: {}", mail);

    let target_file_server = format!("{}.enc", mail); 
    
    let res = client.get("https://localhost:3000/login")
        .query(&[("mail", &target_file_server)])
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if res.status() == StatusCode::NOT_FOUND {
        return Err("User does not exist on server".to_string());
    }
    if !res.status().is_success() {
        return Err(format!("Server error: {}", res.status()));
    }

    let file_content = res.bytes()
        .await
        .map_err(|e| "Failed to read file body".to_string())?;
    
    if file_content.len() < 16 {
        return Err("Corrupted file (too short)".to_string());
    }

    let salt = &file_content[..16];
    let encrypted_data = &file_content[16..];

    let key = derive_key(&password, salt).map_err(|_| "Key derivation failed".to_string())?;
    let decrypted_data = decrypt_data(encrypted_data, &key).map_err(|_| "Invalid Password".to_string())?;

    let accounts_json = String::from_utf8(decrypted_data)
        .map_err(|_| "Decrypted data is not valid text".to_string())?;
    
    let account_count: Vec<Account> = serde_json::from_str(&accounts_json).unwrap_or_default();

    let safe_filename = mail.replace(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-', "_");
    let local_path = file_path(&safe_filename)?;

    println!("Saving synced data to: {}", local_path);
    fs::write(&local_path, &file_content).map_err(|e| format!("Failed to save local file: {}", e))?;

    println!("Login Successful! Data saved locally.");
    Ok(format!("Welcome back! Found {} accounts.", account_count.len()))
}

#[tauri::command]
fn show_accounts(mail: &str, password: &str) -> Result<Vec<(String, String, String)>, String> {
    let safe_filename = mail.replace(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-', "_");
    
    check_path()?; 
    let local_path = file_path(&safe_filename)?;

    println!("Reading from: {}", local_path);
    let file_content = fs::read(&local_path)
        .map_err(|_| "Account data not found on disk. Please login first.".to_string())?;

    if file_content.len() < 16 {
         return Err("File corrupted: too short".to_string());
    }

    let salt = &file_content[..16];
    let encrypted_data = &file_content[16..];

    let key = derive_key(password, salt)
        .map_err(|_| "Failed to derive key".to_string())?;

    let decrypted_data = decrypt_data(&encrypted_data, &key).map_err(|_| "Invalid password".to_string())?;
    
    let accounts: Vec<Account> =
        serde_json::from_slice(&decrypted_data)
            .map_err(|e| format!("Corrupted account data: {}", e))?;

    let mut result = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Time error: {}", e))?
        .as_secs();

    for account in accounts {
        if let Some(totp) = TOTP::from_base32(&account.secret) {
            let code = totp.generate(30, now);
            let code_str = format!("{:06}", code);
            result.push((account.name, account.issuer, code_str));
        } else {
            println!("Skipping account {} due to invalid secret", account.name);
        }
    }
    
    Ok(result)
}

#[tauri::command]
async fn add_account(mail: &str, password: &str, name: &str, issuer: &str, secret: &str) -> Result<String, String> {
    if TOTP::from_base32(secret).is_none() {
        return Err("Invalid Base32 secret key".to_string());
    }

    check_path()?;

    let safe_filename = mail.replace(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-', "_");
    let local_path = file_path(&safe_filename)?;

    let (mut accounts, salt, key) = if std::path::Path::new(&local_path).exists() {
        let file_content = fs::read(&local_path).map_err(|e| format!("Read failed: {}", e))?;
        if file_content.len() < 16 { return Err("File corrupted".to_string()); }

        let salt = file_content[..16].to_vec();
        let key = derive_key(password, &salt).map_err(|_| "Key derivation failed".to_string())?;
        
        let encrypted = &file_content[16..];
        let decrypted = decrypt_data(encrypted, &key).map_err(|_| "Invalid password".to_string())?;
        let accs: Vec<Account> = serde_json::from_slice(&decrypted).unwrap_or_default();
        
        (accs, salt, key)
    } else {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(password, &salt).map_err(|_| "Key failed".to_string())?;
        (Vec::new(), salt.to_vec(), key)
    };

    accounts.push(Account {
        name: name.to_string(),
        issuer: issuer.to_string(),
        secret: secret.to_string(),
    });

    let data = serde_json::to_vec(&accounts).map_err(|e| e.to_string())?;
    let new_encrypted_data = encrypt_data(&data, &key).map_err(|e| e.to_string())?;
    
    let mut final_content = salt;
    final_content.extend_from_slice(&new_encrypted_data);
    let server_filename = format!("{}.enc", mail);
    
    fs::write(&local_path, &final_content).map_err(|e| e.to_string())?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let form = multipart::Form::new()
        .part("file", multipart::Part::bytes(final_content).file_name(server_filename));

    let res = client.post("https://localhost:3000/add")
        .multipart(form)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = res.status();

    if status.is_success() {
        Ok(format!("Account added to server."))
    } else {
        Ok("Account added locally".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![register, login, show_accounts, add_account]) 
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}