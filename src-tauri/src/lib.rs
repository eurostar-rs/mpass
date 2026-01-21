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

#[derive(Serialize, Deserialize)]
struct Account {
    name: String,
    issuer: String,
    secret: String,
}

fn file_path(filename: &str) -> Result<String, String> {
    let app_data = std::env::var("APPDATA").expect("error");
    // let filename = format!("{}.enc", filename);

    let file_path = app_data + "\\mpass_data\\" + filename + ".enc";

    println!("{}", file_path);
    Ok(file_path)

}

fn check_path() {
    let app_data = std::env::var("APPDATA").expect("error");

    let folder_path = app_data + "\\mpass_data\\";

    if (std::path::Path::new(&folder_path).exists()) {
        ;
    }

    else {
        match fs::create_dir(folder_path) {
            Ok(_) => println!("Directory created"),
            Err(e) => println!("Couldn't create directory: {}", e)
        };
    }    
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

#[tauri::command]
fn register(mail: &str, password: &str) -> Result<String, String> {
    if mail.is_empty() || password.is_empty() {
        return Err("Email and password cannot be empty".to_string());
    }
    
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }

    check_path();

    let filename = mail.replace(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-', "_");
    let filename_result = file_path(filename.as_str());

    let filename: String = match filename_result {
        Ok(s) => s,
        Err(e) => {
            e
        }
    };
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)
        .map_err(|_| "Failed to derive key".to_string())?;

    if std::path::Path::new(&filename).exists() {
        return Err("User with this email already exists".to_string());
    }

    let empty_accounts: Vec<Account> = Vec::new();
    let data = serde_json::to_vec(&empty_accounts)
        .map_err(|e| format!("Serialization failed: {}", e))?;
    
    let encrypted_data = encrypt_data(&data, &key)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut file_content = salt.to_vec();
    file_content.extend_from_slice(&encrypted_data);
    
    fs::write(&filename, file_content)
        .map_err(|e| format!("File write failed: {}", e))?;
    
    Ok(format!("Registration successful for {}", mail))
}

#[tauri::command]
fn login(mail: &str, password: &str) -> Result<String, String> {
    if mail.is_empty() || password.is_empty() {
        return Err("Email and password cannot be empty".to_string());
    }

    check_path();

    let filename = mail.replace(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-', "_");
    let filename_result = file_path(filename.as_str());

    let filename: String = match filename_result {
        Ok(s) => s,
        Err(e) => {
            e
        }
    };

    if !std::path::Path::new(&filename).exists() {
        return Err("User not found".to_string());
    }

    let file_content = fs::read(&filename)
        .map_err(|e| format!("Failed to read user data: {}", e))?;

    if file_content.len() < 16 {
        return Err("File corrupted".to_string());
    }

    let salt = &file_content[..16];
    let encrypted_data = &file_content[16..];

    let key = derive_key(password, salt)
        .map_err(|_| "Failed to derive key".to_string())?;
    
    let decrypted_data = decrypt_data(&encrypted_data, &key)
        .map_err(|_| "Invalid password".to_string())?;

    Ok(format!("Welcome back, {}!", mail))
}

#[tauri::command]
fn show_accounts(mail: &str, password: &str) -> Result<Vec<(String, String, String)>, String> {
    let filename = mail.replace(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-', "_");
    let filename_result = file_path(filename.as_str());

    let filename: String = match filename_result {
        Ok(s) => s,
        Err(e) => {
            e
        }
    };

    let file_content = fs::read(&filename)
        .map_err(|e| format!("Failed to read user data: {}", e))?;

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
    for account in accounts {
        let totp = TOTP::from_base32(&account.secret)
            .ok_or("Invalid secret format found".to_string())?;
        
        // Generate TOTP with current time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Time error: {}", e))?
            .as_secs();
        
        // The second parameter (30) is the step/period, third is digits (6)
        let code = totp.generate(30, now);
        
        // Format as 6-digit string with leading zeros
        let code_str = format!("{:06}", code);

        println!("CODE: {:?}", code);
        
        result.push((account.name, account.issuer, code_str));
    }
    
    Ok(result)
}

#[tauri::command]
fn add_account(mail: &str, password: &str, name: &str, issuer: &str, secret: &str) -> Result<String, String> {
    // 1. Validate Secret (Check if it is valid Base32)
    // If the secret is bad, we stop right here.
    if TOTP::from_base32(secret).is_none() {
        return Err("Invalid Base32 secret key".to_string());
    }

    let filename = mail.replace(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-', "_");
    let filename_result = file_path(filename.as_str());

    let filename: String = match filename_result {
        Ok(s) => s,
        Err(e) => {
            e
        }
    };

    let file_content = fs::read(&filename)
        .map_err(|e| format!("Failed to read user data: {}", e))?;

    if file_content.len() < 16 {
         return Err("File corrupted: too short".to_string());
    }

    // 2. EXTRACT SALT (First 16 bytes)
    let salt = &file_content[..16];
    let key = derive_key(password, salt)
        .map_err(|_| "Failed to derive key".to_string())?;


    let mut accounts: Vec<Account> = if std::path::Path::new(&filename).exists() {
        let result = (|| -> Result<Vec<Account>, String> {
            let encrypted_data = &file_content[16..];            
            // If file is empty (0 bytes), return empty list immediately
            if encrypted_data.is_empty() { return Ok(Vec::new()); }

            let decrypted_data = decrypt_data(&encrypted_data, &key).map_err(|_| "Decryption failed".to_string())?;
            let parsed: Vec<Account> = serde_json::from_slice(&decrypted_data).map_err(|e| e.to_string())?;
            Ok(parsed)
        })();

        match result {
            Ok(accs) => accs,
            Err(_) => Vec::new(), // Fallback: Start fresh if data is bad/empty
        }
    } else {
        Vec::new()
    };

    // 3. Add the new account
    accounts.push(Account {
        name: name.to_string(),
        issuer: issuer.to_string(),
        secret: secret.to_string(),
    });

    // 4. Encrypt and Save back
    let data = serde_json::to_vec(&accounts).map_err(|e| e.to_string())?;
    let new_encrypted_data = encrypt_data(&data, &key).map_err(|e| e.to_string())?;
    
    fs::write(&filename, new_encrypted_data).map_err(|e| e.to_string())?;

    Ok("Account added successfully".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // IMPORTANT: Add show_accounts to the list below
        .invoke_handler(tauri::generate_handler![register, login, show_accounts, add_account]) 
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}