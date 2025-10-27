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

fn login(password: &str) -> [u8; 32] {
    let salt = b"saltpassword12";
    let key = match derive_key(password, salt) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("Failed to derive key");
            std::process::exit(1);
        }
    };

    if !std::path::Path::new("accounts.enc").exists() {
        let empty_accounts: Vec<Account> = Vec::new();
        let data = serde_json::to_vec(&empty_accounts).unwrap();
        let encrypted_data = encrypt_data(&data, &key).unwrap();
        fs::write("accounts.enc", encrypted_data).unwrap();
        println!("Created new encrypted storage file.");
        return key;
    }

    let encrypted_data = match fs::read("accounts.enc") {
        Ok(data) => data,
        Err(_) => {
            eprintln!("Failed to read encrypted data");
            std::process::exit(1);
        }
    };

    match decrypt_data(&encrypted_data, &key) {
        Ok(_) => key,
        Err(_) => {
            println!("Wrong password or corrupted data. Please try again with another password.");
            std::process::exit(1);
        }
    }
}

fn load_accounts(key: &[u8; 32]) -> Vec<Account> {
    if !std::path::Path::new("accounts.enc").exists() {
        return Vec::new();
    }

    let encrypted_data = match fs::read("accounts.enc") {
        Ok(data) => data,
        Err(_) => return Vec::new(),
    };

    let decrypted_data = match decrypt_data(&encrypted_data, &key) {
        Ok(data) => data,
        Err(_) => {
            println!("Wrong password or corrupted data");
            return Vec::new();
        }
    };

    serde_json::from_slice(&decrypted_data).unwrap_or_else(|_| Vec::new())
}

fn save_accounts(key: &[u8; 32], accounts: &[Account]) -> Result<(), Box<dyn std::error::Error>> {
    let data = serde_json::to_vec(accounts)?;
    let encrypted_data = encrypt_data(&data, &key)?;

    fs::write("accounts.enc", encrypted_data)?;
    println!("Accounts saved successfully!");
    Ok(())
}

fn main() {
    let password = prompt_password("Enter password: ").unwrap();
    let key = login(&password);

    let mut accounts = load_accounts(&key);
    loop {
        println!("Welcome to MPass Authenticator");
        println!("1. View TOTP Codes");
        println!("2. Add Account");
        println!("3. Exit");
        print!("Enter your choice: ");
        stdout().flush().unwrap();

        let mut input = String::new();
        stdin().read_line(&mut input).expect("Failed to read input");
        let choice: i32 = input.trim().parse().unwrap_or(0);

        match choice {
            1 => {
                if accounts.is_empty() {
                    println!("No accounts found. Please add accounts first.");
                    continue;
                }

                loop {
                    execute!(stdout(), Clear(ClearType::All)).unwrap();
                    println!("Welcome to MPass Authenticator");

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let seconds_left = 30 - (now % 30);

                    for acc in &accounts {
                        let totp = match TOTP::from_base32(&acc.secret) {
                            Some(t) => t,
                            None => {
                                println!("{} ({}): invalid base32 secret", acc.issuer, acc.name);
                                continue;
                            }
                        };

                        let code = totp.generate(30, now);

                        println!(
                            "{} ({}) - Code: {:06} (valid for {}s)",
                            acc.issuer, acc.name, code, seconds_left
                        );
                    }

                    println!("\nCodes refresh in {} seconds...", seconds_left);
                    thread::sleep(Duration::from_secs(1));
                }
            }
            2 => {
                let mut name = String::new();
                let mut issuer = String::new();
                let mut secret = String::new();

                print!("Enter account name: ");
                stdout().flush().unwrap();
                stdin().read_line(&mut name).expect("Failed to read input");

                print!("Enter issuer: ");
                stdout().flush().unwrap();
                stdin()
                    .read_line(&mut issuer)
                    .expect("Failed to read input");

                print!("Enter Base32 secret: ");
                stdout().flush().unwrap();
                stdin()
                    .read_line(&mut secret)
                    .expect("Failed to read input");

                accounts.push(Account {
                    name: name.trim().to_string(),
                    issuer: issuer.trim().to_string(),
                    secret: secret.trim().to_string(),
                });

                if let Err(e) = save_accounts(&key, &accounts) {
                    println!("Failed to save accounts: {}", e);
                }
            }
            _ => {
                println!("Exiting...");
                std::process::exit(1);
            }
        }
    }
}
