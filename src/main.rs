use std::{
    fs,
    io::{Write, stdout, stdin},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use otpauth::TOTP;
use serde::{Serialize, Deserialize};
use crossterm::{execute, terminal::{Clear, ClearType}};

#[derive(Serialize, Deserialize)]
struct Account {
    name: String,
    issuer: String,
    secret: String,
}

fn load_accounts() -> Vec<Account> {
    fs::read_to_string("accounts.json")
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(Vec::new)
}

fn main() {
    loop {
        println!("Welcome to MPass Authenticator");
        println!("1. View TOTP Codes");
        println!("2. Add Account");
        print!("Enter your choice: ");
        stdout().flush().unwrap();

        let mut input = String::new();
        stdin().read_line(&mut input).expect("Failed to read input");
        let choice: i32 = input.trim().parse().unwrap_or(0);

        let mut accounts = load_accounts();

        if choice == 1 {
            if accounts.is_empty() {
                println!("No accounts found. Please add accounts to accounts.json");
                continue;
            }

            loop {
                execute!(stdout(), Clear(ClearType::All)).unwrap();
                println!("Welcome to MPass Authenticator");

                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
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
        } else if choice == 2 {
            let mut name = String::new();
            let mut issuer = String::new();
            let mut secret = String::new();

            print!("Enter account name: ");
            stdout().flush().unwrap();
            stdin().read_line(&mut name).expect("Failed to read input");

            print!("Enter issuer: ");
            stdout().flush().unwrap();
            stdin().read_line(&mut issuer).expect("Failed to read input");

            print!("Enter Base32 secret: ");
            stdout().flush().unwrap();
            stdin().read_line(&mut secret).expect("Failed to read input");

            accounts.push(Account {
                name: name.trim().to_string(),
                issuer: issuer.trim().to_string(),
                secret: secret.trim().to_string(),
            });

            fs::write("accounts.json", serde_json::to_string_pretty(&accounts).unwrap())
                .expect("Failed to write accounts");
        }
    }
}
