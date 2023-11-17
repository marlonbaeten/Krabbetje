use krabbetje::{
    decrypt_string, decrypt_yaml, encrypt_string, encrypt_yaml, is_yaml_path, Error, Result,
    VAULT_NAME,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

fn run(path: &Path) -> Result<String> {
    if !path.exists() {
        return Err(Error::Generic(format!(
            "file not found: {}",
            path.display()
        )));
    }

    let password = rpassword::prompt_password("Secret: ").unwrap();
    let input: String = fs::read_to_string(path)?;

    if input.starts_with(VAULT_NAME) {
        if is_yaml_path(path) {
            decrypt_yaml(&input, &password)
        } else {
            decrypt_string(&input, &password)
        }
    } else if is_yaml_path(path) {
        encrypt_yaml(&input, &password)
    } else {
        encrypt_string(&input, &password)
    }
}

fn main() {
    if let Some(path) = env::args()
        .nth(1)
        .and_then(|path| PathBuf::try_from(path).ok())
    {
        match run(&path) {
            Ok(value) => println!("{}", value),
            Err(e) => {
                eprintln!("{e}");
                
                process::exit(1);
            }
        }
    } else {
        eprintln!(
            "Krabbetje wil automatically detect if the provided file is a \
            krabbetje vault and either encrypt or decrypt its contents \
            accordingly and print the result to stdout"
        );
        eprintln!("Usage:");
        eprintln!("krabbetje <file>");
        eprintln!("krabbetje <file> > <target_file>");

        process::exit(1);
    }
}
