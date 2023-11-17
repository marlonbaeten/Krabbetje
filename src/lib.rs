use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use data_encoding::BASE64URL_NOPAD;
use pbkdf2::pbkdf2_hmac_array;
use rand::RngCore;
use sha2::Sha256;
use std::{ffi::OsStr, fmt, fs, io, path::Path, result};

const PBKDF_ROUNDS: u32 = 4096;

pub const VAULT_NAME: &str = "#KRABBETJE_VAULT";

const VAULT_VERSION: &str = "v1";

type Key = aes_gcm::Key<Aes256Gcm>;

type Salt = [u8; 32];

#[derive(Debug)]
pub enum Error {
    Base64(data_encoding::DecodeError),
    Io(io::Error),
    Generic(String),
    Decrypt(&'static str),
    Encrypt(&'static str),
    InputFormat(&'static str),
    VaultFormat(&'static str),
    Yaml(serde_yaml::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "nicht gut")
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(error: serde_yaml::Error) -> Self {
        Error::Yaml(error)
    }
}

impl From<data_encoding::DecodeError> for Error {
    fn from(error: data_encoding::DecodeError) -> Self {
        Error::Base64(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

pub type Result<T> = result::Result<T, Error>;

/// generate N random bytes
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut salt_bytes: [u8; N] = [0; N];
    OsRng.fill_bytes(&mut salt_bytes);

    salt_bytes
}

/// derive a AES 256 GCM key, using a password as input,
/// the 32 byte salt will be filled with random data when omitted as paramater
fn derive_key(password: &str, salt: Option<Salt>) -> (Key, Salt) {
    let salt: Salt = salt.unwrap_or(random_bytes());
    let key_data = pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), &salt, PBKDF_ROUNDS);

    (Key::from(key_data), salt)
}

/// encrypt a plain text using AES 256 GCM, prepending the nonce and encoding the result using base64 URL encoding
pub fn encrypt(key: &Key, plain_text: &str) -> Result<String> {
    let nonce_bytes: [u8; 12] = random_bytes();

    // encrypt using 16 byte key and 12 byte nonce
    let cipher_text = {
        let nonce = Nonce::from_slice(nonce_bytes.as_ref());
        let cipher = Aes256Gcm::new(key);

        cipher
            .encrypt(nonce, plain_text.as_bytes())
            .map_err(|_| Error::Encrypt("error encrypting the data"))?
    };

    // concatenate nonce and cipher_text
    let value = [nonce_bytes.as_slice(), cipher_text.as_slice()].concat();

    Ok(BASE64URL_NOPAD.encode(&value))
}

/// decrypt a base64 URL encoded cipher text using AES 256 GCM, in which the nonce in prepended
fn decrypt(key: &Key, cipher_text: &str) -> Result<String> {
    let decoded = BASE64URL_NOPAD.decode(cipher_text.as_bytes())?;

    // cipher_text is encoded as 16 bytes password salt + 12 bytes aes nonce + cipher_text bytes
    let (nonce_bytes, cipher_text) = (&decoded[0..12], &decoded[12..]);

    let key = Key::from_slice(key);

    let plaintext = {
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new(key);

        cipher
            .decrypt(nonce, cipher_text.as_ref())
            .map_err(|_| Error::Decrypt("error decrypting the data"))?
    };

    Ok(String::from_utf8_lossy(&plaintext).to_string())
}

/// prepend a krabbetje vault header before a cipher text
fn prepend_header(data: &str, salt: &Salt) -> String {
    let salt_encoded = BASE64URL_NOPAD.encode(salt);

    format!("{VAULT_NAME};{VAULT_VERSION};{salt_encoded}\n{data}")
}

/// parse a krabbetje vault header and extract the salt and result of the cipher_text
fn parse_header(vault_data: &str, password: &str) -> Result<(String, Key)> {
    // first line of the file is a vault header
    let (header, rest) = vault_data
        .split_once('\n')
        .ok_or_else(|| Error::VaultFormat("missing header line"))?;

    // split header into 3 parts (name, version, salt)
    let mut header_split = header.splitn(3, ';');

    // verify vault name
    header_split
        .next()
        .and_then(|name| if name == VAULT_NAME { Some(name) } else { None })
        .ok_or_else(|| Error::VaultFormat("invalid vault name"))?;

    // verify vault version
    header_split
        .next()
        .and_then(|version| {
            if version == VAULT_VERSION {
                Some(version)
            } else {
                None
            }
        })
        .ok_or_else(|| Error::VaultFormat("invalid vault version"))?;

    // extract salt from header
    let salt: Salt = header_split
        .next()
        .and_then(|salt| BASE64URL_NOPAD.decode(salt.as_bytes()).ok())
        .and_then(|salt| salt.try_into().ok())
        .ok_or_else(|| {
            Error::VaultFormat("invalid salt, expected base64 url encoded 32 byte value")
        })?;

    let (key, _) = derive_key(password, Some(salt));

    Ok((rest.to_owned(), key))
}

// encrypt a yaml encoded plain text
// the resulting string will have a vault header containing the key derivation
// salt and the vault name / version i.e. a krabbetje vault
// note that the security is heavily depending on a high entropy password
pub fn encrypt_yaml(yaml: &str, password: &str) -> Result<String> {
    let (key, salt) = derive_key(password, None);
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml)?;

    let new_doc = doc
        .as_mapping()
        .ok_or_else(|| Error::InputFormat("invalid yaml file"))?
        .into_iter()
        .map(|(yaml_key, value)| {
            let formatted = serde_yaml::to_string(&value)?;
            let cipher_text = encrypt(&key, &formatted)?;

            Ok((yaml_key.clone(), serde_yaml::Value::String(cipher_text)))
        })
        .collect::<Result<serde_yaml::Mapping>>()?;

    let yaml = serde_yaml::to_string(&new_doc)?;

    Ok(prepend_header(&yaml, &salt))
}

// decrypt a krabbetje vault into yaml plain text
pub fn decrypt_yaml(vault_data: &str, password: &str) -> Result<String> {
    let (yaml, key) = parse_header(vault_data, password)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml)?;

    let new_doc = doc
        .as_mapping()
        .ok_or_else(|| Error::InputFormat("invalid yaml file decrypted"))?
        .into_iter()
        .map(|(yaml_key, value)| {
            let cipher_text = decrypt(
                &key,
                value
                    .as_str()
                    .ok_or_else(|| Error::VaultFormat("invalid yaml value found"))?,
            )?;
            let formatted: serde_yaml::Value = serde_yaml::from_str(&cipher_text)?;

            Ok((yaml_key.clone(), formatted))
        })
        .collect::<Result<serde_yaml::Mapping>>()?;

    Ok(serde_yaml::to_string(&new_doc)?)
}

/// wrap lines at `line_length` characters
fn truncate(input: &str, line_length: usize) -> String {
    let mut result = String::new();

    for chunk in input.chars().collect::<Vec<char>>().chunks(line_length) {
        result.push_str(chunk.iter().collect::<String>().as_str());
        result.push('\n');
    }

    result
}

// encrypt a plain text as a krabbetje vault
pub fn encrypt_string(plain_text: &str, password: &str) -> Result<String> {
    let (key, salt) = derive_key(password, None);

    Ok(prepend_header(&truncate(&encrypt(&key, plain_text)?, 80), &salt))
}

// decrypt a krabbetje vault into yaml plain text
pub fn decrypt_string(vault_data: &str, password: &str) -> Result<String> {
    let (mut cipher_text, key) = parse_header(vault_data, password)?;

    // remove all newlines and other whitespace
    cipher_text.retain(|c| !c.is_whitespace());

    decrypt(&key, &cipher_text)
}

/// check path has yaml extension
pub fn is_yaml_path(path: &Path) -> bool {
    let ext = path.extension().and_then(OsStr::to_str);

    ext == Some("yaml") || ext == Some("yml")
}

/// read a krabbetje vault file end return decrypted data
pub fn decrypt_file(path: &Path, password: &str) -> Result<String> {
    let vault_data: String = fs::read_to_string(path)?;

    if is_yaml_path(path) {
        decrypt_yaml(&vault_data, password)
    } else {
        decrypt_string(&vault_data, password)
    }
}

/// encrypt data to a krabbetje vault file
pub fn encrypt_file(path: &Path, plain_text: &str, password: &str) -> Result<String> {
    let encoded = if is_yaml_path(path) {
        encrypt_yaml(plain_text, password)
    } else {
        encrypt_string(plain_text, password)
    }?;

    fs::write(path, &encoded)?;

    Ok(encoded)
}

#[cfg(test)]
mod test {
    use crate::{decrypt, decrypt_yaml, derive_key, encrypt, encrypt_yaml, encrypt_string, decrypt_string};

    #[test]
    fn test_encrypt_decrypt() {
        let (key, _) = derive_key("krabbetje", None);
        let plain_text = "Hello, world!".repeat(1);
        let cipher_text = encrypt(&key, &plain_text).unwrap();
        let decrypted = decrypt(&key, &cipher_text).unwrap();

        assert_eq!(plain_text, decrypted);
    }

    #[test]
    fn test_yaml_encrypt_decrypt() {
        let password = "krabbetje";
        let source = indoc::indoc! {"
            production: true
            app_secret: O5OcIMBfPKHzSLir9xJnp0fJKbZUKm
            database_url: postgresql://example:O5OcIMBfPKHzSLir9xJnp0fJKbZUKm@database/example
        "};

        let yaml = encrypt_yaml(&source, &password).unwrap();
        let result = decrypt_yaml(&yaml, &password).unwrap();

        assert_eq!(source, result);
    }

    #[test]
    fn test_string_encrypt_decrypt() {
        let password = "krabbetje";
        let source = indoc::indoc! {"
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer et turpis enim. Vivamus elementum suscipit
            purus, sit amet facilisis neque sodales id. Praesent enim eros, varius eget ullamcorper non, tempus eu
            justo. Integer neque nunc, varius at congue vehicula, pellentesque non ligula. Curabitur eu tincidunt
            tortor, ac tempus libero. In efficitur nulla sit amet tincidunt sodales. Orci varius natoque penatibus
            et magnis dis parturient montes, nascetur ridiculus mus.
            
            Sed fermentum interdum urna et sagittis. Donec efficitur pretium lorem, eu tempor leo scelerisque vitae.
            Fusce facilisis lectus at leo tincidunt sollicitudin. Suspendisse facilisis erat sed mauris tristique,
            ac gravida justo molestie. Vivamus vitae risus volutpat, scelerisque magna non, ultricies nunc. Integer
            ut viverra turpis. Morbi arcu neque, sollicitudin non faucibus sollicitudin, aliquet vitae risus.
            Phasellus bibendum augue vel nulla facilisis, vel congue dolor imperdiet.
        "};

        let cipher_text = encrypt_string(&source, &password).unwrap();
        let result = decrypt_string(&cipher_text, &password).unwrap();

        assert_eq!(source, result);
    }

    #[test]
    fn test_key_derive() {
        let (key, salt) = derive_key("krabbetje", None);
        let (key_new, _) = derive_key("krabbetje", Some(salt));

        assert_eq!(key, key_new);
    }
}
