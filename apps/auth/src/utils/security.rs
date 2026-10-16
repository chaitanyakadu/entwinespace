use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, OsRng},
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{Error as Argon2PasswordError, SaltString},
};
use hex::ToHex;
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::Error as JWTError,
};
use crate::schema::security::{AccessClaims, AccessTokenState, JWTClaims};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tracing::debug;

/// Generates a SHA-256 hash of the input string and returns it as a
/// lowercase hexadecimal string.
///
/// # Arguments
///
/// * `data` - The input string to hash.
///
/// # Returns
///
/// A lowercase hexadecimal representation of the SHA-256 digest.
pub fn generate_sha2_hash(data: &str) -> String {
    debug!("generate hash using sha256");
    let hash = Sha256::digest(data);
    hash.encode_hex()
}

/// Generates the password hash using argon2
/// returns a Result<String, Argon2PasswordError>
///
/// incase of confusion
/// argon2 uses password-centric terminology
/// password here is synonym to data
pub fn generate_argon_hash(password: &str) -> Result<String, Argon2PasswordError> {
    debug!("generate hash using argon2");
    let salt = SaltString::generate(&mut OsRng);
    let password: &[u8] = password.as_bytes();
    match Argon2::default().hash_password(password, &salt) {
        Ok(v) => Ok(v.to_string()),
        Err(e) => {
            debug!(
                error = ?e,
                "error occured while generating hash using argon2"
            );
            Err(e)
        }
    }
}

/// Verifies the password hash using argon2
/// returns a Result<bool, Argon2PasswordError>
///
/// incase of confusion
/// argon2 uses password-centric terminology
/// password here is synonym to data
pub fn verify_argon_hash(password: &[u8], hash: &str) -> Result<bool, Argon2PasswordError> {
    debug!("verify the argon2 password hash");
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok())
}

/// Symmetric encryption
/// uses AES-GCM with a 256-bit key and 96-bit nonce
pub fn sym_encryption(data: &str, secret: &str) -> anyhow::Result<Vec<u8>> {
    debug!("symmetric encryption of data");
    let cipher = Aes256Gcm::new_from_slice(secret.as_bytes())?;
    let nonce: [u8; 12] = rand::random();
    let mut output = nonce.to_vec();
    let ciphertext = cipher.encrypt((&nonce).into(), data.as_bytes()).unwrap();
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Symmetric decryption
pub fn sym_decryption(secret: &str, mut data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    debug!("symmetric decryption of data");
    let cipher = Aes256Gcm::new(secret.as_bytes().into());
    let ciphertext = data.split_off(12);
    let nonce: [u8; 12] = data
        .try_into()
        .map_err(|e| {
            debug!(
                error = ?e,
                "failed to convert the data of type Vec<u8> into [u8; 12]"
            );
            e
        })
        .unwrap();

    Ok(cipher.decrypt(&nonce.into(), ciphertext.as_ref()).unwrap())
}

/// Encode the header and claims given
/// and sign the payload using
/// the HS256 algorithm from the header and the key
pub fn generate_jwt(claims: JWTClaims, secret: &str, header: Header) -> Result<String, JWTError> {
    debug!("creating a jsonwebtoken");
    let key = EncodingKey::from_secret(secret.as_bytes());
    let result = encode(&header, &claims, &key)?;
    Ok(result)
}

/// Decode the JWT token
pub fn decode_jwt(token: &str, secret: &str) -> Result<TokenData<JWTClaims>, JWTError> {
    debug!("decode a jsonwebtoken");
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let result = decode(token, &decoding_key, &validation)?;
    Ok(result)
}

/// Get username from jwt access token
pub fn decode_jwt_for_username(token: &str, secret: &str) -> Result<String, JWTError> {
    debug!("decode a jsonwebtoken using username");
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let token_data = decode::<JWTClaims>(token, &decoding_key, &validation).map_err(|e| {
        debug!(
            error = ?e,
            "failed to decode the jsonwebtoken"
        );
        e
    })?;

    match token_data.claims {
        JWTClaims::AccessToken(t) => Ok(t.username),
    }
}

/// Verify the access jwt token
/// returns AccessTokenState
pub fn verify_access_token(token: &str, secret: &str) -> AccessTokenState {
    debug!("verify the access token");
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let token_data = decode::<AccessClaims>(token, &decoding_key, &validation);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    match token_data {
        Err(e) => {
            debug!(
                error = ?e,
                token = ?token,
                "failed to decode the jsonwebtoken"
            );
            AccessTokenState::Invalid
        }
        Ok(v) => {
            if v.claims.exp <= now  {
                AccessTokenState::Expired
            } else {
                AccessTokenState::Valid
            }
        }
    }
}
