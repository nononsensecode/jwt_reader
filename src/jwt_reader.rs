// Import necessary items from the base64 crate, including the Engine trait and the specific engine configuration.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _; // Import the Engine trait itself to use its methods like `decode`.
use serde_json::{from_str, to_string_pretty, Value};
use std::env;
use std::error::Error;
use std::fmt;

// Define a custom error type for better error handling
#[derive(Debug)]
enum JwtError {
    InvalidTokenFormat(String),
    Base64DecodeError(base64::DecodeError),
    JsonParseError(serde_json::Error),
    Utf8Error(std::string::FromUtf8Error),
}

// Implement Display trait for JwtError to allow easy printing
impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JwtError::InvalidTokenFormat(msg) => write!(f, "Invalid JWT format: {}", msg),
            JwtError::Base64DecodeError(e) => write!(f, "Base64 decoding error: {}", e),
            JwtError::JsonParseError(e) => write!(f, "JSON parsing error: {}", e),
            JwtError::Utf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
        }
    }
}

// Implement Error trait for JwtError
impl Error for JwtError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            JwtError::Base64DecodeError(e) => Some(e),
            JwtError::JsonParseError(e) => Some(e),
            JwtError::Utf8Error(e) => Some(e),
            _ => None,
        }
    }
}

// Conversion from underlying errors to JwtError
impl From<base64::DecodeError> for JwtError {
    fn from(err: base64::DecodeError) -> JwtError {
        JwtError::Base64DecodeError(err)
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(err: serde_json::Error) -> JwtError {
        JwtError::JsonParseError(err)
    }
}

impl From<std::string::FromUtf8Error> for JwtError {
    fn from(err: std::string::FromUtf8Error) -> JwtError {
        JwtError::Utf8Error(err)
    }
}

/// Decodes the payload of a JWT string and returns it as a pretty-printed JSON string.
///
/// # Arguments
/// * `token_str` - A string slice representing the JWT.
///
/// # Returns
/// A `Result` containing the pretty-printed JSON payload string or a `JwtError`.
///
/// # Remarks
/// This function does NOT verify the JWT's signature.
fn decode_jwt_payload(token_str: &str) -> Result<String, JwtError> {
    // A JWT typically consists of three parts separated by dots: header.payload.signature
    let parts: Vec<&str> = token_str.split('.').collect();

    // We need at least two parts (header and payload) to extract the payload.
    if parts.len() < 2 {
        return Err(JwtError::InvalidTokenFormat(
            "Token does not contain enough parts.".to_string(),
        ));
    }

    let payload_encoded = parts[1];

    // Decode the payload from Base64 URL Safe format using the engine
    // The `URL_SAFE_NO_PAD` engine is used here.
    let payload_decoded_bytes = URL_SAFE_NO_PAD.decode(payload_encoded)?;

    // Convert the decoded bytes to a UTF-8 string
    let payload_json_str = String::from_utf8(payload_decoded_bytes)?;

    // Parse the JSON string into a serde_json::Value for validation and pretty-printing
    let payload_value: Value = from_str(&payload_json_str)?;

    // Convert the serde_json::Value to a pretty-printed JSON string
    let pretty_payload = to_string_pretty(&payload_value)?;

    Ok(pretty_payload)
}

fn main() {
    // Get the JWT from command line arguments or use a default example
    let args: Vec<String> = env::args().collect();
    let token_to_decode: String;

    if args.len() > 1 {
        token_to_decode = args[1].clone();
    } else {
        println!("No JWT provided as a command-line argument.");
        println!("Usage: jwt_reader \"<YOUR_JWT_TOKEN_STRING>\"");
        println!("\nUsing a default example JWT (unsigned):");
        // Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 (header: {"alg":"HS256","typ":"JWT"})
        // .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZSwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSJ9 (payload: {"sub":"1234567890","name":"John Doe","iat":1516239022,"admin":true,"email":"john.doe@example.com"})
        // .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c (signature - not verified by this program)
        token_to_decode = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZSwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_string();
        println!("Default JWT: {}", token_to_decode);
    }

    match decode_jwt_payload(&token_to_decode) {
        Ok(payload) => {
            println!("{}", payload);
        }
        Err(e) => {
            eprintln!("\nError decoding JWT: {}", e);
            if let Some(source) = e.source() {
                eprintln!("Caused by: {}", source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_jwt_payload_decoding() {
        // A common example JWT.
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = decode_jwt_payload(token);
        assert!(result.is_ok());
        let payload_json = result.unwrap();
        // Using contains to avoid issues with exact spacing/newline differences in pretty print
        assert!(payload_json.contains("\"sub\": \"1234567890\""));
        assert!(payload_json.contains("\"name\": \"John Doe\""));
        assert!(payload_json.contains("\"iat\": 1516239022"));
    }

    #[test]
    fn test_jwt_with_different_payload() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJhY2Nlc3MiOiJ1c2VyIiwiZXhwIjoxNzAxNTAyNDAwfQ.signature"; // Example token, signature part is irrelevant for payload decoding
        let result = decode_jwt_payload(token);
        assert!(result.is_ok());
        let payload_json = result.unwrap();
        assert!(payload_json.contains("\"access\": \"user\""));
        assert!(payload_json.contains("\"exp\": 1701502400"));
    }

    #[test]
    fn test_invalid_token_format_too_few_parts() {
        let token = "invalidtoken";
        let result = decode_jwt_payload(token);
        assert!(result.is_err());
        match result.err().unwrap() {
            JwtError::InvalidTokenFormat(_) => {} // Expected error
            _ => panic!("Wrong error type for too few parts"),
        }
    }

    #[test]
    fn test_invalid_base64_payload() {
        // The payload part "payload*with*invalid*chars" contains invalid Base64 characters.
        let token = "header.payload*with*invalid*chars.signature";
        let result = decode_jwt_payload(token);
        assert!(result.is_err());
        match result.err().unwrap() {
            JwtError::Base64DecodeError(_) => {} // Expected error
            _ => panic!("Wrong error type for invalid base64 payload"),
        }
    }

    #[test]
    fn test_payload_not_json() {
        // Payload "not json" base64 encoded is "bm90IGpzb24="
        let token = "eyJhbGciOiJIUzI1NiJ9.bm90IGpzb24.c2lnbmF0dXJl";
        let result = decode_jwt_payload(token);
        assert!(result.is_err());
        match result.err().unwrap() {
            JwtError::JsonParseError(_) => {} // Expected error
            _ => panic!("Wrong error type for non-JSON payload"),
        }
    }
}
