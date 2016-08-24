use std::result;
use std::io;
use std::string;
use std::fmt;

use serde_json;
use rustc_serialize;
use openssl;
use chrono;
use cast;
use validation::*;

use algorithm::Algorithm;

quick_error! {
    #[derive(Debug)]
    pub enum JwtError {
        IoError(err: io::Error) {
            from()
            description("io error")
            display("I/O error: {}", err)
            cause(err.get_ref().unwrap())
        }
        
        JsonError(err: serde_json::Error) {
            from()
            description("json error")
            display("Json error: {}", err)
            cause(err)
        }
        
        Utf8Error(err: string::FromUtf8Error) {
            from()
            description("utf8 error")
            display("utf8 error: {}", err)
            cause(err)
        }
        
        AppError(s: String) {
            description("error")
            display("error: {}", s)
        }
        
        IllegalStateError(s: String) {
            description("illegal state error")
            display("illegal state error: {}", s)
        }
        
        AlgorithmNotSupported(a: Algorithm) {
            description("algorithm not supported")
            display("algorithm not supported: {:?}", a)
        }
        
        InvalidAlgorithm(msg: String, a: Algorithm) {
            description("selected algorithm is inappropriate")
            display("selected algorithm is inappropriate: {}: {}", msg, a)
        }
        
        SecretTooShort {
            description("secret is too short")
            display("secret it too short")
        }
        
        KeyLengthError(s: String) {
            description("key length error")
            display("key length error: {}", s)
        }
        
        BadArgument(s: String) {
            description("bad argument")
            display("bad argument: {}", s)
        }
        
        FromBase64Error(e: rustc_serialize::base64::FromBase64Error) {
            from()
            description("base64 deserialization error")
            display("base64 deserialization error: {}", e)
            cause(e)
        }
        
        MissingKeyParam(s: String) {
            description("missing key param")
            display("missing key param: {}", s)
        }
        
        InvalidKeyParam(s: String) {
            description("invalid key param")
            display("invalid key param: {}", s)
        }
        
        SslError(e: openssl::error::Error) {
            from()
            description("ssl error")
            display("ssl error: {}", e)
            cause(e)
        }

        SslAggregateError(e: openssl::error::ErrorStack) {
            from()
            description("ssl aggregate error")
            display("ssl aggregate error: {}", e)
            cause(e)
        }
        
        InvalidSignature {
            description("invalid signature")
            display("Invalid signature")
        }
        
        InvalidToken {
            description("invalid token")
            display("Invalid token")
        }
        
        WrongAlgorithmHeader {
            description("wrong algorithm header")
            display("Wrong algorithm header")
        }
        
        InvalidClaim(msg: String) {
            description("invalid claim")
            display("invalid claim: {}", msg)
        }
        
        DateTimeParseError(e: chrono::ParseError) {
            from()
            description("datetime parse error")
            display("datetime parse error: {}", e)
            cause(e)
        }
        
        NumericConversionError(e: cast::Error) {
            from()
            description("numeric conversion error")
            display("numeric conversion error: {:?}", e)
        }
        
        ValidationError(e: ValidationError) {
            from()
            description("validation error")
            display("validation error: {}", e)
            cause(e)
        }
    }
}

pub type JwtResult<T> = result::Result<T, JwtError>;

impl From<JwtError> for fmt::Error {
    fn from(err: JwtError) -> fmt::Error {
        info!("string formatting error: {}", err);
        
        fmt::Error
    }
}
