#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;
extern crate serde;

use jwt::{encode, decode};
use jwt::header::*;
use jwt::result::*;
use jwt::crypto::mac_signer::MacSigner;


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String
}

// Example validation implementation
impl Claims {
    fn is_valid(self) -> bool {
        if self.company != "ACME".to_owned() {
            return false;
        }
        // expiration etc

        true
    }
}

fn main() {
    let my_claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned()
    };
    let signer = MacSigner::new("secret".as_bytes()).unwrap();
    let token = match encode(Header::default(), &my_claims, &signer) {
        Ok(t) => t,
        Err(_) => panic!() // in practice you would return the error
    };

    println!("{:?}", token);

    let token_data = match decode::<Claims, MacSigner>(&token, &signer) {
        Ok(c) => c,
        Err(err) => match err {
            JwtError::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!()
        }
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
    println!("{:?}", token_data.claims.is_valid());
}
