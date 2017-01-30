
extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;

use jwt::{encode, decode};
use jwt::header::*;
use jwt::algorithm::*;
use jwt::result::*;
use jwt::crypto::mac_signer::MacSigner;


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String
}

fn main() {
    let my_claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned()
    };
    let signer = MacSigner::new("secret".as_bytes()).unwrap();

    let mut header = Header::default();
    header.kid = Some("signing_key".to_owned());
    header.alg = Algorithm::HS512;

    let token = match encode(header, &my_claims, &signer) {
        Ok(t) => t,
        Err(_) => panic!() // in practice you would return the error
    };

    let token_data = match decode::<Claims, MacSigner>(&token, &signer) {
        Ok(c) => c,
        Err(err) => match err {
            JwtError::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!()
        }
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}
