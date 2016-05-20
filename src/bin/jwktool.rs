extern crate openssl;
extern crate rbvt;
extern crate jsonwebtoken;
extern crate serde_json;
extern crate clap;
extern crate rustc_serialize;

use openssl::crypto::rsa::RSA;
use openssl::bn::BigNum;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{Read, Write};
use jsonwebtoken::Part;
use jsonwebtoken::bignum::*;
use jsonwebtoken::json::*;
use jsonwebtoken::jwk::*;
use jsonwebtoken::key_type::*;
use jsonwebtoken::algorithm::*;
use jsonwebtoken::header::Header;
use jsonwebtoken::signer::*;
use jsonwebtoken::verifier::*;
use jsonwebtoken::crypto::rsa::*;
use jsonwebtoken::jwt::*;
use jsonwebtoken::result::*;
use rbvt::state::*;
use rbvt::result::*;
use clap::{Arg, ArgMatches, App, SubCommand};
use rustc_serialize::base64::ToBase64;

pub fn main() {
    // convert public key pem to jwk
    // convert private key pem to jwk?
    // verify signature given public key pem or jwk and signing input + signature in detached, compact jwt or expanded jwt form
    // sign signing input given private key pem. output in either detached, compact jwt, or expanded jwt form
    // create jwk set file from list of public keys
    
    match cli() {
        Err(e) => println!("Error: {}", e),
        _ => ()
    }
}

pub fn cli() -> JwtResult<()> {
    let matches = App::new("rsenv")
        .version("1.0")
        .author("Chris Dawes <cmsd2@cantab.net>")
        .about("Convert pem to jwk and back")
        .subcommand(SubCommand::with_name("convert")
                    .about("Converts pem keys to jwk files and back again")
                    .author("Chris Dawes <cmsd2@cantab.net>")
                    .version("1.0")
                    .arg(Arg::with_name("pem")
                        .short("p")
                        .required(false)
                        .takes_value(true)
                        .help("name of public key pem file to convert")
                        )
                    .arg(Arg::with_name("jwk")
                        .short("j")
                        .required(false)
                        .takes_value(true)
                        .help("name of public or private key jwk file to convert")
                        )
                    .arg(Arg::with_name("format")
                        .short("f")
                        .required(false)
                        .takes_value(true)
                        .help("format of output")
                        )
                    .arg(Arg::with_name("pubout")
                        .long("pubout")
                        .required(false)
                        .takes_value(false)
                        .help("output the public key")
                        )
                    .arg(Arg::with_name("pubin")
                        .long("pubin")
                        .required(false)
                        .takes_value(false)
                        .help("input is a public key")
                        )
                    .arg(Arg::with_name("out")
                        .long("out")
                        .required(false)
                        .takes_value(true)
                        .help("output file name")
                        )
        )
        .subcommand(SubCommand::with_name("sign")
                    .about("Sign input with given private key pem or jwk file")
                    .author("Chris Dawes <cmsd2@cantab.net>")
                    .version("1.0")
                    .arg(Arg::with_name("pem")
                        .short("p")
                        .required(false)
                        .takes_value(true)
                        .help("private key pem file")
                    )
                    .arg(Arg::with_name("jwk")
                        .short("j")
                        .required(false)
                        .takes_value(true)
                        .help("private key jwk file")
                    )
                    .arg(Arg::with_name("msg")
                        .short("m")
                        .required(false)
                        .takes_value(true)
                        .help("message to sign")
                    )
                    .arg(Arg::with_name("alg")
                        .short("a")
                        .required(false)
                        .takes_value(true)
                        .help("algorithm to use for signing (RS256 (default), RS384, RS512))")
                    )
                    .arg(Arg::with_name("format")
                        .short("f")
                        .required(false)
                        .takes_value(true)
                        .help("signed message output format (sig (default), jwt))")
                    )
        )
        .subcommand(SubCommand::with_name("verify")
                    .about("Verify signature with given public key pem or jwk file")
                    .author("Chris Dawes <cmsd2@cantab.net>")
                    .version("1.0")
                    .arg(Arg::with_name("pem")
                        .short("p")
                        .required(false)
                        .takes_value(true)
                        .help("public key pem file")
                    )
                    .arg(Arg::with_name("jwk")
                        .short("j")
                        .required(false)
                        .takes_value(true)
                        .help("public key jwk file")
                    )
                    .arg(Arg::with_name("msg")
                        .short("m")
                        .required(false)
                        .takes_value(true)
                        .help("text that was signed")
                    )
                    .arg(Arg::with_name("sig")
                        .short("s")
                        .required(false)
                        .takes_value(true)
                        .help("detached signature")
                    )
                    .arg(Arg::with_name("jwt")
                        .short("t")
                        .required(false)
                        .takes_value(true)
                        .help("signed json web token in compact form")
                    )
                    .arg(Arg::with_name("alg")
                        .short("a")
                        .required(false)
                        .takes_value(true)
                        .help("algorithm to use for signing (RS256 (default), RS384, RS512))")
                    )
                    .arg(Arg::with_name("format")
                        .short("f")
                        .required(false)
                        .takes_value(true)
                        .help("signed message output format (sig (default), jwt))")
                    )
        )
        .get_matches();
    
    match matches.subcommand() {
        ("convert", Some(sub_matches)) => convert(sub_matches),
        ("sign", Some(sub_matches)) => sign(sub_matches),
        ("verify", Some(sub_matches)) => verify(sub_matches),
        _ => Ok(())
    }
}

pub fn convert(args: &ArgMatches) -> JwtResult<()> {
    let format = args.value_of("format").unwrap_or("jwk");
    
    if let Some(pem) = args.value_of("pem") {
        let rsa: RSA = if args.is_present("pubin") {
            load_public_pem(&PathBuf::from(pem)).unwrap()
        } else {
            load_private_pem(&PathBuf::from(pem)).unwrap()
        };
        
        match format {
            "jwk" => {
                let jwk = if args.is_present("pubin") {
                    convert_public_pem_to_jwk(rsa).unwrap()
                } else {
                    convert_private_pem_to_jwk(rsa).unwrap()
                };
            
                let jwk_json = serde_json::to_string(&jwk).unwrap();
                
                if let Some(outfile) = args.value_of("out") {
                    let mut f = try!(File::create(outfile));
                    try!(f.write(&jwk_json.as_bytes()));
                } else {
                    println!("{}", jwk_json);
                }
            },
            _ => unimplemented!()
        }
    } else if let Some(jwkfile) = args.value_of("jwk") {
        let jwk = load_jwk(&PathBuf::from(jwkfile)).unwrap();
        
        match format {
            "jwk" => {
                let out = format!("{}", try!(serde_json::to_string(&jwk)));
                
                if let Some(outfile) = args.value_of("out") {
                    let mut f = try!(File::create(outfile));
                    try!(f.write(&out.as_bytes()));
                } else {
                    println!("{}", out);
                }
            },
            "pem" => {
                let mut out = vec![];
                
                if jwk.is_private_key() && !args.is_present("pubout") {
                    let rsa = try!(jwk.private_key());
                    
                    try!(rsa.private_key_to_pem(&mut out)); 
                } else {
                    let rsa = try!(jwk.public_key());
                    
                    try!(rsa.public_key_to_pem(&mut out));
                }
                
                if let Some(outfile) = args.value_of("out") {
                    let mut f = try!(File::create(outfile));
                    try!(f.write(&out));
                } else {
                    println!("{}", try!(String::from_utf8(out)));
                }
            },
            _ => {
                unimplemented!()
            }
        }
    } else {
        panic!("missing pem or jwk input to convert");
    }
    
    Ok(())
}

pub fn sign(args: &ArgMatches) -> JwtResult<()> {
    let msg = args.value_of("msg").unwrap_or("");
    let alg: Algorithm = try!(Algorithm::from_str(args.value_of("alg").unwrap_or("RS256")));
    
    let mut jwk = None;
    
    if let Some(pem) = args.value_of("pem") {
        let rsa = try!(load_private_pem(&PathBuf::from(pem)));
        
        jwk = Some(try!(convert_private_pem_to_jwk(rsa)));
    } else if let Some(jwkfile) = args.value_of("jwk") {
        jwk = Some(try!(load_jwk(&PathBuf::from(jwkfile))));
    }
    
    if let Some(jwk) = jwk {
        let header = Header::new(alg);
        let signer = RsaSigner::new(jwk);
        
        let sig = try!(signer.sign(&header, msg.as_bytes()));
        
        print_sig(args, msg, &sig);
        
        Ok(())
    } else {
        panic!("no private key supplied")
    }
}

pub fn verify(args: &ArgMatches) -> JwtResult<()> {
    let msg = args.value_of("msg");
    let sig = args.value_of("sig");
    let jwt = args.value_of("jwt");
    let alg: Algorithm = try!(Algorithm::from_str(args.value_of("alg").unwrap_or("RS256")));
    
    let mut jwk = None;
    
    if let Some(pem) = args.value_of("pem") {
        let rsa = try!(load_private_pem(&PathBuf::from(pem)));
        
        jwk = Some(try!(convert_private_pem_to_jwk(rsa)));
    } else if let Some(jwkfile) = args.value_of("jwk") {
        jwk = Some(try!(load_jwk(&PathBuf::from(jwkfile))));
    }
    
    if let Some(jwk) = jwk {
        let header = Header::new(alg);
        let signer = RsaSigner::new(jwk);
            
        if let Some(jwt) = jwt {
            let t = try!(Jwt::decode(jwt, &signer));
            
            println!("{}\n{}", try!(serde_json::to_string(&t.header)), try!(serde_json::to_string(&t.claims)));
        } else if let Some(msg) = msg {
            let sig = sig.unwrap();
            
            let verified = try!(signer.verify(&header, msg.as_bytes(), &sig));
        
            if verified {
                println!("Ok");
            } else {
                panic!("invalid signature");
            }
        } else {
            panic!("no message or jwt supplied");
        }
        
        Ok(())
    } else {
        panic!("no private key supplied")
    }
}

pub fn print_sig(args: &ArgMatches, msg: &str, sig: &str) {
    let format = args.value_of("format").unwrap_or("sig");
    
    match format {
        "sig" => {
            println!("{}", sig);
        },
        "jwt" => {
            println!("{}.{}", msg, sig);
        }
        _ => {
            unimplemented!()
        }
    }
}

pub fn convert_public_pem_to_jwk(rsa: RSA) -> JwtResult<Jwk> {    
    let mut vs = ValidationState::new();
    
    if !rsa.has_n() {
        vs.reject("n", ValidationError::MissingRequiredValue("n".to_owned()));
    }
    
    if !rsa.has_e() {
        vs.reject("e", ValidationError::MissingRequiredValue("e".to_owned()));
    }
    
    if vs.valid {
        let mut jwk = Jwk::new(KeyType::RSA);
        
        let n = try!(rsa.n());
        let n_bn = BigNumComponent(n);
        let n_b64 = try!(n_bn.to_base64());
        jwk.set_value("n", &n_b64);
        
        let e = try!(rsa.e());
        let e_bn = BigNumComponent(e);
        let e_b64 = try!(e_bn.to_base64());
        jwk.set_value("e", &e_b64);
        
        Ok(jwk)
    } else {
        Err(From::from(ValidationError::ValidationError(vs)))
    }
}

pub fn bn_to_b64(bn: BigNum) -> JwtResult<String> {
    let component = BigNumComponent(bn);
    component.to_base64().map_err(From::from)
}

pub fn get_dp(rsa: &RSA) -> JwtResult<BigNum> {
    unsafe {
        BigNum::new_from_ffi((*rsa.as_ptr()).dmp1)
    }.map_err(From::from)
}

pub fn get_dq(rsa: &RSA) -> JwtResult<BigNum> {
    unsafe {
        BigNum::new_from_ffi((*rsa.as_ptr()).dmq1)
    }.map_err(From::from)
}

pub fn get_qi(rsa: &RSA) -> JwtResult<BigNum> {
    unsafe {
        BigNum::new_from_ffi((*rsa.as_ptr()).iqmp)
    }.map_err(From::from)
}

pub fn convert_private_pem_to_jwk(rsa: RSA) -> JwtResult<Jwk> {
    let mut vs = ValidationState::new();
    
    if !rsa.has_n() {
        vs.reject("n", ValidationError::MissingRequiredValue("n".to_owned()));
    }
    
    if !rsa.has_e() {
        vs.reject("e", ValidationError::MissingRequiredValue("e".to_owned()));
    }
    
    if vs.valid {
        let mut jwk = Jwk::new(KeyType::RSA);
        
        let n = try!(rsa.n());
        jwk.set_value("n", &try!(bn_to_b64(n)));
        
        let e = try!(rsa.e());
        jwk.set_value("e", &try!(bn_to_b64(e)));
        
        let d = try!(rsa.d());
        jwk.set_value("d", &try!(bn_to_b64(d)));
        
        let p = try!(rsa.p());
        jwk.set_value("p", &try!(bn_to_b64(p)));
        
        let q = try!(rsa.q());
        jwk.set_value("q", &try!(bn_to_b64(q)));
        
        let dp = try!(get_dp(&rsa));
        jwk.set_value("dp", &try!(bn_to_b64(dp)));
        
        let dq = try!(get_dq(&rsa));
        jwk.set_value("dq", &try!(bn_to_b64(dq)));
        
        let qi = try!(get_qi(&rsa));
        jwk.set_value("qi", &try!(bn_to_b64(qi)));
        
        Ok(jwk)
    } else {
        Err(From::from(ValidationError::ValidationError(vs)))
    }
}

pub fn load_public_pem(pem_path: &Path) -> JwtResult<RSA> {
    let mut buffer = try!(File::open(pem_path));
    RSA::public_key_from_pem(&mut buffer).map_err(From::from)
}

pub fn load_private_pem(pem_path: &Path) -> JwtResult<RSA> {
    let mut buffer = try!(File::open(pem_path));
    RSA::private_key_from_pem(&mut buffer).map_err(From::from)
}

pub fn load_jwk(jwk_path: &Path) -> JwtResult<Jwk> {
    let mut buffer = try!(File::open(jwk_path));
    let mut s = String::new();
    
    try!(buffer.read_to_string(&mut s));
    
    serde_json::from_str(&s).map_err(From::from)
}