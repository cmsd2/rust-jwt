extern crate openssl;
extern crate jsonwebtoken;
extern crate serde_json;
extern crate clap;
extern crate rustc_serialize;

use openssl::rsa::Rsa;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{Read, Write};
use jsonwebtoken::jwk::*;
use jsonwebtoken::algorithm::*;
use jsonwebtoken::header::Header;
use jsonwebtoken::signer::*;
use jsonwebtoken::verifier::*;
use jsonwebtoken::crypto::rsa::*;
use jsonwebtoken::jwt::*;
use jsonwebtoken::result::*;
use clap::{Arg, ArgMatches, App, SubCommand};

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
        /*.subcommand(SubCommand::with_name("keyset")
                    .about("Manages JWK Set files")
                    .author("Chris Dawes <cmsd2@cantab.net>")
                    .version("1.0")
                    .subcommand(SubCommand::with_name("add")
                                .about("Adds a key to a keyset file")
                                .author("Chris Dawes <cmsd2@cantab.net>")
                                .version("1.0")
                                .arg(Arg::with_name("pem")
                                    .short("p")
                                    .required(false)
                                    .takes_value(true)
                                    .help("name of private? key pem to add")
                                )
                                .arg(Arg::with_name("jwk")
                                    .short("j")
                                    .required(false)
                                    .takes_value(true)
                                    .help("name of jwk private? key file to add")
                                )
                    )
                    // list key IDs
                    // remove by key ID
                    // new keyset file
                    // get key by key ID
        )*/
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
        let rsa: Rsa = if args.is_present("pubin") {
            load_public_pem(&PathBuf::from(pem)).unwrap()
        } else {
            load_private_pem(&PathBuf::from(pem)).unwrap()
        };
        
        match format {
            "jwk" => {
                let jwk = if args.is_present("pubin") {
                    rsa.convert_public_pem_to_jwk().unwrap()
                } else {
                    rsa.convert_private_pem_to_jwk().unwrap()
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
                let out =           
                    if jwk.is_private_key() && !args.is_present("pubout") {
                        let rsa = try!(jwk.private_key());
                        
                        try!(rsa.private_key_to_pem())
                    } else {
                        let rsa = try!(jwk.public_key());
                        
                        try!(rsa.public_key_to_pem())
                    };
                
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
        
        jwk = Some(try!(rsa.convert_private_pem_to_jwk()));
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
        
        jwk = Some(try!(rsa.convert_private_pem_to_jwk()));
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

pub fn load_public_pem(pem_path: &Path) -> JwtResult<Rsa> {
    let mut buffer = try!(File::open(pem_path));
    let mut bytes = vec![];
    try!(buffer.read_to_end(&mut bytes));
    Rsa::public_key_from_pem(&bytes[..]).map_err(From::from)
}

pub fn load_private_pem(pem_path: &Path) -> JwtResult<Rsa> {
    let mut buffer = try!(File::open(pem_path));
    let mut bytes = vec![];
    try!(buffer.read_to_end(&mut bytes));
    Rsa::private_key_from_pem(&bytes[..]).map_err(From::from)
}

pub fn load_jwk(jwk_path: &Path) -> JwtResult<Jwk> {
    let mut buffer = try!(File::open(jwk_path));
    let mut s = String::new();
    
    try!(buffer.read_to_string(&mut s));
    
    serde_json::from_str(&s).map_err(From::from)
}