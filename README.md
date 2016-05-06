# jsonwebtoken

This is a hard fork of [https://github.com/Keats/rust-jwt](https://github.com/Keats/rust-jwt)

It uses serde instead of rustc_serialize.
It also adds openssl for RSA.

This is a work in progress.


## Installation
Add the following to Cargo.toml:

```toml
jsonwebtoken = "1"
rustc-serialize = "0.3"
```

## How to use
There is a complete example in `examples/claims.rs` but here's a quick one.

In terms of imports:
```rust
extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;

use jwt::{encode, decode, Header, Algorithm};
```

Look at the examples directory for 2 examples: a basic one and one with a custom
header.

### Encoding
```rust
let token = encode(Header::default(), &my_claims, "secret".as_ref()).unwrap();
```
In that example, `my_claims` is an instance of a Claims struct that derives `RustcEncodable` and `RustcDecodable`.
The default algorithm is HS256.
Look at custom headers section to see how to change that.

### Decoding
```rust
let token = decode::<Claims>(&token, "secret", Algorithm::HS256).unwrap();
// token is a struct with 2 params: header and claims
```
In addition to the normal base64/json decoding errors, `decode` can return two custom errors:

- **InvalidToken**: if the token is not a valid JWT
- **InvalidSignature**: if the signature doesn't match
- **WrongAlgorithmHeader**: if the alg in the header doesn't match the one given to decode

### Validation
The library only validates the algorithm type used but does not verify claims such as expiration.
Feel free to add a `validate` method to your claims struct to handle that: there is an example of that in `examples/claims.rs`.

### Custom headers
All the parameters from the RFC are supported but the default header only has `typ` and `alg` set: all the other fields are optional.
If you want to set the `kid` parameter for example:

```rust
let mut header = Header::default();
header.kid = Some("blabla".to_owned());
header.alg = Algorithm::HS512;
let token = encode(header, &my_claims, "secret".as_ref()).unwrap();
```
Look at `examples/custom_header.rs` for a full working example.

## Algorithms
Right now, only SHA family is supported: SHA256, SHA384 and SHA512.

## Performance
On my thinkpad 440s for a 2 claims struct using SHA256:

```
test bench_decode ... bench:       7,259 ns/iter (+/- 1,506)
test bench_encode ... bench:       4,261 ns/iter (+/- 722)
```

## Changelog

- 1.1.3: Make sign and verify public
- 1.1.2: Update rust-crypto to 0.2.35
- 1.1.1: Don't serialize empty fields in header
- 1.1.0: Impl Error for jsonwebtoken errors
- 1.0: Initial release
