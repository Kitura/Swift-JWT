# Kitura-JWT
An implementation of JSON Web Token

![Mac OS X](https://img.shields.io/badge/os-Mac%20OS%20X-green.svg?style=flat)
![Linux](https://img.shields.io/badge/os-linux-green.svg?style=flat)
![Apache 2](https://img.shields.io/badge/license-Apache2-blue.svg?style=flat)

## Summary
An implementation of [JSON Web Token](https://tools.ietf.org/html/rfc7519)

## Table of Contents
* [Getting started](#getting-started)
* [Supported algorithms](#supported-algorithms)
* [Usage](#usage)
* [License](#license)

## Getting started

### macOS

Install OpenSSl:

```
$ brew install openssl
```

Download `Kitura-JWT` and run:

```
$ swift package fetch
```

Edit `Packages/OpenSSL-<version>/Package.swift`, change the `pkgConfig` to `"openssl"`, i.e. the file should contain:

```swift
import PackageDescription

let package = Package(
        name: "OpenSSL",
        pkgConfig: "openssl",
        providers: [
                .Brew("openssl"),
        ]
)
```

Set `PKG_CONFIG_PATH`:

```
$ export PKG_CONFIG_PATH=/usr/local/opt/openssl/ib/pkgconfig/
```

And build `Kitura-JWT`:

```
$ swift build
```


## Supported algorithms
At the moment the supported algorithms are: RSA with 256, 384 and 512 bits.

They are listed in `Algorithm`. In order to check if an algorithm is supported and whether it requires a key or a secret, call:
``` swift
public static func isSupported(name: String) -> Supported
```
where `name` is a textual representation of an algorithm, e.g., "rs256" or "RS256".

`Supported` is an enum with the following cases: unsupported, supportedWithKey (RSA falls into this category), and supportedWithSecret (HMAC, which is currently unsupported).

## Usage


Add

```swift
import KituraJWT
```
to your application.

### Sign a JWT

The `sign` method encodes header and claims of a JWT instance, creates a signature, and returns a String containing a signed JSON Web Token.

```swift
let jwt = JWT(header: Header([.typ:"JWT"]), claims: Claims([.name:"Kitura"]))
let signedJWT = jwt.sign(using: .rs256(key, .privateKey))
```
`signedJWT` will be of the form
```
<encoded header>.<encoded claims>.<signature>
```
Note, that `sign` sets the alg field of the header.

### Decode a JSON Web Token

A static function `JWT.decode` creates an instance of `JWT` for a String containing JSON Web Token:

``` swift
let jwt = decode(encodedAndSignedJWT)
```
Note, that this method doesn't verify the signature of the token.

### Verify signature of a JSON Web Token

A static function `JWT.verify` verifies the signature of a JSON Web Token given as a String:

```swift
if !verify(encodedAndSignedJWT, using: .rs512(key, .publicKey)) {
    print("Verification failed")
}
```

### Validate claims

`validateClaims` method validates the claims of a JWT instance.
The following claims are validated if they are present in the `Claims` object:
  - iss
  - aud
  - azp
  - at_hash
  - exp
  - nbf
  - iat

Various validations require an input. In these cases, if the claim in question exists and the input
is provided, the validation will be performed. Otherwise, the validation is skipped.

The method returns `ValidateClaimsResult` - an enum that list the various reasons for validation failure.
If the validation succeeds `ValidateClaimsResult.success` is returned.

```swift
let validationResult = validateClaims(issuer: issuer, audience: clientID, accessToken: accessToken)
if validationResult != .success {
  print("Claims validation failed: ", validationResult)
}
```


## License
This library is licensed under Apache 2.0. Full license text is available in [LICENSE](LICENSE.txt).
