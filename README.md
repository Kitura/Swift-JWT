# SwiftJWT
An implementation of JSON Web Token

![Mac OS X](https://img.shields.io/badge/os-macOS-green.svg?style=flat)
![Linux](https://img.shields.io/badge/os-linux-green.svg?style=flat)
![Apache 2](https://img.shields.io/badge/license-Apache2-blue.svg?style=flat)

## Summary
An implementation of [JSON Web Token](https://tools.ietf.org/html/rfc7519) using Swift. For more information on JSON Web Tokens, their use cases and how they work, we recommend visiting [jwt.io](https://jwt.io/introduction/). For their IETF specification, see [RFC 7519](https://tools.ietf.org/html/rfc7519).

## Table of Contents
* [Prerequisites](#prerequisites)
* [Supported algorithms](#supported-algorithms)
* [Usage](#usage)
* [License](#license)


## Prerequisites

### macOS

* macOS 10.12.0 (*Sierra*) or higher

## Supported algorithms
At the moment the supported algorithms are:

RS256 - RSASSA-PKCS1-v1_5 using SHA-256
RS384 - RSASSA-PKCS1-v1_5 using SHA-384
RS512 - RSASSA-PKCS1-v1_5 using SHA-512

## Usage

Start by importing the module:

```swift
import SwiftJWT
```
### Alogithm Support
The supported algorithms are listed above.

In order to check at run time if an algorithm is supported and whether it requires a key or a secret, call:

``` swift
public static func isSupported(name: String) -> Supported
```
where `name` is a textual representation of an algorithm, e.g., "RS256" (case insensitive).

`Supported` is an enum with the following cases: `unsupported`, `supportedWithKey` (RSA falls into this category), and `supportedWithSecret` (HMAC, which is currently unsupported).

### The modeling of JSON Web Tokens

The JWT class models JSON Web Tokens by using a pair of structs, `Header` for the JSON Web Token header and `Claims` for the JSON Web Token claims.

#### Header API

The Header struct contains the various fields of the JSON Web Token header. These fields can be accessed and modified using the subscript operator. The subscript is of the type `HeaderKeys`.

#### Claims API

The Claims struct contains the various fields of the JSON Web Token claims. These fields can be accessed and modified using the subscript operator. The subscript can be either of the type `ClaimKeys` for the standard claims or of the type `String` for any non-standard claims.

### Sign a JWT

The `sign` function encodes the header and claims of a JWT instance, creates a signature, and returns a String containing the signed JSON Web Token of the JWT instance.

For example:

```swift
let jwt = JWT(header: Header([.typ:"JWT"]), claims: Claims([.name:"Kitura"]))
let signedJWT = jwt.sign(using: .rs256(key, .privateKey))
```
`signedJWT` will be of the form:

```
<encoded header>.<encoded claims>.<signature>
```
**Note:** The `sign` function sets the alg (algorithm) field of the header.

### Creating a Key to Sign a JSON Web Token

To use the `sign` function, you must pass in the `key` parameter. This could be the contents of a .key file generated via the following Terminal commands:

```
$ ssh-keygen -t rsa -b 4096 -f privateKey.key
# Don't add a passphrase
$ openssl rsa in privateKey.key -pubout -outform PEM -out privateKey.key.pub
```

This will create a public and private key pair on your system, and the contents of the private key can be passed into a Swift variable using the following code:

```swift
let keyPath = URL(fileURLWithPath: getAbsolutePath(relativePath: "/path/to/privateKey.key"))
let key: Data = try Data(contentsOf: keyPath, options: alwaysMapped)
```

You then use the public key to read 

### Decode a JSON Web Token

The static function `JWT.decode` creates an instance of `JWT` for a String containing a JSON Web Token.

For example:

``` swift
let jwt = JWT.decode(encodedAndSignedJWT)
```
**Note:** This function doesn't verify the signature of the token.

### Encode a JSON Web Token
To encode a token without signing it, call encode.

``` swift
let encoded = jwt.encode()
```

### Verify the signature of a JSON Web Token

The static function `JWT.verify` verifies the signature of a JSON Web Token given in String form.

For example:

```swift
if !JWT.verify(encodedAndSignedJWT, using: .rs512(key, .publicKey)) {
    print("Verification failed")
}
```

### Validate claims

The `validateClaims` function validates the claims of a JWT instance.
The following claims are validated if they are present in the `Claims` object:
  - iss (issuer)
  - aud (audience)
  - exp (expiration date)
  - nbf (not before date)
  - iat (issued at date)

Various validations require an input. In these cases, if the claim in question exists and the input is provided, the validation will be performed. Otherwise, the validation is skipped.

The method returns `ValidateClaimsResult` - an enum that list the various reasons for validation failure.
If the validation succeeds `ValidateClaimsResult.success` is returned.

```swift
let validationResult = validateClaims(issuer: issuer, audience: clientID)
if validationResult != .success {
  print("Claims validation failed: ", validationResult)
}
```


## License
This library is licensed under Apache 2.0. Full license text is available in [LICENSE](LICENSE.txt).
