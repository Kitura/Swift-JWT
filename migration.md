## Upgrading to Swift-JWT 3.0

Swift-JWT version 3.0 adds Codable conformance to JWT's for easier encoding and decoding. This release includes breaking changes to the Swift-JWT API and the following is a guide for converting from Swift-JWT Version 2.* to Swift-JWT Version 3.*

### Header:

The `Header` struct is now Codable and has fixed fields representing the possible headers. As a result, the Header is now intialized by setting the field values:

```swift
// Swift-JWT 2.0
let header = Header([.typ:"JWT", .kid:"KeyID"])
// Swift-JWT 3.0
let header = Header(typ: "JWT", kid: "KeyID")
```
These values can then accessed directly:
```swift
// Swift-JWT 2.0
let keyID = header["kid"]
// Swift-JWT 3.0
let keyID = header.kid
```

### Claims:
The JWT `Claims` has been changed to be a protocol. This means that instead of intializing a fixed `Claims` struct with a `[String: Any]` dictionary, you define and intialize your own object that conforms to claims. Alternatively, you can use one of the provided `Claims` Examples. This change adds compile time safety since your claims are defined types instead of `Any` and allows `Claims` to conform to Codable.

```swift
// Swift-JWT 2.0
let myClaims = Claims(["iss":"Kitura"])
// Swift-JWT 3.0, User defined claims
struct MyClaims: Claims {
    let sub: String
}
let myClaims = MyClaims(iss: "Kitura")
// Swift-JWT 3.0, Using Standard Claims
let myClaims = ClaimsStandardJWT(iss: "Kitura")
```

### Algorithm:

The `Algorithm` enum has been removed and replaced with `JWTSigner` and `JWTVerfier` structs. This change removes the requirement to specify the Key type and allows more signing and verifying algorithms to be added later.

```swift
let privateKey = "<PrivateKey>".data(using: .utf8)!
let publicKey = "<PublicKey>".data(using: .utf8)!
// Swift-JWT 2.0
let signer = Algorithm.rs256(privateKey, .privateKey)
let verifier = Algorithm.rs256(publicKey, .publicKey)
// Swift-JWT 3.0
let signer = JWTSigner.rs256(privateKey: privateKey)
let verifier = JWTVerifier.rs256(publicKey: publicKey)
```

 - The `isSupported` function has been removed. To see supported Algorithms, check the [README](https://github.com/IBM-Swift/Swift-JWT#supported-algorithms) or inspect the initialisers for `JWTSigner` and `JWTVerifier`.

### JWT:

 - The `JWT` Struct is now generic over a `Claims` object.
 - The `sign` function returns `String` instead of `String?`.  
 - The `verify` function no longer throws.
 - The `validateClaims` function now only checks time based claims.  


The `encode()` function has been removed. To encode a JWT without signing it use the `none` JWTSigner:

```swift
// Swift-JWT 2.0
let encodedJWT = try jwt.encoded()
// Swift-JWT 3.0
let encodedJWT = try jwt.sign(using: .none)
```

The `decode()` function has been replaced with an init from String:
```swift
// Swift-JWT 2.0
let decodedJWT = try JWT.decode(encodedJWT)
// Swift-JWT 3.0
let decodedJWT = try JWT<MyClaims>(jwtString: encodedJWT)
```


## Removed APIs
To Clean up the Swift-JWT API, the following public structs and enums have been removed. They are either no longer necessary or not a part of using JWTs.

 - The `Supported` enum has been removed.

 - The struct `Base64URL` has been made internal.

 - The struct `Hash` has been removed.

 - The `RSAKeyType` enum has been made internal since you no longer need to provide a KeyType with `JWTSigner` and `JWTVerifier`.

 - The `ClaimKeys` enum has been removed. See [ClaimsExamples](https://github.com/IBM-Swift/Swift-JWT/tree/master/Sources/SwiftJWT/ClaimsExamples) for example `Claims` you can use.
