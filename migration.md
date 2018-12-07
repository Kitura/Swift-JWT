## Upgrading to Swift-JWT 3.0

Swift-JWT version 3.0 adds Codable conformance to JWT's for easier encoding and decoding. This release includes breaking changes to the Swift-JWT API and the following is a guide for converting from Swift-JWT 2.0 to Swift-JWT 3.0

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
The JWT `Claims` has been changed to be a protocol. This means that instead of intializing a fixed `Claims` struct with a `[String: Any]` dictionary, you define and intialize your own object that conforms to claims. Alternatively, you can use one of the [example Claims implementations](https://github.com/IBM-Swift/Swift-JWT/tree/master/Sources/SwiftJWT/ClaimsExamples) provided.

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
 
 ```swift
 // Swift-JWT 2.0
 JWT
 
 // Swift-JWT 3.0
 JWT<MyClaims>
 ```
 
 - The `sign` function takes a `JWTSigner` and returns `String` instead of `String?`.  
 
 ```swift
 // Swift-JWT 2.0
let signedJWT: String? = try jwt.sign(using: Algorithm.rs256(key, .privateKey))

 // Swift-JWT 3.0
 let signedJWT: String = try jwt.sign(using: JWTSigner.rs256(privateKey: key))
```
 
 - The `verify` function takes a `JWTVerifier` and no longer throws.
 
 ```swift
 // Swift-JWT 2.0
 let verified = try JWT.verify(signedJWT, using: Algorithm.rs256(key, .publicKey))
 
 // Swift-JWT 3.0
 let verified = JWT<MyClaims>.verify(signedJWT, using: JWTVerifier.rs256(publicKey: key))
```
 
 - The `validateClaims` function now only checks registered JWT date based claims.  
 
 ```swift
 // Swift-JWT 2.0
 let validationResult = jwt.validateClaims(issuer: "issuer", audience: "clientID")

 // Swift-JWT 3.0
 let validationResult = jwt.validateClaims()
 let validateOthers = jwt.issuer == "issuer" && jwt.audience == "clientID"
 ```

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
 As a result of the new API, a number of types are now redundant and have been removed. These include:

 - `Supported`
 - `Base64URL` 
 -  `Hash` 
 - `RSAKeyType` 
 - `ClaimKeys` 
