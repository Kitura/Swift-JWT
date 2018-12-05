A guide for converting from Swift-JWT Version 2.* to Swift-JWT Version 3.

## Changed Structs

The following Structs have been changed:

### Header:

To initialise the `Header` class, instead of providing a `[HeaderKey: Any]` dictionary:

```swift
let header = Header([.typ:"JWT", .kid:"KeyID"])
```

Set the fields directly:
```swift
let header = Header(typ: "JWT", kid: "KeyID")
```

Instead of accessing the fields using subscripting:
```swift
let keyID = header["kid"]
```
Access the Header fields directly:
```swift
let keyID = header.kid
```

### Claims:
In Swift-JWT 2.0, you initialize the `Claims` struct using a dictionary:
```swift
let myClaims = Claims(["name":"Kitura"])
```
 In Swift-JWT 3.0, instead you define an object conforming to claims:
 ```swift
struct MyClaims: Claims {
    let name: String
}
let myClaims = MyClaims(name: "Kitura")
```

### Algorithm:

The `Algorithm` enum has been removed and replaced with `JWTSigner` and `JWTVerfier` structs.

Instead of creating Algorithms:
```swift
let privateKey = "<PrivateKey>".data(using: .utf8)!
let publicKey = "<publicKey>".data(using: .utf8)!
let signer = Algorithm.rs256(privateKey, .privateKey)
let verifier = Algorithm.rs256(publicKey, .publicKey)
```
Create a `JWTSigner` and `JWTVerfier`:
```swift
let privateKey = "<PrivateKey>".data(using: .utf8)!
let publicKey = "<publicKey>".data(using: .utf8)!
let signer = JWTSigner.rs256(privateKey: privateKey)
let verifier = Algorithm.rs256(publicKey: publicKey)
```

### JWT:

The `JWT` Struct is now generic over a `Claims` struct.
```swift
JWT<MyClaims>
```

The `sign` function returns `String` instead of `String?`.  
The `verify` function no longer throws.

The `encode()` function:
```swift
let encodedJWT = try jwt.encoded()
```
Has been removed. To encode a JWT without signing it use:
```swift
let encodedJWT = try jwt.sign(using: .none)
```

The `decode()` function:
```swift
let decodedJWT = try JWT.decode(encodedJWT)
```
Has been replaced with an init from String:
```swift
let decodedJWT = try JWT<MyClaims>(jwtString: encodedJWT)
```

The validateClaims function now only checks time based claims.  

## Removed APIs

```swift
JWT.isSupported(name: String) -> Supported
```

To see supported Algorithms, check the README.md or inspect the initialisers for JWTSigner and JWTVerifier.

The struct `Base64URL` has been made internal.

The struct `Hash` has been removed.

The `RSAKeyType` enum has been made internal

The `ClaimKeys` enum has been removed. See [ClaimsExamples](https://github.com/IBM-Swift/Swift-JWT/tree/master/Sources/SwiftJWT/ClaimsExamples) for registered claims.
