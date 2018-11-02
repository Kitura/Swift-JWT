/**
 * Copyright IBM Corporation 2018
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Foundation
import Cryptor

/**
 
 A struct that will be used to verify the signature of a JWT is valid for the provided `Header` and `Claims`.
 
 ### Usage Example: ###
 ```swift
 struct MyClaims: Claims {
    var name: String
 }
 let jwt = JWT(claims: MyClaims(name: "Kitura"))
 
 let privateKey = "<PrivateKey>".data(using: .utf8)!
 let jwtSigner = JWTSigner.rs256(privateKey: privateKey)
 let signedJWT: String = jwt.sign(using: jwtSigner)
 
 let publicKey = "<PublicKey>".data(using: .utf8)!
 let jwtVerifier = JWTVerifier.rs256(publicKey: publicKey)
 let verified: Bool = jwt.verify(signedJWT, using: jwtVerifier)
 ```
 */
public struct JWTVerifier {    
    let verifierAlgorithm: VerifierAlgorithm
    
    init(verifierAlgorithm: VerifierAlgorithm) {
        self.verifierAlgorithm = verifierAlgorithm
    }
    
    func verify(jwt: String) -> Bool {
        return verifierAlgorithm.verify(jwt: jwt)
    }
    
    /// Initialize a JWTVerifier using the RSA 256 bits algorithm and the provided publicKey.
    public static func rs256(publicKey: Data) -> JWTVerifier {
        #if os(Linux)
        return JWTVerifier(verifierAlgorithm: RSA(key: publicKey, keyType: .publicKey, algorithm: .sha256))
        #else
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha256))
        #endif
    }
    
    /// Initialize a JWTVerifier using the RSA 384 bits algorithm and the provided publicKey.
    public static func rs384(publicKey: Data) -> JWTVerifier {
        #if os(Linux)
        return JWTVerifier(verifierAlgorithm: RSA(key: publicKey, keyType: .publicKey, algorithm: .sha384))
        #else
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha384))
        #endif
    }
    
    /// Initialize a JWTVerifier using the RSA 512 bits algorithm and the provided publicKey.
    public static func rs512(publicKey: Data) -> JWTVerifier {
        #if os(Linux)
        return JWTVerifier(verifierAlgorithm: RSA(key: publicKey, keyType: .publicKey, algorithm: .sha512))
        #else
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: publicKey, keyType: .publicKey, algorithm: .sha512))
        #endif
    }
    
    /// Initialize a JWTVerifier using the RSA 256 bits algorithm and the provided certificate.
    public static func rs256(certificate: Data) -> JWTVerifier {
        #if os(Linux)
        return JWTVerifier(verifierAlgorithm: RSA(key: certificate, keyType: .certificate, algorithm: .sha256))
        #else
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: certificate, keyType: .certificate, algorithm: .sha256))
        #endif
    }
    
    /// Initialize a JWTVerifier using the RSA 384 bits algorithm and the provided certificate.
    public static func rs384(certificate: Data) -> JWTVerifier {
        #if os(Linux)
        return JWTVerifier(verifierAlgorithm: RSA(key: certificate, keyType: .certificate, algorithm: .sha384))
        #else
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: certificate, keyType: .certificate, algorithm: .sha384))
        #endif
    }
    
    /// Initialize a JWTVerifier using the RSA 512 bits algorithm and the provided certificate.
    public static func rs512(certificate: Data) -> JWTVerifier {
        #if os(Linux)
        return JWTVerifier(verifierAlgorithm: RSA(key: certificate, keyType: .certificate, algorithm: .sha512))
        #else
        return JWTVerifier(verifierAlgorithm: BlueRSA(key: certificate, keyType: .certificate, algorithm: .sha512))
        #endif
    }
    
    /// Initialize a JWTVerifier that will always return true when verifying the JWT. This is equivelent to using the "none" alg header.
    public static let none = JWTVerifier(verifierAlgorithm: NoneAlgorithm())
}
