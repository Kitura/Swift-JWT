/**
 * Copyright IBM Corporation 2017
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

import Cryptor
import Foundation

// MARK Algorithm

/**
 
 The algorithm that will be used when signing and verifying a JWT.
 
 ### Usage Example: ###
 ```swift
 let privateKey = "<PrivateKey>".data(using: .utf8)!
 let publicKey = "<PublicKey>".data(using: .utf8)!
 let signingAlgorithm = Algorithm.rs256(key: privateKey, keyType: .privateKey)
 let verifyAlgorithm = Algorithm.rs256(key: publicKey, keyType: .publicKey)
 struct MyClaims: Claims {
    var name: String
 }
 let jwt = JWT(header: Header(), claims: MyClaims(name: "Kitura"))
 let signedJWT: String = jwt.sign(using: signingAlgorithm)
 let verified: Bool = jwt.verify(signedJWT, using: verifyAlgorithm)
 ```
 */

public struct Algorithm {
    /// The name of the algorithm.
    public let name: String
    
    /// the algorithm used to encrypt the data.
    let encryptionAlgorithm: EncryptionAlgorithm
    
    /// RSA 256 bits with its key and key type.
    public static func rs256(key: Data, keyType: RSAKeyType) -> Algorithm {
        #if os(Linux)
            return Algorithm(name: "RS256", encryptionAlgorithm: RSA(key: key, keyType: keyType, algorithm: .sha256))
        #else
            return Algorithm(name: "RS256", encryptionAlgorithm: BlueRSA(key: key, keyType: keyType, algorithm: .sha256))
        #endif
    }
    
    /// RSA 384 bits with its key and key type.
    public static func rs384(key: Data, keyType: RSAKeyType) -> Algorithm {
        #if os(Linux)
        return Algorithm(name: "RS384", encryptionAlgorithm: RSA(key: key, keyType: keyType, algorithm: .sha384))
        #else
        return Algorithm(name: "RS384", encryptionAlgorithm: BlueRSA(key: key, keyType: keyType, algorithm: .sha384))
        #endif
    }
    
    /// RSA 512 bits with its key and key type.
    public static func rs512(key: Data, keyType: RSAKeyType) -> Algorithm {
        #if os(Linux)
        return Algorithm(name: "RS512", encryptionAlgorithm: RSA(key: key, keyType: keyType, algorithm: .sha512))
        #else
        return Algorithm(name: "RS512", encryptionAlgorithm: BlueRSA(key: key, keyType: keyType, algorithm: .sha512))
        #endif
    }
    
    /// No Algorithm used. This matches the "none" JWT alg header.
    /// This algorithm doesn't add a signiture when signing.
    /// When verifying a JWT, this algorithm always returns true.
    public static func none() -> Algorithm {
        return Algorithm(name: "none", encryptionAlgorithm: NoneAlgorithm())
    }

    func sign(_ input: String) -> Data? {
        return encryptionAlgorithm.sign(input)
    }
    
    func generateJWT(header: String, claims: String) -> String? {
        guard let signature = encryptionAlgorithm.sign(header + "." + claims),
              let signatureString = Base64URL.encode(signature)
        else {
            return nil
        }
        if signatureString.isEmpty {
            return header + "." + claims
        } else {
            return header + "." + claims + "." + signatureString
        }
    }
    
    func verify(signature: Data, for input: String) -> Bool {
        return encryptionAlgorithm.verify(signature: signature, for: input)
    }
    
    func verify(_ jwt: String) -> Bool {
        let components = jwt.components(separatedBy: ".")
        if components.count == 2 {
            return encryptionAlgorithm.verify(signature: Data(), for: components[0] + "." + components[1])
        } else if components.count == 3 {
            guard let signature = Base64URL.decode(components[2]) else {
                return false
            }
            return encryptionAlgorithm.verify(signature: signature, for: components[0] + "." + components[1])
        } else {
            return false
        }
    }
}
