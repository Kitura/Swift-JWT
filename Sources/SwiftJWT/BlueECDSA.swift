/**
 * Copyright IBM Corporation 2019
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

import CryptorECC
import LoggerAPI
import Foundation

// Class for ECDSA signing using BlueECC
@available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
class BlueECSigner: SignerAlgorithm {
    let name: String = "ECDSA"
    
    private let key: Data
    private let curve: EllipticCurve
    
    // Initialize a signer using .utf8 encoded PEM private key.
    init(key: Data, curve: EllipticCurve) {
        self.key = key
        self.curve = curve
    }
    
    // Sign the header and claims to produce a signed JWT String
    func sign(header: String, claims: String) throws -> String {
        let unsignedJWT = header + "." + claims
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            throw JWTError.invalidJWTString
        }
        let signature = try sign(unsignedData)
        let signatureString = JWTEncoder.base64urlEncodedString(data: signature)
        return header + "." + claims + "." + signatureString
    }
    
    // send utf8 encoded `header.claims` to BlueECC for signing
    private func sign(_ data: Data) throws -> Data {
        guard let keyString = String(data: key, encoding: .utf8) else {
            throw JWTError.invalidPrivateKey
        }
        let privateKey = try ECPrivateKey(key: keyString)
        guard privateKey.curve == curve else {
            throw JWTError.invalidPrivateKey
        }
        let signedData = try data.sign(with: privateKey)
        return signedData.r + signedData.s
    }
}

// Class for ECDSA verifying using BlueECC
@available(OSX 10.13, iOS 11, tvOS 11.0, watchOS 4.0, *)
class BlueECVerifier: VerifierAlgorithm {
    
    let name: String = "ECDSA"
    
    private let key: Data
    private let curve: EllipticCurve
    
    // Initialize a verifier using .utf8 encoded PEM public key.
    init(key: Data, curve: EllipticCurve) {
        self.key = key
        self.curve = curve
    }
    
    // Verify a signed JWT String
    func verify(jwt: String) -> Bool {
        let components = jwt.components(separatedBy: ".")
        if components.count == 3 {
            guard let signature = JWTDecoder.data(base64urlEncoded: components[2]),
                let jwtData = (components[0] + "." + components[1]).data(using: .utf8)
                else {
                    return false
            }
            return self.verify(signature: signature, for: jwtData)
        } else {
            return false
        }
    }
    
    // Send the base64URLencoded signature and `header.claims` to BlueECC for verification.
    private func verify(signature: Data, for data: Data) -> Bool {
        do {
            guard let keyString = String(data: key, encoding: .utf8) else {
                return false
            }
            let r = signature.subdata(in: 0 ..< signature.count/2)
            let s = signature.subdata(in: signature.count/2 ..< signature.count)
            let signature = try ECSignature(r: r, s: s)
            let publicKey = try ECPublicKey(key: keyString)
            guard publicKey.curve == curve else {
                return false
            }
            return signature.verify(plaintext: data, using: publicKey)
        }
        catch {
            Log.error("Verification failed: \(error)")
            return false
        }
    }
}
