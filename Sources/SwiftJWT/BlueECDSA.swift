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

import CryptorECC
import LoggerAPI

import Foundation

class BlueECSigner: SignerAlgorithm {
    let name: String = "ECDSA"
    
    private let key: Data
    private let curve: String
    
    init(key: Data, curve: String) {
        self.key = key
        self.curve = curve
    }
    
    func sign(header: String, claims: String) throws -> String {
        let unsignedJWT = header + "." + claims
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            throw JWTError.invalidJWTString
        }
        let signature = try sign(unsignedData)
        let signatureString = signature.base64urlEncodedString()
        return header + "." + claims + "." + signatureString
    }
    
    func sign(_ data: Data) throws -> Data {
        guard let keyString = String(data: key, encoding: .utf8) else {
            throw JWTError.invalidPrivateKey
        }
        if #available(OSX 10.13, *) {
            let privateKey = try ECPrivateKey(key: keyString)
            guard privateKey.curveId == curve else {
                throw JWTError.invalidPrivateKey
            }
            let signedData = try data.sign(with: privateKey)
            return signedData.r + signedData.s
        } else {
            throw JWTError.osVersionToLow
        }

    }
}

class BlueECVerifier: VerifierAlgorithm {
    
    let name: String = "ECDSA"
    
    private let key: Data
    private let curve: String
    init(key: Data, curve: String) {
        self.key = key
        self.curve = curve
    }
    
    func verify(jwt: String) -> Bool {
        let components = jwt.components(separatedBy: ".")
        if components.count == 3 {
            guard let signature = Data(base64urlEncoded: components[2]),
                let jwtData = (components[0] + "." + components[1]).data(using: .utf8)
                else {
                    return false
            }
            return self.verify(signature: signature, for: jwtData)
        } else {
            return false
        }
    }
    
    func verify(signature: Data, for data: Data) -> Bool {
        guard #available(OSX 10.13, *) else {
            return false
        }
        do {
            guard let keyString = String(data: key, encoding: .utf8) else {
                return false
            }
            let r = signature.subdata(in: 0 ..< signature.count/2)
            let s = signature.subdata(in: signature.count/2 ..< signature.count)
            let signature = try ECSignature(r: r, s: s)
            let publicKey = try ECPublicKey(key: keyString)
            guard publicKey.curveId == curve else {
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
