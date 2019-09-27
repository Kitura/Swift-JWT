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

import CryptorRSA
import LoggerAPI

import Foundation

class BlueRSA: SignerAlgorithm, VerifierAlgorithm {
    let name: String = "RSA"
    
    private let key: Data
    private let keyType: RSAKeyType
    private let algorithm: Data.Algorithm
    private let usePSS: Bool
    
    init(key: Data, keyType: RSAKeyType?=nil, algorithm: Data.Algorithm, usePSS: Bool = false) {
        self.key = key
        self.keyType = keyType ?? .publicKey
        self.algorithm = algorithm
        self.usePSS = usePSS
    }
    
    func sign(header: String, claims: String) throws -> String {
        let unsignedJWT = header + "." + claims
        guard let unsignedData = unsignedJWT.data(using: .utf8) else {
            throw JWTError.invalidJWTString
        }
        let signature = try sign(unsignedData)
        let signatureString = JWTEncoder.base64urlEncodedString(data: signature)
        return header + "." + claims + "." + signatureString
    }
    
    func sign(_ data: Data) throws -> Data {
        guard #available(macOS 10.12, iOS 10.3, tvOS 12.0, watchOS 3.3, *) else {
            Log.error("macOS 10.12.0 (Sierra) or higher or iOS 10.0 or higher is required by CryptorRSA")
            throw JWTError.osVersionToLow
        }
        // Convert PEM format to DER
        let keyDer: Data
        if let keyString = String(data: key, encoding: .utf8) {
            let strippedKey = String(keyString.filter { !" \n\t\r".contains($0) })
            let pemComponents = strippedKey.components(separatedBy: "-----")
            guard pemComponents.count >= 5 else {
                throw JWTError.missingPEMHeaders
            }
            guard let der = Data(base64Encoded: pemComponents[2]) else {
                throw JWTError.invalidPrivateKey
            }
            keyDer = der
        } else {
            keyDer = key
        }
        let privateKey = try CryptorRSA.createPrivateKey(with: keyDer)
        let myPlaintext = CryptorRSA.createPlaintext(with: data)
        guard let signedData = try myPlaintext.signed(with: privateKey, algorithm: algorithm, usePSS: usePSS) else {
            throw JWTError.invalidPrivateKey
        }
        return signedData.data
    }
    
    
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
    
    func verify(signature: Data, for data: Data) -> Bool {
        guard #available(macOS 10.12, iOS 10.3, tvOS 12.0, watchOS 3.3, *) else {
            return false
        }
        do {
            var publicKey: CryptorRSA.PublicKey
            switch keyType {
            case .privateKey:
                return false
            case .publicKey:
                // Convert PEM format to DER
                let keyDer: Data
                if let keyString = String(data: key, encoding: .utf8) {
                    let strippedKey = String(keyString.filter { !" \n\t\r".contains($0) })
                    let pemComponents = strippedKey.components(separatedBy: "-----")
                    guard pemComponents.count >= 5 else {
                        return false
                    }
                    guard let der = Data(base64Encoded: pemComponents[2]) else {
                        return false
                    }
                    keyDer = der
                } else {
                    keyDer = key
                }
                publicKey = try CryptorRSA.createPublicKey(with: keyDer)
            case .certificate:
                publicKey = try CryptorRSA.createPublicKey(extractingFrom: key)
            }
            let myPlaintext = CryptorRSA.createPlaintext(with: data)
            let signedData = CryptorRSA.createSigned(with: signature)
            return try myPlaintext.verify(with: publicKey, signature: signedData, algorithm: algorithm, usePSS: usePSS)
        }
        catch {
            Log.error("Verification failed: \(error)") 
            return false
        }
    }
}
