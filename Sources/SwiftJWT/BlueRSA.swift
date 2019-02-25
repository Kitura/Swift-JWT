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

@available(OSX 10.12, *)
class BlueRSA: SignerAlgorithm, VerifierAlgorithm {
    let name: String = "RSA"
    
    private let key: Data
    private let keyType: RSAKeyType
    private let algorithm: Data.Algorithm
    private let privateKey: CryptorRSA.PrivateKey?
    private let publicKey: CryptorRSA.PublicKey?

    init(key: Data, keyType: RSAKeyType?=nil, algorithm: Data.Algorithm) {
        self.key = key
        self.keyType = keyType ?? .publicKey
        self.algorithm = algorithm
        if let keyString = String(data: key, encoding: .utf8) {
            switch self.keyType {
            case  .privateKey:
                self.privateKey = try? CryptorRSA.createPrivateKey(withPEM: keyString)
                self.publicKey = nil
            case .publicKey:
                self.publicKey = try? CryptorRSA.createPublicKey(withPEM: keyString)
                self.privateKey = nil
            case .certificate:
                self.publicKey = try? CryptorRSA.createPublicKey(extractingFrom: key)
                self.privateKey = nil
            }
        } else {
            self.privateKey = nil
            self.publicKey = nil
        }
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
        guard let privateKey = self.privateKey else {
            throw JWTError.invalidPrivateKey
        }
        let myPlaintext = CryptorRSA.createPlaintext(with: data)
        guard let signedData = try myPlaintext.signed(with: privateKey, algorithm: algorithm) else {
            throw JWTError.invalidPrivateKey
        }
        return signedData.data
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
        do {
            guard let publicKey = self.publicKey else {
                return false
            }
            let myPlaintext = CryptorRSA.createPlaintext(with: data)
            let signedData = CryptorRSA.createSigned(with: signature)
            return try myPlaintext.verify(with: publicKey, signature: signedData, algorithm: algorithm)
        }
        catch {
            Log.error("Verification failed: \(error)") 
            return false
        }
    }
}
