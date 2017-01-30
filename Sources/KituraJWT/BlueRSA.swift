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

class BlueRSA: EncryptionAlgorithm {
    
    private let key: Data
    private let keyType: RSAKeyType
    private let algorithm: Data.Algorithm
    
    init(key: Data, keyType: RSAKeyType?=nil, algorithm: Data.Algorithm) {
        self.key = key
        self.keyType = keyType ?? .publicKey
        self.algorithm = algorithm
    }
    
    func sign(_ data: Data) -> Data? {
        guard #available(macOS 10.12, iOS 10.0, *) else {
            Log.error("macOS 10.12.0 (Sierra) or higher or iOS 10.0 or higher is required by CryptorRSA")
            return nil
        }
        do {
            let privateKey = try CryptorRSA.createPrivateKey(with: key)
            let myPlaintext = CryptorRSA.createPlaintext(with: data)
            if let signedData = try myPlaintext.signed(with: privateKey, algorithm: algorithm) {
                return signedData.data
            }
            return nil
        }
        catch {
            return nil
        }
    }

    func sign(_ string: String, encoding: String.Encoding) -> Data? {
        guard let data: Data = string.data(using: encoding) else {
            Log.error("macOS 10.12.0 (Sierra) or higher or iOS 10.0 or higher is required by CryptorRSA")
            return nil
        }
        return sign(data)
    }
    
    func verify(signature: Data, for data: Data) -> Bool {
        guard #available(macOS 10.12, iOS 10.0, *) else {
            return false
        }
        do {
            var publicKey: CryptorRSA.PublicKey
            switch keyType {
            case .privateKey:
                return false
            case .publicKey:
                publicKey = try CryptorRSA.createPublicKey(with: key)
            case .certificate:
                publicKey = try CryptorRSA.createPublicKey(extractingFrom: key)
            }
            let signedData = CryptorRSA.createSigned(with: data)
            return try signedData.verify(with: publicKey, signature: signedData, algorithm: algorithm)
        }
        catch {
            return false
        }
    }
    
    func verify(signature: Data, for string: String, encoding: String.Encoding) -> Bool {
        guard let data: Data = string.data(using: encoding) else {
            return false
        }
        return verify(signature: signature, for: data)
    }
    
}


