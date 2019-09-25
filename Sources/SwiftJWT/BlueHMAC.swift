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
import LoggerAPI
import Foundation

class BlueHMAC: SignerAlgorithm, VerifierAlgorithm {
    let name: String = "HMAC"
    
    private let key: Data
    private let algorithm: HMAC.Algorithm
    
    init(key: Data, algorithm: HMAC.Algorithm) {
        self.key = key
        self.algorithm = algorithm
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
        guard #available(macOS 10.12, iOS 10.0, *) else {
            Log.error("macOS 10.12.0 (Sierra) or higher or iOS 10.0 or higher is required by Cryptor")
            throw JWTError.osVersionToLow
        }
        guard let hmac = HMAC(using: algorithm, key: key).update(data: data)?.final() else {
            throw JWTError.invalidPrivateKey
        }
        #if swift(>=5.0)
        return Data(hmac)
        #else 
        return Data(bytes: hmac)
        #endif
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
        guard #available(macOS 10.12, iOS 10.0, *) else {
            return false
        }
        do {
            let expectedHMAC = try sign(data)
            return expectedHMAC == signature
        }
        catch {
            Log.error("Verification failed: \(error)")
            return false
        }
    }
}
