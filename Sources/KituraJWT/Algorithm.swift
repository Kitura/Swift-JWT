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


public enum Algorithm {
    case rs256(Data, RSAKeyType)
    case rs384(Data, RSAKeyType)
    case rs512(Data, RSAKeyType)
    
    public var name: String {
        switch self {
        case .rs256:
            return "RS256"
        case .rs384:
            return "RS384"
        case .rs512:
            return "RS512"
        }
    }
    
    func sign(_ input: String) -> Data? {
        return encryptionAlgortihm.sign(input)
    }
    
    func verify(signature: Data, for input: String) -> Bool {
        return encryptionAlgortihm.verify(signature: signature, for: input)
    }
    
    var encryptionAlgortihm: EncryptionAlgorithm {
        switch self {
        case .rs256(let key, let type):
            return RSA(key: key, keyType: type, algorithm: .sha256)
        case .rs384(let key, let type):
            return RSA(key: key, keyType: type, algorithm: .sha384)
        case .rs512(let key, let type):
            return RSA(key: key, keyType: type, algorithm: .sha512)
        }
    }
    
    public static func from(name: String, key: Data, keyType: RSAKeyType = .publicKey) -> Algorithm? {
        if name == "RS256" || name == "rs256" {
            return .rs256(key, keyType)
        }
        if name == "RS384" || name == "rs384" {
            return .rs384(key, keyType)
        }
        if name == "RS512" || name == "rs512" {
            return .rs512(key, keyType)
        }
        return nil
    }
}
