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

import Foundation

protocol EncryptionAlgorithm {
    @available(macOS 10.12, iOS 10.0, *)
    func sign(_ data: Data) -> Data?
    
    @available(macOS 10.12, iOS 10.0, *)
    func sign(_ string: String, encoding: String.Encoding) -> Data?
    
    @available(macOS 10.12, iOS 10.0, *)
    func verify(signature: Data, for data: Data) -> Bool
    
    @available(macOS 10.12, iOS 10.0, *)
    func verify(signature: Data, for string: String, encoding: String.Encoding) -> Bool
}

extension EncryptionAlgorithm {
    @available(macOS 10.12, iOS 10.0, *)
    func sign(_ string: String, encoding: String.Encoding = .utf8) -> Data? {
        return sign(string, encoding: encoding)
    }
    
    @available(macOS 10.12, iOS 10.0, *)
    func verify(signature: Data, for string: String, encoding: String.Encoding = .utf8) -> Bool {
        return verify(signature: signature, for: string, encoding: encoding)
    }   
}
