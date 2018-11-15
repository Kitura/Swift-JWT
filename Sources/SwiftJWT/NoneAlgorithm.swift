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

/// An EncryptionAlgorithm representing an alg of "none" in a JWT.
/// Using this algorithm means the header and claims will not be signed or verified.
struct NoneAlgorithm: VerifierAlgorithm, SignerAlgorithm {
    
    let name: String = "none"
    
    func sign(header: String, claims: String) -> String {
        return header + "." + claims
    }
    
    func verify(jwt: String) -> Bool {
        return true
    }
}
