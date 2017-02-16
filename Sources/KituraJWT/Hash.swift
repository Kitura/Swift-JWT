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

// MARK Hash

/// A utility struct to perform SHA256/384/512 hash.
public struct Hash {
    
    /// Generate hash for the input string.
    ///
    /// - Parameter input: A String containg the input for the hash.
    /// - Parameter using algorithmName: A String containing the name of the JWT encryption algorithm.
    /// - Returns: The hashed data. Returns nil if something goes wrong.
    public static func hash(_ input: String, using algorithmName: String) -> [UInt8]? {
        var algorithm: Digest.Algorithm?
        let name = algorithmName.lowercased()
        switch algorithmName.lowercased() {
        case "rs256":
            algorithm = Digest.Algorithm.sha256
        case "rs384":
            algorithm = Digest.Algorithm.sha384
        case "rs512":
            algorithm = Digest.Algorithm.sha512
        default:
            return nil
        }
        
        guard let data = input.data(using: .utf8) else {
            return nil
        }
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        defer { ptr.deallocate(capacity: data.count) }
        data.copyBytes(to: ptr, count: data.count)
        return Digest(using: algorithm!).update(from: ptr, byteCount: data.count)?.final()
    }
}
