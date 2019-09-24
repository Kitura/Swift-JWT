/**
 * Copyright IBM Corporation 2017-2019
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

/// Convenience extensions to `Data` for converting to and from base64url encoding.
extension Data {

    /// Returns a `String` representation of this data, encoded in base64url format
    /// as defined in RFC4648 (https://tools.ietf.org/html/rfc4648).
    ///
    /// This is the appropriate format for encoding the header and claims of a JWT.
    public func base64urlEncodedString() -> String {
        let result = self.base64EncodedString()
        return result.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    /// Initializes a new `Data` from the base64url-encoded `String` provided. The
    /// base64url encoding is defined in RFC4648 (https://tools.ietf.org/html/rfc4648).
    ///
    /// This is appropriate for reading the header or claims portion of a JWT string.
    public init?(base64urlEncoded: String) {
        let paddingLength = 4 - base64urlEncoded.count % 4
        let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
        let base64EncodedString = base64urlEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + padding
        self.init(base64Encoded: base64EncodedString)
    }
}
