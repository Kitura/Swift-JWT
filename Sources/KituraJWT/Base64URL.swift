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

struct Base64URL {
    static func encode(_ data: Data) -> String? {
        let base64EncodedData = data.base64EncodedData()
        if let base64EncodedString = String(data: base64EncodedData, encoding: .utf8) {
            let base64URLEncodedString = base64EncodedString
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
            return base64URLEncodedString
        }
        return nil
    }
    
    static func decode(_ base64URLEncodedString: String) -> Data? {
        let paddingLength = 4 - base64URLEncodedString.characters.count % 4
        let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
        
        let base64EncodedString = base64URLEncodedString
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + padding
        
        return Data(base64Encoded: base64EncodedString)
    }
}
