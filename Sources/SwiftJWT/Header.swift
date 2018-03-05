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

// MARK Header

/// A representation of a JSON Web Token header.
public struct Header {
    var headers: [String:Any]

    /// Initialize a `Header` instance.
    ///
    /// - Parameter header: An optional dictionary containing the claims with `HeaderKeys` as keys.
    /// - Returns: A new instance of `Header`.
    public init(_ header: [HeaderKeys:Any]?=nil) {
        self.headers = [String:Any]()
        if let header = header {
            for (key, value) in header {
                self.headers[key.rawValue] = value
            }
        }
    }
    
    init(_ header: [String:Any]) {
        headers = header
    }
    
    /// Return a header value for the key of type HeaderKeys.
    ///
    /// - Parameter key: The key.
    /// - Returns: The header value for the key.
    public subscript(key: HeaderKeys) -> Any? {
        get {
            return headers[key.rawValue]
        }
        
        set(newValue) {
            headers[key.rawValue] = newValue
        }
    }
    
    func encode() throws -> String? {
        let data = try JSONSerialization.data(withJSONObject: headers)
        return Base64URL.encode(data)
    }
}

/// A list of the available header keys. Can be used to create a Header, which would then be attached to a payload to form a JWT.
public enum HeaderKeys: String {
    /// Algorithm Header Parameter
    case alg
    /// JSON Web Token Set URL Header Parameter
    case jku
    /// JSON Web Key Header Parameter
    case jwk
    /// Key ID Header Parameter
    case kid
    /// X.509 URL Header Parameter
    case x5u
    /// X.509 Certificate Chain Header Parameter
    case x5c
    /// X.509 Certificate SHA-1 Thumbprint Header Parameter
    case x5t
    /// X.509 Certificate SHA-256 Thumbprint Header Parameter
    case x5tS256 = "x5t#S256"
    /// Type Header Parameter
    case typ
    /// Content Type Header Parameter
    case cty
    /// Critical Header Parameter
    case crit
}
