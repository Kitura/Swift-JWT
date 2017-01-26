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

// MARK Claims

/// A representation of JSON Web Token claims.
public struct Claims {
    var claims: [String:Any]
    
    /// Initialize a `Claims` instance.
    ///
    /// - Parameter claims: A dictionary containing the claims with `ClaimsKeys` as keys.
    /// - Returns: A new instance of `Claims`.
    public init(_ claims: [ClaimKeys:Any]) {
        self.claims = [String:Any]()
        for (key, value) in claims {
            self.claims[key.rawValue] = value
        }
    }
    
    /// Initialize a `Claims` instance.
    ///
    /// - Parameter claims: A dictionary containing the claims with String as keys type.
    /// - Returns: A new instance of `Claims`.
    public init(_ claims: [String:Any]) {
        self.claims = claims
    }
    
    /// Return a claim for the key of type ClaimKeys.
    ///
    /// - Parameter key: The key.
    /// - Returns: The claim for the key.
    public subscript(key: ClaimKeys) -> Any? {
        get {
            return claims[key.rawValue]
        }
        
        set(newValue) {
            claims[key.rawValue] = newValue
        }
    }
    
    /// Return a claim for the key of type String.
    ///
    /// - Parameter key: The key.
    /// - Returns: The claim for the key.
    public subscript(key: String) -> Any? {
        get {
            return claims[key]
        }
        
        set(newValue) {
            claims[key] = newValue
        }
    }
    
    /// Representation of the claims as a dictionary.
    public var asDictionary: [String:Any] {
        return claims
    }
    
    func encode() throws -> String? {
        let data = try JSONSerialization.data(withJSONObject: claims)
        return Base64URL.encode(data)
    }
}

/// A list of the [claims names](https://www.iana.org/assignments/jwt/jwt.xhtml).
/// Other claims are supported using a String as the key.
public enum ClaimKeys: String {
    case acr
    case address
    case amr
    case at_hash
    case aud
    case auth_time
    case azp
    case birthdate
    case c_hash
    case cnf
    case email
    case email_verified
    case exp
    case family_name
    case gender
    case given_name
    case iat
    case iss
    case jti
    case locale
    case middle_name
    case name
    case nbf
    case nickname
    case nonce
    case phone_number
    case phone_number_verified
    case picture
    case preferred_username
    case profile
    case sip_callid
    case sip_cseq_num
    case sip_date
    case sip_from_tag
    case sip_via_branch
    case sub
    case sub_jwk
    case updated_at
    case website
    case zoneinfo
}
