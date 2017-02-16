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
    /// - Parameter claims: An optional dictionary containing the claims with `ClaimsKeys` as keys.
    /// - Returns: A new instance of `Claims`.
    public init(_ claims: [ClaimKeys:Any]?=nil) {
        self.claims = [String:Any]()
        if let claims = claims {
            for (key, value) in claims {
                self.claims[key.rawValue] = value
            }
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
/// Standard JWT claims are described in [RFC7519](https://tools.ietf.org/html/rfc7519#section-4.1).
/// OpenID related claims are decsribed in [OpenID specs](http://openid.net/specs/openid-connect-core-1_0.html).
/// SIP related claims are listed in [RFC3261](https://tools.ietf.org/html/rfc3261).
/// Other claims are supported using a String as the key.
public enum ClaimKeys: String {
    /// Authentication Context Class Reference (OpenID)
    case acr

    /// Preferred postal address (OpenID)
    case address

    /// Authentication Methods References (OpenID)
    case amr

    /// Access Token hash value (OpenID)
    case at_hash

    /// Audience - standard JWT claim
    case aud

    /// Time when the authentication occurred (OpenID)
    case auth_time
    
    /// Authorized party - the party to which the ID Token was issued (OpenID)
    case azp
    
    /// Birthday (OpenID)
    case birthdate
    
    /// Code hash value (OpenID)
    case c_hash
    
    /// Confirmation ([RFC7800](https://tools.ietf.org/html/rfc7800))
    case cnf
    
    /// Preferred e-mail address (OpenID)
    case email

    /// True if the e-mail address has been verified; otherwise false (OpenID)
    case email_verified
    
    /// Expiration Time - standard JWT claim
    case exp

    /// Surname(s) or last name(s) (OpenID)
    case family_name

    /// Gender (OpenID)
    case gender

    /// Given name(s) or first name(s) (OpenID)
    case given_name

    /// Issued At - standard JWT claim
    case iat

    /// Issuer - standard JWT claim
    case iss

    /// JWT ID - standard JWT claim
    case jti

    /// Locale (OpenID)
    case locale

    /// Middle name(s) (OpenID)
    case middle_name

    /// Full name (OpenID)
    case name

    /// Not Before - standard JWT claim
    case nbf

    /// Casual name (OpenID)
    case nickname

    /// Value used to associate a Client session with an ID Token (OpenID)
    case nonce

    /// Preferred telephone number (OpenID)
    case phone_number

    /// True if the phone number has been verified; otherwise false (OpenID)
    case phone_number_verified

    /// Profile picture URL(OpenID)
    case picture

    /// Shorthand name by which the End-User wishes to be referred to (OpenID)
    case preferred_username

    /// Profile page URL (OpenID)
    case profile

    /// SIP Call-Id header field value
    case sip_callid
    
    /// SIP CSeq numeric header field parameter value
    case sip_cseq_num
    
    /// SIP Date header field value
    case sip_date
    
    /// SIP From tag header field parameter value
    case sip_from_tag
    
    /// SIP Via branch header field parameter value
    case sip_via_branch
    
    /// Subject - standard JWT claim
    case sub
    
    /// Public key used to check the signature of an ID Token (OpenID)
    case sub_jwk
    
    /// Time the information was last updated (OpenID)
    case updated_at
    
    /// Web page or blog URL (OpenID)
    case website
    
    /// Time zone (OpenID)
    case zoneinfo
}
