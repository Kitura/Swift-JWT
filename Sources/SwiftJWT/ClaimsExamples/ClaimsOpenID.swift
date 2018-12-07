/**
 * Copyright IBM Corporation 2018
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

// MARK ClaimsOpenID

/// A class representing OpenID related claims as decsribed in [OpenID specs](http://openid.net/specs/openid-connect-core-1_0.html).
public class ClaimsOpenID: Claims {
    
    /// Initalise the `ClaimsOpenID`
    public init(
        iss: String,
        sub: String,
        aud: [String],
        exp: Date,
        iat: Date,
        auth_time: Date? = nil,
        nonce: String? = nil,
        acr: String? = nil,
        amr: [String]? = nil,
        azp: String? = nil,
        name: String? = nil,
        given_name: String? = nil,
        family_name: String? = nil,
        middle_name: String? = nil,
        nickname: String? = nil,
        preferred_username: String? = nil,
        profile: String? = nil,
        picture: String? = nil,
        website: String? = nil,
        email: String? = nil,
        email_verified: Bool? = nil,
        gender: String? = nil,
        birthdate: String? = nil,
        zoneinfo: String? = nil,
        locale: String? = nil,
        phone_number: String? = nil,
        phone_number_verified: Bool? = nil,
        address: AddressClaim? = nil,
        updated_at: Date? = nil
    ) {
        self.iss = iss
        self.sub = sub
        self.aud = aud
        self.exp = exp
        self.iat = iat
        self.auth_time = auth_time
        self.nonce = nonce
        self.acr = acr
        self.amr = amr
        self.azp = azp
        self.name = name
        self.given_name = given_name
        self.family_name = family_name
        self.middle_name = middle_name
        self.nickname = nickname
        self.preferred_username = preferred_username
        self.profile = profile
        self.picture = picture
        self.website = website
        self.email = email
        self.email_verified = email_verified
        self.gender = gender
        self.birthdate = birthdate
        self.zoneinfo = zoneinfo
        self.locale = locale
        self.phone_number = phone_number
        self.phone_number_verified = phone_number_verified
        self.address = address
        self.updated_at = updated_at
    }
    
    // MARK: ID Token
    
    /// Issuer Identifier for the Issuer of the response. The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
    public var iss: String
    
    /// Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The sub value is case sensitive.
    public var sub: String
    
    /// Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences.
    public var aud: [String]
    
    /// Expiration time on or after which the ID Token MUST NOT be accepted for processing. The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
    public var exp: Date
    
    /// Time at which the JWT was issued.
    public var iat: Date
    
    /// Time when the End-User authentication occurred.
    public var auth_time: Date?

    /// String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce values used.
    public var nonce: String?
    
    /// Authentication Context Class Reference. String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied. The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 level 1. Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific.
    public var acr: String?
    
    /// Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in the authentication. For instance, values might indicate that both password and OTP authentication methods were used. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific.
    public var amr: [String]?
    
    /// Authorized party - the party to which the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID of this party. This Claim is only needed when the ID Token has a single audience value and that audience is different than the authorized party. It MAY be included even when the authorized party is the same as the sole audience.
    public var azp: String?
    
    // MARK: Standard Claims
    
    /// End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
    public var name: String?
    
    /// Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
    public var given_name: String?
    
    /// Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
    public var family_name: String?
    
    /// Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
    public var middle_name: String?
    
    /// Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
    public var nickname: String?
    
    /// Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace.
    public var preferred_username: String?
    
    /// URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
    public var profile: String?
    
    /// URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
    public var picture: String?
    
    ///  URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an organization that the End-User is affiliated with.
    public var website: String?
    
    /// End-User's preferred e-mail address.
    public var email: String?
    
    /// True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed. The means by which an e-mail address is verified is context-specific, and dependent upon the trust framework or contractual agreements within which the parties are operating.
    public var email_verified: Bool?
    
    /// End-User's gender. Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
    public var gender: String?
    
    /// End-User's birthday, represented as an ISO 8601:2004 YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
    public var birthdate: String?
    
    /// String from zoneinfo time zone database representing the End-User's time zone. For example, Europe/Paris or America/Los_Angeles.
    public var zoneinfo: String?
    
    /// End-User's locale, represented as a BCP47 language tag. This is typically an ISO 639-1 Alpha-2 language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
    public var locale: String?
    
    /// End-User's preferred telephone number. E.164 is RECOMMENDED as the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400.
    public var phone_number: String?
    
    /// True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed. The means by which a phone number is verified is context-specific, and dependent upon the trust framework or contractual agreements within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
    public var phone_number_verified: Bool?
    
    /// End-User's preferred postal address.
    public var address: AddressClaim?
    
    /// Time the End-User's information was last updated.
    public var updated_at: Date?
}

/// Struct representing an AddressClaim as defined in the [OpenID specs](http://openid.net/specs/openid-connect-core-1_0.html).
public struct AddressClaim: Codable {
    
    /// Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
    public var formatted: String?
    
    /// Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address information. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
    public var street_address: String?
    
    /// City or locality component.
    public var locality: String?
    
    /// State, province, prefecture, or region component.
    public var region: String?
    
    /// Zip code or postal code component.
    public var postal_code: String?
    
    /// Country name component.
    public var country: String?
    
}
