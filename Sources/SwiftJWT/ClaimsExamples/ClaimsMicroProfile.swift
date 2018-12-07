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

// MARK ClaimsMicroProfile

/// A class representing the MicroProfile claims as listed in [MicroProfile specs](http://microprofile.io/project/eclipse/microprofile-jwt-auth/spec/src/main/asciidoc/interoperability.asciidoc).
public class ClaimsMicroProfile: Claims {
    
    /// Initialize a `ClaimsMicroProfile`
    public init(
        iss: String,
        sub: String,
        exp: Date,
        iat: Date,
        jti: String,
        upn: String,
        groups: [String]
    ) {
        self.iss = iss
        self.sub = sub
        self.exp = exp
        self.iat = iat
        self.jti = jti
        self.upn = upn
        self.groups = groups
    }
    
    /**
     The MP-JWT issuer. [RFC7519, Section 4.1.1](https://tools.ietf.org/html/rfc7519#section-4.1.1)
     */
    public var iss: String
    
    /**
     Identifies the principal that is the subject of the JWT.
     */
    public var sub: String
    
    /**
     Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
     */
    public var exp: Date
    
    /**
     Identifies the time at which the JWT was issued.
     */
    public var iat: Date
    
    /**
     The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     The identifier value MUST be assigned in a manner that ensures that
     there is a negligible probability that the same value will be
     accidentally assigned to a different data object.
     */
    public var jti: String
    
    /**
    This MP-JWT custom claim is the user principal name in the java.security.Principal interface, and is the caller principal name in javax.security.enterprise.identitystore.IdentityStore. If this claim is missing, fallback to the "preferred_username", should be attempted, and if that claim is missing, fallback to the "sub" claim should be used.
     */
    public var upn: String?
    
    /**
     Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace.
     */
    public var preferred_username: String?
    
    /**
    This MP-JWT custom claim is the list of group names that have been assigned to the principal of the MP-JWT. This typically will required a mapping at the application container level to application deployment roles, but a one-to-one between group names and application role names is required to be performed in addition to any other mapping.
     */
    public var groups: [String]
}
