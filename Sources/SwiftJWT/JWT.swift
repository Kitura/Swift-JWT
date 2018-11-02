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
import Foundation

// MARK JWT

/**
 
 A struct representing the `Header` and `Claims` of a JSON Web Token.
 
 ### Usage Example: ###
 ````swift
 struct MyClaims: Claims {
    var name: String
 }
 let key = "<PrivateKey>".data(using: .utf8)!
 let jwt = JWT(claims: MyClaims(name: "Kitura"))
 let signedJWT: String = jwt.sign(using: .rs256(key: key, keyType: .privateKey))
 ````
 */

public struct JWT<T: Claims>: Codable {
    
    /// The JWT header.
    public var header: Header
    
    /// The JWT claims
    public var claims: T
    
    /// Initialize a `JWT` instance from a `Header` and `Claims`.
    ///
    /// - Parameter header: A JSON Web Token header object.
    /// - Parameter claims: A JSON Web Token claims object.
    /// - Returns: A new instance of `JWT`.
    public init(header: Header = Header(), claims: T) {
        self.header = header
        self.claims = claims
    }
    
    /// Initialize a `JWT` instance from a JWT String.
    /// The signature will be verified using the provided JWTVerifier.
    /// The time based standard JWT claims will be verified with `validateClaims()`.
    /// If the string is not a valid JWT, or the verification fails, the initializer returns nil.
    ///
    /// - Parameter jwt: A String with the encoded and signed JWT.
    /// - Parameter verifier: The `JWTVerifier` used to verify the JWT.
    /// - Returns: An instance of `JWT` if the decoding succeeds.
    public init?(jwtString: String, verifier: JWTVerifier = .none ) {
        let components = jwtString.components(separatedBy: ".")
        guard components.count == 2 || components.count == 3,
            JWT.verify(jwtString, using: verifier),
            let headerData = Data(base64urlEncoded: components[0]),
            let claimsData = Data(base64urlEncoded: components[1]),
            let header = try? JSONDecoder().decode(Header.self, from: headerData),
            let claims = try? JSONDecoder().decode(T.self, from: claimsData)
        else {
            return nil
        }
        self.header = header
        self.claims = claims
    }
    
    /// Sign the JWT using the given algorithm and encode the header, claims and signature as a JWT String.
    ///
    /// - Note: If header.alg is nil, will set header.alg with the name of the signing algorithm.
    ///
    /// - Parameter using algorithm: The algorithm to sign with.
    /// - Returns: A String with the encoded and signed JWT.
    /// - Throws: An error thrown during the encoding or signing.
    public mutating func sign(using jwtSigner: JWTSigner) -> String? {
        var tempHeader = header
        tempHeader.alg = jwtSigner.name
        guard let headerString = tempHeader.encode(), let claimsString = claims.encode() else {
            return nil
        }
        header.alg = jwtSigner.name
        return jwtSigner.sign(header: headerString, claims: claimsString)
    }

    /// Verify the signature of the encoded JWT using the given algorithm.
    ///
    /// - Parameter jwt: A String with the encoded and signed JWT.
    /// - Parameter using algorithm: The algorithm to verify with.
    /// - Returns: A Bool indicating whether the verification was successful.
    /// - Throws: An error thrown during the verification.
    public static func verify(_ jwt: String, using jwtVerifier: JWTVerifier) -> Bool {
        return jwtVerifier.verify(jwt: jwt)
    }

    /// Validate the time based standard JWT claims.
    /// This function checks that the "exp" (expiration time) is in the future
    /// and the "iat" (issued at) and "nbf" (not before) headers are in the past,
    ///
    /// - Returns: A value of `ValidateClaimsResult`.
    public func validateClaims() -> ValidateClaimsResult {        
        if let _ = claims.exp {
            if let expirationDate = claims.exp {
                if expirationDate < Date() {
                    return .expired
                }
            }
            else {
                return .invalidExpiration
            }
        }
        
        if let _ = claims.nbf {
            if let notBeforeDate = claims.nbf {
                if notBeforeDate > Date() {
                    return .notBefore
                }
            }
            else {
                return .invalidNotBefore
            }
        }
        
        if let _ = claims.iat {
            if let issuedAtDate = claims.iat {
                if issuedAtDate > Date() {
                    return .issuedAt
                }
            }
            else {
                return .invalidIssuedAt
            }
        }
        
        return .success
    }
}

