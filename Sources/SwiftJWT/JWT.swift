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
 let jwt = JWT(header: Header(), claims: MyClaims(name: "Kitura"))
 let signedJWT: String = jwt.sign(using: .rs256(key: key, keyType: .privateKey))
 ````
 */

public struct JWT<T: Claims>: Codable {
    
    /// The JWT header.
    public var header: Header
    
    /// The JWT claims
    public var claims: T
    
    /// Initialize a `JWT` instance.
    ///
    /// - Parameter header: A JSON Web Token header object.
    /// - Parameter claims: A JSON Web Token claims object.
    /// - Returns: A new instance of `JWT`.
    public init(header: Header, claims: T) {
        self.header = header
        self.claims = claims
    }
    
    /// Encode the Header and claims of the JWT with no signature.
    ///
    /// - Note: If header.alg is nil, will set header.alg as "none".
    ///
    /// - Returns: A String with the encoded Header and Claims.
    /// - Throws: An error thrown during the encoding.
    public mutating func encode() throws -> String? {
        return try self.sign(using: .none())
    }
    
    /// Sign the JWT using the given algorithm and encode the header, claims and signature as a JWT String.
    ///
    /// - Note: If header.alg is nil, will set header.alg with the name of the signing algorithm.
    ///
    /// - Parameter using algorithm: The algorithm to sign with.
    /// - Returns: A String with the encoded and signed JWT.
    /// - Throws: An error thrown during the encoding or signing.
    public mutating func sign(using algorithm: Algorithm) throws -> String? {
        header.alg = algorithm.name
        guard let headerString = try header.encode(),
              let claimsString = try claims.encode(),
              let encodedJwt = algorithm.generateJWT(header: headerString, claims: claimsString)
        else {
            return nil
        }
        return encodedJwt
    }

    /// Verify the signature of the encoded JWT using the given algorithm.
    ///
    /// - Parameter jwt: A String with the encoded and signed JWT.
    /// - Parameter using algorithm: The algorithm to verify with.
    /// - Returns: A Bool indicating whether the verification was successful.
    /// - Throws: An error thrown during the verification.
    public static func verify(_ jwt: String, using algorithm: Algorithm) throws -> Bool {
        return algorithm.verify(jwt)
    }
    
    /// Decode the encoded JWT.
    ///
    /// - Parameter jwt: A String with the encoded and signed JWT.
    /// - Parameter using: The `Algorithm` used to verify the JWT.
    /// - Returns: An instance of `JWT` if the decoding succeeds.
    /// - Throws: An error thrown during the decoding.
    public static func decode(_ jwt: String, using algorithm: Algorithm = .none()) throws -> JWT<T>? {
        
        let components = jwt.components(separatedBy: ".")
        guard components.count == 2 || components.count == 3,
            try JWT.verify(jwt, using: algorithm),
            let headerData = Base64URL.decode(components[0]),
            let claimsData = Base64URL.decode(components[1]),
            let header = try? JSONDecoder().decode(Header.self, from: headerData),
            let claims = try? JSONDecoder().decode(T.self, from: claimsData) else {
                return nil
        }
        return JWT<T>(header: header, claims: claims)
    }

    /// Validate the time based standard JWT claims are valid.
    /// This function checks that the "exp" (expiration time) is in the future
    /// and the "iat" (issued at) and "nbf" (not before) are in the past,
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

