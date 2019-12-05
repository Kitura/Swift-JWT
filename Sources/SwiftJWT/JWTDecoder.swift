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
import KituraContracts

// MARK: JWTDecoder

/**
 A thread safe decoder that decodes either Data or a JWT String as a `JWT` instance and verifies the signiture using the provided algorithm.

 ### Usage Example: ###
 ```swift
 struct MyClaims: Claims {
    var name: String
 }
 let publicKey = "<PublicKey>".data(using: .utf8)!
 let rsaJWTDecoder = JWTDecoder(jwtVerifier: JWTVerifier.rs256(publicKey: publicKey))
 do {
    let jwt = try rsaJWTDecoder.decode(JWT<MyClaims>.self, fromString: exampleJWTString)
 } catch {
    print("Failed to decode JWT: \(error)")
 }
 ```
 */
public class JWTDecoder: BodyDecoder {
    
    let keyIDToVerifier: (String) -> JWTVerifier?
    let jwtVerifier: JWTVerifier?
    
    // MARK: Initializers
    
    /// Initialize a `JWTDecoder` instance with a single `JWTVerifier`.
    ///
    /// - Parameter JWTVerifier: The `JWTVerifier` that will be used to verify the signiture of the JWT.
    /// - Returns: A new instance of `JWTDecoder`.
    public init(jwtVerifier: JWTVerifier) {
        self.keyIDToVerifier = {_ in return jwtVerifier }
        self.jwtVerifier = jwtVerifier
    }
    
    /// Initialize a `JWTDecoder` instance with a function to generate the `JWTVerifier` from the JWT `kid` header.
    ///
    /// - Parameter keyIDToVerifier: The function that will generate the `JWTVerifier` using the "kid" header.
    /// - Returns: A new instance of `JWTDecoder`.
    public init(keyIDToVerifier: @escaping (String) -> JWTVerifier?) {
        self.keyIDToVerifier = keyIDToVerifier
        self.jwtVerifier = nil
    }
    
    // MARK: Decode
    
    /// Decode a `JWT` instance from a JWT String.
    ///
    /// - Parameter type: The JWT type the String will be decoded as.
    /// - Parameter fromString: The JWT String that will be decoded.
    /// - Returns: A `JWT` instance of the provided type.
    /// - throws: `JWTError.invalidJWTString` if the provided String is not in the form mandated by the JWT specification.
    /// - throws: `JWTError.invalidKeyID` if the KeyID `kid` header fails to generate a jwtVerifier.
    /// - throws: `JWTError.failedVerification` if the `JWTVerifier` fails to verify the decoded String.
    /// - throws: `DecodingError` if the decoder fails to decode the String as the provided type.
    public func decode<T : Decodable>(_ type: T.Type, fromString: String) throws -> T {
        // Seperate the JWT into the headers and claims.
        let components = fromString.components(separatedBy: ".")
        guard components.count > 1,
         let headerData = JWTDecoder.data(base64urlEncoded: components[0]),
            let claimsData = JWTDecoder.data(base64urlEncoded: components[1])
        else {
            throw JWTError.invalidJWTString
        }
        
        // Decode the JWT headers and claims data into a _JWTDecoder.
        let decoder = _JWTDecoder(header: headerData, claims: claimsData)
        let jwt = try decoder.decode(type)
        
        let _jwtVerifier: JWTVerifier
        // Verify the JWT String using the JWTDecoder constant jwtVerifier.
        if let jwtVerifier = jwtVerifier {
            _jwtVerifier = jwtVerifier
        } else {
            // The JWTVerifier is generated using the kid Header that was read inside the _JWTDecoder
            // and then used to verify the JWT.
            guard let keyID = decoder.keyID, let jwtVerifier = keyIDToVerifier(keyID) else {
                throw JWTError.invalidKeyID
            }
            _jwtVerifier = jwtVerifier
        }
        guard _jwtVerifier.verify(jwt: fromString) else {
            throw JWTError.failedVerification
        }
        return jwt
    }
    
    /// Decode a `JWT` instance from a utf8 encoded JWT String.
    ///
    /// - Parameter type: The JWT type the Data will be decoded as.
    /// - Parameter data: The utf8 encoded JWT String that will be decoded.
    /// - Returns: A `JWT` instance of the provided type.
    /// - throws: `JWTError.invalidUTF8Data` if the provided Data can't be decoded to a String.
    /// - throws: `JWTError.invalidJWTString` if the provided String is not in the form mandated by the JWT specification.
    /// - throws: `JWTError.invalidKeyID` if the KeyID `kid` header fails to generate a `JWTVerifier`.
    /// - throws: `JWTError.failedVerification` if the `JWTVerifier` fails to verify the decoded String.
    /// - throws: `DecodingError` if the decoder fails to decode the String as the provided type.
    public func decode<T : Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard let jwtString = String(data: data, encoding: .utf8) else {
            throw JWTError.invalidUTF8Data
        }
        return try decode(type, fromString: jwtString)
    }
}

/*
 The JWTDecoder creates it's own instance of _JWTDecoder everytime the decode function is called.
 This is because the _JWTDecoder changes it's own value so we can only have one thread using it at a time.
 The following is the code generated by codable and called by JWTDecoder.decode(type:, fromString:) for a JWT<MyClaims> struct:
 ```
 enum MyStructKeys: String, CodingKey {
     case header, claims
 }
 init(from decoder: Decoder) throws {
     let container = try decoder.container(keyedBy: MyStructKeys.self) // defining our (keyed) container
     let header: Header = try container.decode(Header.self, forKey: .header) // extracting the data
     let claims: MyClaims = try container.decode(MyClaims.self, forKey: .claims) // extracting the data
     self.init(header: header, claims: claims) // initializing our struct
 }
 ```
 Where decoder is a _JWTDecoder instance, and MyClaims is the user defined object conforming to Claims.
 */
fileprivate class _JWTDecoder: Decoder {
    
    init(header: Data, claims: Data) {
        self.header = header
        self.claims = claims
    }
    
    var header: Data
    
    var claims: Data
    
    var keyID: String?
    
    var codingPath: [CodingKey] = []
    
    var userInfo: [CodingUserInfoKey : Any] = [:]
    
    // Call the Codable Types init from decoder function.
    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        return try type.init(from: self)
    }
    
    // JWT should only be a Keyed container
    func container<Key : CodingKey>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> {
        let container = _JWTKeyedDecodingContainer<Key>(decoder: self, header: header, claims: claims)
        return KeyedDecodingContainer(container)
    }
    
    // This function should not be called when decoding a JWT
    func unkeyedContainer() throws -> UnkeyedDecodingContainer {
        return UnkeyedContainer(decoder: self)
    }
    
    // This function should not be called when decoding a JWT
    func singleValueContainer() throws -> SingleValueDecodingContainer {
        return UnkeyedContainer(decoder: self)
    }
}

private struct _JWTKeyedDecodingContainer<Key: CodingKey>: KeyedDecodingContainerProtocol {
    
    // A reference to the Decoder the container is inside
    let decoder: _JWTDecoder
    
    var header: Data
    
    var claims: Data
    
    var codingPath: [CodingKey]
    
    public var allKeys: [Key]
    {
        #if swift(>=4.1)
            return ["header", "claims"].compactMap { Key(stringValue: $0) }
        #else
            return ["header", "claims"].flatMap { Key(stringValue: $0) }
        #endif
    }
    
    fileprivate init(decoder: _JWTDecoder, header: Data, claims: Data) {
        self.decoder = decoder
        self.header = header
        self.claims = claims
        self.codingPath = decoder.codingPath
    }
    
    public func contains(_ key: Key) -> Bool {
        return key.stringValue == "header" || key.stringValue == "claims"
    }
    
    // The JWT Class should only have to decode Decodable types
    // Those types will be a `Header` object and a generic `Claims` object.
    func decode<T : Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
        decoder.codingPath.append(key)
        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        if key.stringValue == "header" {
            let header = try jsonDecoder.decode(Header.self, from: self.header)
            decoder.keyID = header.kid
            guard let decodedHeader = header as? T else {
                throw DecodingError.typeMismatch(T.self, DecodingError.Context(codingPath: codingPath, debugDescription: "Type of header key was not a JWT Header"))
            }
            return decodedHeader
        } else
        if key.stringValue == "claims" {
            return try jsonDecoder.decode(type, from: claims)
        } else {
            throw DecodingError.keyNotFound(key, DecodingError.Context(codingPath: codingPath, debugDescription: "value not found for provided key"))
        }
    }
    
// No functions beyond this point should be called when decoding JWT, However the functions are required by KeyedDecodingContainerProtocol.
    func decodeNil(forKey key: Key) throws -> Bool {
        throw DecodingError.typeMismatch(Key.self, DecodingError.Context(codingPath: codingPath, debugDescription: "JWTDecoder can only Decode JWT tokens"))
    }
    
    func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> where NestedKey : CodingKey {
        return try decoder.container(keyedBy: type)
    }
    
    func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
        return try decoder.unkeyedContainer()
    }
    
    func superDecoder() throws -> Decoder {
        return decoder
    }
    
    func superDecoder(forKey key: Key) throws -> Decoder {
        return decoder
    }
}

// When decoding a JWT you should not have an UnkeyedContainer
private struct UnkeyedContainer: UnkeyedDecodingContainer, SingleValueDecodingContainer {
    var decoder: _JWTDecoder
    
    var codingPath: [CodingKey] { return [] }
    
    var count: Int? { return nil }
    
    var currentIndex: Int { return 0 }
    
    var isAtEnd: Bool { return false }
    
    func decode<T: Decodable>(_ type: T.Type) throws -> T {
        throw DecodingError.typeMismatch(type, DecodingError.Context(codingPath: codingPath, debugDescription: "JWTDecoder can only Decode JWT tokens"))
    }
    
    func decodeNil() -> Bool {
        return true
    }
    
    func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey : CodingKey {
        return try decoder.container(keyedBy: type)
    }
    
    func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
        return self
    }
    
    func superDecoder() throws -> Decoder {
        return decoder
    }
}
