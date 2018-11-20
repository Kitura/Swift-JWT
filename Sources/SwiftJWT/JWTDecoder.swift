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
 let rsaPublicKey = read(fileName: "rsa_public_key")
 let rsaJWTDecoder = JWTDecoder(algorithm: Algorithm.rs256(rsaPublicKey, .publicKey))
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
    
    /// Initialize a `JWTDecoder` instance.
    ///
    /// - Parameter algorithm: The `Algorithm` that will be used to verify the signiture of the JWT.
    /// - Returns: A new instance of `JWTDecoder`.
    public init(jwtVerifier: JWTVerifier) {
        self.keyIDToVerifier = {_ in return jwtVerifier }
        self.jwtVerifier = jwtVerifier
    }
    
    /// Initialize a `JWTDecoder` instance which will select the Algorithm key based on the "kid" header.
    ///
    /// - Parameter algorithmGenerator: The function that will generate the `Algorithm` using the "kid" header.
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
    /// - throws: `JWTError.invalidJWTString` if the provided String is not base64urlEncoded sections seperated by full stops.
    /// - throws: `JWTError.invalidKeyID` if the KeyID `kid` header fails to generate a jwtVerifier.
    /// - throws: `JWTError.failedVerification` if the `JWTVerifier` fails to verify the decoded String.
    /// - throws: `DecodingError` if the decoder fails to decode the String as the provided type.
    public func decode<T : Decodable>(_ type: T.Type, fromString: String) throws -> T {
        let components = fromString.components(separatedBy: ".")
        guard let headerData = Data(base64urlEncoded: components[0]),
              let claimsData = Data(base64urlEncoded: components[1])
        else {
            throw JWTError.invalidJWTString
        }
        let jwtContainer: [String: Data] = ["header": headerData, "claims": claimsData]
        let _jwtVerifier: JWTVerifier
        if let jwtVerifier = jwtVerifier {
            _jwtVerifier = jwtVerifier
        } else {
            let receivedHeader = try JSONDecoder().decode(Header.self, from: headerData)
            guard let keyID = receivedHeader.kid, let jwtVerifier = keyIDToVerifier(keyID) else {
                throw JWTError.invalidKeyID
            }
            _jwtVerifier = jwtVerifier
        }
        guard _jwtVerifier.verify(jwt: fromString) else {
            throw JWTError.failedVerification
        }
        let decoder = _JWTDecoder(referencing: jwtContainer)
        return try decoder.decode(type)
    }
    
    /// Decode a `JWT` instance from a utf8 encoded JWT String.
    ///
    /// - Parameter type: The JWT type the Data will be decoded as.
    /// - Parameter data: The utf8 encoded JWT String that will be decoded.
    /// - Returns: A `JWT` instance of the provided type.
    /// - throws: `JWTError.invalidUTF8Data` if the provided Data can't be decoded to a String.
    /// - throws: `JWTError.invalidJWTString` if the provided String is not base64urlEncoded sections seperated by full stops.
    /// - throws: `JWTError.invalidKeyID` if the KeyID `kid` header fails to generate a jwtVerifier.
    /// - throws: `JWTError.failedVerification` if the `JWTVerifier` fails to verify the decoded String.
    /// - throws: `DecodingError` if the decoder fails to decode the String as the provided type.
    public func decode<T : Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard let jwtString = String(data: data, encoding: .utf8) else {
            throw JWTError.invalidUTF8Data
        }
        return try decode(type, fromString: jwtString)
    }
}

fileprivate class _JWTDecoder: Decoder {
    
    init(referencing container: [String: Data]) {
        self.container = container
    }
    
    var container: [String: Data]
    
    var codingPath: [CodingKey] = []
    
    var userInfo: [CodingUserInfoKey : Any] = [:]
    
    // Call the Codable Types init from decoder function.
    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        return try type.init(from: self)
    }
    
    // JWT should only be a Keyed container
    func container<Key : CodingKey>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> {
        let container = _JWTKeyedDecodingContainer<Key>(decoder: self, wrapping: self.container)
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
    
    /// A reference to the container we're reading from.
    private let container: [String : Data]
    
    var codingPath: [CodingKey]
    
    public var allKeys: [Key] {
        #if swift(>=4.1)
        return self.container.keys.compactMap { Key(stringValue: $0) }
        #else
        return self.container.keys.flatMap { Key(stringValue: $0) }
        #endif
    }
    
    fileprivate init(decoder: _JWTDecoder, wrapping container: [String : Data]) {
        self.decoder = decoder
        self.container = container
        self.codingPath = decoder.codingPath
    }
    
    public func contains(_ key: Key) -> Bool {
        return self.container[key.stringValue] != nil
    }
    
    // The JWT Class should only have to decode Decodable types
    func decode<T : Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
        decoder.codingPath.append(key)
        guard let data = self.container[key.stringValue] else {
            throw DecodingError.keyNotFound(key, DecodingError.Context(codingPath: codingPath, debugDescription: "value not found for provided key"))
        }
        return try JSONDecoder().decode(type, from: data)
    }
    
    // No functions beyond this point should be called when decoding JWT, However the functions are required KeyedDecodingContainerProtocol.
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
