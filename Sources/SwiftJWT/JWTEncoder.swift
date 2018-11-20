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

// MARK: JWTEncoder

/**
 A thread safe encoder that signs the JWT header and claims using the provided algorithm and encodes a `JWT` instance as either data or a JWT String.
 
 ### Usage Example: ###
 ```swift
 struct MyClaims: Claims {
    var name: String
 }
 var jwt = JWT(claims: MyClaims(name: "John Doe"))
 let rsaPrivateKey = read(fileName: "rsa_private_key")
 let rsaJWTEncoder = JWTEncoder(algorithm: Algorithm.rs256(rsaPrivateKey, .privateKey))
 do {
    let jwtString = try rsaJWTEncoder.encodeToString(jwt)
 } catch {
    print("Failed to encode JWT: \(error)")
 }
 ```
 */
public class JWTEncoder: BodyEncoder {
    
    let keyIDToSigner: (String) -> JWTSigner?
    let jwtSigner: JWTSigner?
    let header: Header?
    
    // MARK: Initializers
    
    /// Initialize a `JWTEncoder` instance.
    ///
    /// - Parameter algorithm: The `Algorithm` that will be used to sign the JWT.
    /// - Returns: A new instance of `JWTEncoder`.
    public init(jwtSigner: JWTSigner, header: Header? = nil) {
        self.keyIDToSigner = {_ in return jwtSigner }
        self.jwtSigner = jwtSigner
        self.header = header
    }
    
    /// Initialize a `JWTEncoder` instance.
    ///
    /// - Parameter algorithm: The `Algorithm` that will be used to sign the JWT.
    /// - Returns: A new instance of `JWTEncoder`.
    public init(keyIDToSigner: @escaping (String) -> JWTSigner?, header: Header? = nil) {
        self.keyIDToSigner = keyIDToSigner
        self.header = header
        self.jwtSigner = nil
    }
    
    // MARK: Encode
    
    /// Encode a `JWT` instance into a utf8 encoded JWT String.
    ///
    /// - Parameter value: The JWT instance to be encoded as Data.
    /// - Returns: The utf8 encoded JWT String.
    /// - throws: An error if any value throws an error during Encoding.
    public func encode<T : Encodable>(_ value: T) throws -> Data {
        guard let jwt = try self.encodeToString(value).data(using: .utf8) else {
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: [], debugDescription: "Failed to encode String to utf8"))
        }
        return jwt
    }
    
    /// Encode a `JWT` instance as a JWT String.
    ///
    /// - Parameter value: The JWT instance to be encoded as a JWT String.
    /// - Returns: A JWT String.
    /// - throws: An error if any value throws an error during encoding.
    public func encodeToString<T : Encodable>(_ value: T) throws -> String {
        let encoder = _JWTEncoder()
        try value.encode(to: encoder)
        var _header: Header
        if let header = header {
            _header = header
        } else {
            guard let headerString = encoder.header, let headerData = Data(base64urlEncoded: headerString) else {
                throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: [], debugDescription: "Failed to encode into header CodingKey"))
            }
            let newHeader = try JSONDecoder().decode(Header.self, from: headerData)
            _header = newHeader
        }
        guard let claims = encoder.claims else {
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: [], debugDescription: "Failed to encode into claims CodingKey"))
        }
        let _jwtSigner: JWTSigner
        if let jwtSigner = jwtSigner {
            _jwtSigner = jwtSigner
        } else {
            guard let keyID = _header.kid, let keyIDJWTSigner = keyIDToSigner(keyID) else {
                throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: [], debugDescription: "No kid header field provided when encoding using KeyID"))
            }
            _jwtSigner = keyIDJWTSigner
        }
        _header.alg = _jwtSigner.name
        do {
            let encodedHeader =  try _header.encode()
            return try _jwtSigner.sign(header: encodedHeader, claims: claims)
        } catch {
            throw error
        }
    }
}

fileprivate class _JWTEncoder: Encoder {
    
    init() {}
    
    var header: String?
    var claims: String?
    
    var codingPath: [CodingKey] = []
    
    var userInfo: [CodingUserInfoKey : Any] = [:]
    
    // We will be provided a keyed container representing the JWT instance
    func container<Key : CodingKey>(keyedBy type: Key.Type) -> KeyedEncodingContainer<Key> {
        let container = _JWTKeyedEncodingContainer<Key>(encoder: self, codingPath: self.codingPath)
        return KeyedEncodingContainer(container)
    }
    
    private struct _JWTKeyedEncodingContainer<Key: CodingKey>: KeyedEncodingContainerProtocol {
        
        /// A reference to the encoder we're writing to.
        let encoder: _JWTEncoder
        
        var codingPath: [CodingKey]
        
        // Set the Encoder header and claims Strings using the container
        mutating func encode<T : Encodable>(_ value: T, forKey key: Key) throws {
            self.codingPath.append(key)
            let fieldName = key.stringValue
            let data = try JSONEncoder().encode(value)
            if fieldName == "header" {
                encoder.header = data.base64urlEncodedString()
            } else if fieldName == "claims" {
                encoder.claims = data.base64urlEncodedString()
            }
        }
        
        // No functions beyond this point should be called for encoding a JWT token
        mutating func nestedContainer<NestedKey>(keyedBy keyType: NestedKey.Type, forKey key: Key) -> KeyedEncodingContainer<NestedKey> where NestedKey : CodingKey {
            return encoder.container(keyedBy: keyType)
        }
        
        mutating func nestedUnkeyedContainer(forKey key: Key) -> UnkeyedEncodingContainer {
            return encoder.unkeyedContainer()
        }
        
        mutating func superEncoder() -> Encoder {
            return encoder
        }
        
        mutating func superEncoder(forKey key: Key) -> Encoder {
            return encoder
        }
        
        // Throw if trying to encode something other than a JWT token
        mutating func encodeNil(forKey key: Key) throws {
            throw EncodingError.invalidValue(key, EncodingError.Context(codingPath: codingPath, debugDescription: "JWTEncoder can only encode JWT tokens"))
        }

    }
    
    func unkeyedContainer() -> UnkeyedEncodingContainer {
        return UnkeyedContainer(encoder: self)
    }
    
    func singleValueContainer() -> SingleValueEncodingContainer {
        return UnkeyedContainer(encoder: self)
    }
    
    // This Decoder should not be used to decode UnkeyedContainer
    private struct UnkeyedContainer: UnkeyedEncodingContainer, SingleValueEncodingContainer {
        var encoder: _JWTEncoder
        
        var codingPath: [CodingKey] { return [] }
        
        var count: Int { return 0 }
        
        func nestedContainer<NestedKey>(keyedBy keyType: NestedKey.Type) -> KeyedEncodingContainer<NestedKey> where NestedKey : CodingKey {
            return encoder.container(keyedBy: keyType)
        }
        
        func nestedUnkeyedContainer() -> UnkeyedEncodingContainer {
            return self
        }
        
        func superEncoder() -> Encoder {
            return encoder
        }
        
        func encodeNil() throws {}
        
        func encode<T>(_ value: T) throws where T : Encodable {
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: codingPath, debugDescription: "JWTEncoder can only encode JWT tokens"))
        }
    }
}
