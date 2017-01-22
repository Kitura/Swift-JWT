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

public struct JWT {
    public var header: Header
    public var claims: Claims
    
    public init(header: [HeaderKeys:Any], claims: [ClaimKeys:Any]) {
        self.header = Header(header)
        self.claims = Claims(claims)
    }
    
    public init(header: [HeaderKeys:Any], claims: [String:Any]) {
        self.header = Header(header)
        self.claims = Claims(claims)
    }
    
    init(header: [String:Any], claims: [String:Any]) {
        self.header = Header(header)
        self.claims = Claims(claims)
    }
    
    public mutating func sign(using algorithm: Algorithm) throws -> String? {
        header[.alg] = algorithm.name
        guard let encodedHeader = try header.encode(),
            let encodedClaims = try claims.encode() else {
                return nil
        }
        let encodedInput = encodedHeader + "." + encodedClaims
        guard let signature = algorithm.sign(encodedInput),
            let encodedSignature = Base64URL.encode(signature) else {
                return nil
        }
        return encodedInput + "." + encodedSignature
    }
    
    public static func verify(_ jwt: String, using algorithm: Algorithm) throws -> Bool {
        let components = jwt.components(separatedBy: ".")
        guard components.count == 3,
            let signature = Base64URL.decode(components[2]) else {
                return false
        }
        return algorithm.verify(signature: signature, for: components[0] + "." + components[1])
    }
    
    public static func decode(_ jwt: String) throws -> JWT? {
        let components = jwt.components(separatedBy: ".")
        guard components.count == 3,
            let headerData = Base64URL.decode(components[0]),
            let claimsData = Base64URL.decode(components[1]),
            let header = (try JSONSerialization.jsonObject(with: headerData)) as? [String:Any],
            let claims = (try JSONSerialization.jsonObject(with: claimsData)) as? [String:Any] else {
                return nil
        }
        return JWT(header: header, claims: claims)
    }
    
    public func verify(accessToken: String) -> Bool {
        guard let algorithm = header[.alg] as? String,
            let atHashValue = claims[.at_hash] as? String else {
            return false
        }
        guard let hash = Hash.hash(accessToken, using: algorithm) else {
            return false
        }
        
        let midpoint = hash.count / 2
        let firstHalf = Array(hash.prefix(upTo: midpoint))
        let data = Data(bytes: firstHalf, count: firstHalf.count)
        guard let hashed = Base64URL.encode(data) else {
            return false
        }
        
        return hashed == atHashValue
    }
}

