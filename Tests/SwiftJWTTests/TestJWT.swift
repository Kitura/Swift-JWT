/**
 Copyright IBM Corporation 2017
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import XCTest
import Foundation
#if os(Linux)
    import Glibc
#elseif os(OSX)
    import Darwin
#endif

@testable import SwiftJWT

let rsaPrivateKey = read(fileName: "rsa_private_key")
let rsaPublicKey = read(fileName: "rsa_public_key")

let certPrivateKey = read(fileName: "cert_private_key")
let certificate = read(fileName: "certificate")

@available(macOS 10.12, iOS 10.0, *)
class TestJWT: XCTestCase {
    
    static var allTests: [(String, (TestJWT) -> () throws -> Void)] {
        return [
            ("testSignAndVerify", testSignAndVerify),
            ("testJWT", testJWT),
            ("testSupported", testSupported),
        ]
    }
    
    func testSignAndVerify() {
        var jwt = JWT(header: Header([.alg:"rs256"]), claims: Claims([.name:"Kitura"]))
        jwt.claims[.name] = "Kitura-JWT"
        XCTAssertEqual(jwt.claims[.name] as! String, "Kitura-JWT")
        jwt.claims[.iss] = "issuer"
        jwt.claims[.aud] = ["clientID"]
        jwt.claims[.iat] = "1485949565.58463"
        jwt.claims[.exp] = "2485949565.58463"
        jwt.claims[.nbf] = "1485949565.58463"
        
        do {
            // encode
            if let encoded = try jwt.encode() {
                if let decoded = try JWT.decode(encoded) {
                    check(jwt: decoded, algorithm: "none")
                    
                    XCTAssertEqual(decoded.validateClaims(issuer: "issuer", audience: "clientID"), .success, "Validation failed")
                }
                else {
                    XCTFail("Failed to decode")
                }
            }
            else {
                XCTFail("Failed to encode")
            }
           
            // public key
            if let signed = try jwt.sign(using: .rs256(rsaPrivateKey, .privateKey)) {
                let ok = try JWT.verify(signed, using: .rs256(rsaPublicKey, .publicKey))
                XCTAssertTrue(ok, "Verification failed")
                
                if let decoded = try JWT.decode(signed) {
                    check(jwt: decoded, algorithm: "RS256")
                    
                    XCTAssertEqual(decoded.validateClaims(issuer: "issuer", audience: "clientID"), .success, "Validation failed")
                }
                else {
                    XCTFail("Failed to decode")
                }
            }
            else {
                XCTFail("Failed to sign")
            }
            
            // certificate
            if let signed = try jwt.sign(using: .rs256(certPrivateKey, .privateKey)) {
                let ok = try JWT.verify(signed, using: .rs256(certificate, .certificate))
                XCTAssertTrue(ok, "Verification failed")
                
                if let decoded = try JWT.decode(signed) {
                    check(jwt: decoded, algorithm: "RS256")
                    
                    XCTAssertEqual(decoded.validateClaims(issuer: "issuer", audience: "clientID"), .success, "Validation failed")
                }
                else {
                    XCTFail("Failed to decode")
                }
            }
            else {
                XCTFail("Failed to sign")
            }

        }
        catch {
            XCTFail("Failed to sign, verify or decode")
        }
    }
    
    func check(jwt: JWT, algorithm: String) {
        XCTAssertEqual(jwt.header.headers.count, 1, "Wrong number of header fields")
        XCTAssertEqual(jwt.claims.claims.count, 6, "Wrong number of claims")

        XCTAssertEqual(jwt.header[.alg] as! String, algorithm, "Wrong .alg in decoded")
        XCTAssertEqual(jwt.claims[.iss] as! String, "issuer", "Wrong .iss in decoded")
        XCTAssertEqual(jwt.claims[.aud] as! [String], ["clientID"], "Wrong .aud in decoded")
        XCTAssertEqual(jwt.claims[.exp] as! String, "2485949565.58463", "Wrong .exp in decoded")
        XCTAssertEqual(jwt.claims[.iat] as! String, "1485949565.58463", "Wrong .iat in decoded")
        XCTAssertEqual(jwt.claims[.nbf] as! String, "1485949565.58463", "Wrong .nbf in decoded")
    }
    
    // From jwt.io
    func testJWT() {
        let encoded = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE"
        let publicKey = read(fileName: "jwt_public")
        
        do {
            let ok = try JWT.verify(encoded, using: .rs256(publicKey, .publicKey))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = try JWT.decode(encoded) {
                XCTAssertEqual(decoded.header[.alg] as! String, "RS256", "Wrong .alg in decoded")
                XCTAssertEqual(decoded.header[.typ] as! String, "JWT", "Wrong .typ in decoded")
                XCTAssertEqual(decoded.header.headers.count, 2, "Wrong number of header fields")
                
                XCTAssertEqual(decoded.claims[.sub] as! String, "1234567890", "Wrong .sub in decoded")
                XCTAssertEqual(decoded.claims[.name] as! String, "John Doe", "Wrong .name in decoded")
                XCTAssertEqual(decoded.claims["admin"] as! Bool, true, "Wrong .admin in decoded")
                XCTAssertEqual(decoded.claims.claims.count, 3, "Wrong number of claims")
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
        catch {
            XCTFail("Failed to sign, verify or decode")
        }
    }
    
    func testSupported() {
        var supported = Algorithm.isSupported(name: "rS512")
        XCTAssertEqual(supported, .supportedWithKey, "isSupported failed for supported algorithm")
        
        supported = Algorithm.isSupported(name: "kitura")
        XCTAssertEqual(supported, .unsupported, "isSupported failed for unsupported algorithm")
        
        var algorithm = Algorithm.for(name: "Rs256", key: rsaPublicKey, keyType: .certificate)
        XCTAssertNotNil(algorithm, "Failed to create Algorithm")
        
        algorithm = Algorithm.for(name: "HMAC512", key: rsaPrivateKey, keyType: .privateKey)
        XCTAssertNil(algorithm, "Create Algorithm for unsupported")
    }

}

func read(fileName: String) -> Data {
    do {
        var pathToTests = #file
        if pathToTests.hasSuffix("TestJWT.swift") {
            pathToTests = pathToTests.replacingOccurrences(of: "TestJWT.swift", with: "")
        }
        let fileData = try Data(contentsOf: URL(fileURLWithPath: "\(pathToTests)\(fileName)"))
        XCTAssertNotNil(fileData, "Failed to read in the \(fileName) file")
        return fileData
    } catch {
        XCTFail("Error in \(fileName).")
        exit(1)
    }
}
