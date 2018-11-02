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
#elseif os(macOS)
    import Darwin
#endif

@testable import SwiftJWT

let rsaPrivateKey = read(fileName: "rsa_private_key")
let rsaPublicKey = read(fileName: "rsa_public_key")
let certPrivateKey = read(fileName: "cert_private_key")
let certificate = read(fileName: "certificate")
let encodedTestClaimJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwic3ViIjoiMTIzNDU2Nzg5MCJ9.WJHaxAjhLu7wkw2J3B7ZpW-pnX-WEDJuy7l46nHZRWtZrH_4f8724v-4V48UlHtEgQpUXCHyGRyWPgPJCdGIfy2vD5GBoMJ1kdNWQa0UVOajTk0omUIloBPKgo-45m3w15ub-_4bihyZOI8dCK9zk5vjvUGnzdKartNi9AN5kNM"

struct TestClaims: Claims, Equatable {
    var name: String?
    var admin: Bool?
    var iss: String?
    var sub: String?
    var aud: [String]?
    var exp: Date?
    var nbf: Date?
    var iat: Date?
    var jti: String?
    init(name: String? = nil) {
        self.name = name
    }
    
}
struct MicroProfile: Claims {
    var name: String?
    var groups: [String]?
    var upn: String?
    var admin: Bool?
    var iss: String?
    var sub: String?
    var aud: [String]?
    var exp: Date?
    var nbf: Date?
    var iat: Date?
    var jti: String?
    init(name: String) {
        self.name = name
    }
}
@available(macOS 10.12, iOS 10.0, *)
class TestJWT: XCTestCase {
    
    static var allTests: [(String, (TestJWT) -> () throws -> Void)] {
        return [
            ("testSignAndVerify", testSignAndVerify),
            ("testJWT", testJWT),
            ("testMicroProfile", testMicroProfile)
        ]
    }
    
    func testSignAndVerify() {
        var jwt = JWT(header: Header(), claims: TestClaims(name:"Kitura"))
        jwt.claims.name = "Kitura-JWT"
        XCTAssertEqual(jwt.claims.name, "Kitura-JWT")
        jwt.claims.iss = "issuer"
        jwt.claims.aud = ["clientID"]
        jwt.claims.iat = Date(timeIntervalSince1970: 1485949565.58463)
        jwt.claims.exp = Date(timeIntervalSince1970: 2485949565.58463)
        jwt.claims.nbf = Date(timeIntervalSince1970: 1485949565.58463)
        // encode
        if let encoded = jwt.sign(using: .none){
            if let decoded = JWT<TestClaims>(jwtString: encoded) {
                check(jwt: decoded, algorithm: "none")
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
        else {
            XCTFail("Failed to encode")
        }
       
        // public key
        if let signed = jwt.sign(using: .rs256(privateKey: rsaPrivateKey)) {
            let ok = JWT<TestClaims>.verify(signed, using: .rs256(publicKey: rsaPublicKey))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = JWT<TestClaims>(jwtString: signed) {
                check(jwt: decoded, algorithm: "RS256")
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
        else {
            XCTFail("Failed to sign")
        }
        
        // certificate
        if let signed = jwt.sign(using: .rs256(privateKey: certPrivateKey)) {
            let ok = JWT<TestClaims>.verify(signed, using: .rs256(certificate: certificate))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = JWT<TestClaims>(jwtString: signed) {
                check(jwt: decoded, algorithm: "RS256")
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
        else {
            XCTFail("Failed to sign")
        }
    }
    
    func check<T: Claims>(jwt: JWT<T>, algorithm: String) {

        XCTAssertEqual(jwt.header.alg, algorithm, "Wrong .alg in decoded")
        XCTAssertEqual(jwt.claims.exp, Date(timeIntervalSince1970: 2485949565.58463), "Wrong .exp in decoded")
        XCTAssertEqual(jwt.claims.iat, Date(timeIntervalSince1970: 1485949565.58463), "Wrong .iat in decoded")
        XCTAssertEqual(jwt.claims.nbf, Date(timeIntervalSince1970: 1485949565.58463), "Wrong .nbf in decoded")
    }
    
    func checkMicroProfile(jwt: JWT<MicroProfile>, algorithm: String) {
        
        XCTAssertEqual(jwt.header.alg, "RS256", "Wrong .alg in decoded. MicroProfile only supports RS256.")
        XCTAssertEqual(jwt.claims.iss, "https://server.example.com", "Wrong .iss in decoded")
        XCTAssertEqual(jwt.claims.exp, Date(timeIntervalSince1970: 2485949565.58463), "Wrong .exp in decoded")
        XCTAssertEqual(jwt.claims.iat, Date(timeIntervalSince1970: 1485949565.58463), "Wrong .iat in decoded")
        XCTAssertEqual(jwt.claims.aud, ["clientID"], "Wrong .aud in decoded")
        XCTAssertEqual(jwt.claims.groups, ["red-group", "green-group", "admin-group", "admin"], "Wrong .groups in decoded")

    }
    
    
    func testMicroProfile() {
        
        var jwt = JWT(header: Header(), claims: MicroProfile(name: "MP-JWT"))
        jwt.header.kid = "abc-1234567890"
        jwt.header.typ = "JWT"
        XCTAssertEqual(jwt.claims.name, "MP-JWT")
        jwt.claims.iss = "https://server.example.com"
        jwt.claims.aud = ["clientID"]
        jwt.claims.iat = Date(timeIntervalSince1970: 1485949565.58463)
        jwt.claims.exp = Date(timeIntervalSince1970: 2485949565.58463)
        jwt.claims.upn = "jdoe@server.example.com"
        jwt.claims.groups = ["red-group", "green-group", "admin-group", "admin"]
            
        // public key (MP-JWT needs to be signed)
        if let signed = jwt.sign(using: .rs256(privateKey: rsaPrivateKey)) {
            let ok = JWT<MicroProfile>.verify(signed, using: .rs256(publicKey: rsaPublicKey))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = JWT<MicroProfile>(jwtString: signed) {
                checkMicroProfile(jwt: decoded, algorithm: "RS256")
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
        else {
            XCTFail("Failed to sign")
        }
        
        // certificate
        if let signed = jwt.sign(using: .rs256(privateKey: certPrivateKey)) {
            let ok = JWT<MicroProfile>.verify(signed, using: .rs256(certificate: certificate))
            XCTAssertTrue(ok, "Verification failed")
            
            if let decoded = JWT<MicroProfile>(jwtString: signed) {
                checkMicroProfile(jwt: decoded, algorithm: "RS256")
                
                XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
            }
            else {
                XCTFail("Failed to decode")
            }
        }
        else {
            XCTFail("Failed to sign")
        }
    }
    
    // From jwt.io
    func testJWT() {
        let ok = JWT<TestClaims>.verify(encodedTestClaimJWT, using: .rs256(publicKey: rsaPublicKey))
        XCTAssertTrue(ok, "Verification failed")
        
        if let decoded = JWT<TestClaims>(jwtString: encodedTestClaimJWT) {
            XCTAssertEqual(decoded.header.alg, "RS256", "Wrong .alg in decoded")
            XCTAssertEqual(decoded.header.typ, "JWT", "Wrong .typ in decoded")
            
            XCTAssertEqual(decoded.claims.sub, "1234567890", "Wrong .sub in decoded")
            XCTAssertEqual(decoded.claims.name, "John Doe", "Wrong .name in decoded")
            XCTAssertEqual(decoded.claims.admin, true, "Wrong .admin in decoded")
            
            XCTAssertEqual(decoded.validateClaims(), .success, "Validation failed")
        }
        else {
            XCTFail("Failed to decode")
        }
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
