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

@testable import KituraJWT

let rsaPrivateKey = read(fileName: "rsa_private_key")
let rsaPublicKey = read(fileName: "rsa_public_key")

@available(macOS 10.12, iOS 10.0, *)
class TestJWT: XCTestCase {
    
    static var allTests: [(String, (TestJWT) -> () throws -> Void)] {
        return [
            ("testSign", testSign),
        ]
    }
    
    func testSign() {
        
        var jwt = JWT(header: Header([.alg:"rs256"]), claims: Claims([.name:"Kitura"]))
        jwt.claims[.name] = "Kitura-JWT"
        XCTAssertEqual(jwt.claims[.name] as! String, "Kitura-JWT")
        
        do {
            if let signed = try jwt.sign(using: .rs256(rsaPrivateKey, .privateKey)) {
                let ok = try JWT.verify(signed, using: .rs256(rsaPublicKey, .publicKey))
                XCTAssertTrue(ok, "Verification failed")
                
                if let decoded = try JWT.decode(signed) {
                    XCTAssertEqual(decoded.header[.alg] as! String, "RS256", "Wrong .alg in decoded")
                    XCTAssertEqual(decoded.claims[.name] as! String, "Kitura-JWT", "Wrong .name in decoded")
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
}

func read(fileName: String) -> Data {
    // Read in a configuration file into an NSData
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
