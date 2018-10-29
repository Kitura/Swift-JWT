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
#if os(Linux)
import Cryptor
import OpenSSL
import Foundation


///
/// RSA Handling: Implements a series of Class Level RSA Helper Functions.
///
class RSA: SignerAlgorithm, VerifierAlgorithm {
    
    private let name: String = "RSA"
    private let algorithm: Algorithm
    private let key: UnsafeMutablePointer<UInt8>
    private let keySize: Int32
    private let keyType: RSAKeyType?
    
    // MARK: Enums
    
    /// The RSA algorithm to use.
    enum Algorithm {
        case md2
        case md4
        case md5
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        
        /// OpenSSL equivalent.
        var nid: Int32 {
            switch self {
            case .md2:
                return NID_md2
            case .md4:
                return NID_md4
            case .md5:
                return NID_md5
            case .sha1:
                return NID_sha1
            case .sha224:
                return NID_sha224
            case .sha256:
                return NID_sha256
            case .sha384:
                return NID_sha384
            case .sha512:
                return NID_sha512
            }
        }
        
        /// `Digest` equivalent.
        var digest: Digest.Algorithm {
            switch self {
            case .md2:
                return .md2
            case .md4:
                return .md4
            case .md5:
                return .md5
            case .sha1:
                return .sha1
            case .sha224:
                return .sha224
            case .sha256:
                return .sha256
            case .sha384:
                return .sha384
            case .sha512:
                return .sha512
            }
        }
    }
    
    init(key: Data, keyType: RSAKeyType?=nil, algorithm: Algorithm) {
        self.algorithm = algorithm
        self.key = UnsafeMutablePointer<UInt8>.allocate(capacity: key.count)
        key.copyBytes(to: self.key, count: key.count)
        self.keySize = Int32(key.count)
        self.keyType = keyType
    }
    
    deinit {
        key.deinitialize(count: Int(keySize))
        #if swift(>=4.1)
            key.deallocate()
        #else
            key.deallocate(capacity: 1)
        #endif
    }
    
    func sign(_ data: Data) -> Data? {
        // Generate hash
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        defer {
        #if swift(>=4.1)
            ptr.deallocate()
        #else
            ptr.deallocate(capacity: 1)
        #endif
        }
        data.copyBytes(to: ptr, count: data.count)
        guard let digest = Digest(using: algorithm.digest).update(from: ptr, byteCount: data.count) else {
            return nil
        }
        
        var digestBytes = digest.final()
        let keyBuf = BIO_new_mem_buf(key, keySize)
        // This can fail for invalid private keys, so we check here
        guard let rsa = PEM_read_bio_RSAPrivateKey(keyBuf, nil, nil, nil) else {
            return nil
        }
        let rsaSize = Int(RSA_size(rsa))
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: rsaSize)
        var len: UInt32 = 0
        let result = RSA_sign(algorithm.nid, &digestBytes, UInt32(digestBytes.count), buffer, &len, rsa)
        guard result != 0 else {
            return nil
        }
        return Data(bytes: buffer, count: rsaSize)
    }
    
    func verify(signature: Data, for data: Data) -> Bool {
        // Generate hash
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        defer {
        #if swift(>=4.1)
            ptr.deallocate()
        #else
            ptr.deallocate(capacity: 1)
        #endif
        }
        data.copyBytes(to: ptr, count: data.count)
        guard let digest = Digest(using: algorithm.digest).update(from: ptr, byteCount: data.count) else {
            return false
        }
        var digestBytes = digest.final()
        
        let signPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: signature.count)
        defer {
        #if swift(>=4.1)
            signPtr.deallocate()
        #else
            signPtr.deallocate(capacity: 1)
        #endif
        }
        signature.copyBytes(to: signPtr, count: signature.count)
        
        let keybuf = BIO_new_mem_buf(key, keySize)
        
        let type = keyType ?? .publicKey
        
        switch type {
        case .certificate:
            guard let cert = PEM_read_bio_X509(keybuf, nil, nil, nil) else {
                return false
            }
            let pkey = X509_get_pubkey(cert)
            let rsa = EVP_PKEY_get1_RSA(pkey)
            EVP_PKEY_free(pkey)
            let result = RSA_verify(algorithm.nid, &digestBytes, UInt32(digestBytes.count), signPtr, UInt32(signature.count), rsa)
            return result != 0
            
        case .publicKey:
            var rsa = RSA_new()
            let ok = PEM_read_bio_RSA_PUBKEY(keybuf, &rsa, nil, nil)
            guard ok != nil else {
                return false
            }
            let result = RSA_verify(algorithm.nid, &digestBytes, UInt32(digestBytes.count), signPtr, UInt32(signature.count), rsa)
            return result != 0
            
        default:
            return false
        }
    }
    
    func sign(header: String, claims: String) -> String? {
        let unsignedJWT = header + "." + claims
        guard let unsignedData = unsignedJWT.data(using: .utf8), let signature = sign(unsignedData) else {
            return nil
        }
        let signatureString = signature.base64urlEncodedString()
        return header + "." + claims + "." + signatureString
    }
    
    func verify(jwt: String) -> Bool {
        let components = jwt.components(separatedBy: ".")
        if components.count == 3 {
            guard let signature = Data(base64urlEncoded: components[2]),
                let jwtData = (components[0] + "." + components[1]).data(using: .utf8)
                else {
                    return false
            }
            return self.verify(signature: signature, for: jwtData)
        } else {
            return false
        }
    }
}
#endif

