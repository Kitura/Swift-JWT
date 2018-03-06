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

// MARK RSAKeyType

/// The type of the key used in the RSA algorithm.
public enum RSAKeyType {
    /// The key is a certificate containing both the private and the public keys.
    case certificate
    
    /// The key is an RSA public key.
    case publicKey
    
    /// The key is an RSA private key.
    case privateKey
}
