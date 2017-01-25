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

public enum ValidateClaimsResult: CustomStringConvertible {
    case success
    case emptyAudience
    case multipleAudiences
    case mismatchedAudience
    case invalidAudience
    case mismatchedIssuer
    case mismatchedAuthorizedParty
    case invalidAlgorithm
    case hashFailure
    case mismatchedAccessTokenHash
    case invalidExpiration
    case expired
    case invalidNotBefore
    case notBefore
    case invalidIssuedAt
    case issuedAt
    
    public var description: String {
        switch self {
        case .success:
            return "Success"
        case .emptyAudience:
            return "Audience claim is empty"
        case .multipleAudiences:
            return "Multiple values in Audience claim"
        case .mismatchedAudience:
            return "Mismatched Audience claim"
        case .invalidAudience:
            return "Invalid Audience claim"
        case .mismatchedIssuer:
            return "Mismatched Issuer claim"
        case .mismatchedAuthorizedParty:
            return "Mismatched Authorized Party claim"
        case .invalidAlgorithm:
            return "Invalid algorithm"
        case .hashFailure:
            return "Failed to hash access token"
        case .mismatchedAccessTokenHash:
            return "Mismatched Access Token Hash claim"
        case .invalidExpiration:
            return "Invalid Expiration claim"
        case .expired:
            return "Expired token"
        case .invalidNotBefore:
            return "Invalid Not Before claim"
        case .notBefore:
            return "Token is not valid yet, Not Before claim is greater than the current time"
        case .invalidIssuedAt:
            return "Invalid Issued At claim"
        case .issuedAt:
            return "Issued At claim is greater than the current time"
        }
    }
 }
