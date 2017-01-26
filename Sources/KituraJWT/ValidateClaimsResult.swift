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

// MARK ValidateClaimsResult

/// ValidateClaimsResult list the possible results of a call to JWT.validateClaims method.
/// In case of successful validation, .success is returned, all other cases list various
/// problems that may occur during claims validation and indicate that the validation failed.
public enum ValidateClaimsResult: CustomStringConvertible {
    /// Successful validation.
    case success
    
    /// The Audience claim exists but is empty.
    case emptyAudience
    
    /// The Audience claim contains more than one value.
    case multipleAudiences
    
    /// Mismatched Audience claim.
    case mismatchedAudience
    
    /// Invalid Audience claim.
    case invalidAudience

    /// Mismatched Issuer.
    case mismatchedIssuer
    
    /// Mismatched AuthorizedParty claim.
    case mismatchedAuthorizedParty
    
    /// Invalid algorithm in the header prevents access token hash claim validation.
    case invalidAlgorithm
    
    /// Hashing algorithm failure prevents access token hash claim validation.
    case hashFailure
    
    /// Mismatched AuthorizedParty claim.
    case mismatchedAccessTokenHash
    
    /// Invalid Expiration claim.
    case invalidExpiration
    
    /// Expired token: expiration time claim is in the past.
    case expired
    
    /// Invalid Not Before claim.
    case invalidNotBefore
    
    /// Not Before claim is in the future.
    case notBefore
    
    /// Invalid Issued At claim.
    case invalidIssuedAt
    
    /// Issued At claim is in the future.
    case issuedAt
    
    /// A textual respersentation of the validation result.
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
