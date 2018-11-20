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

// MARK: ValidateClaimsResult

/// ValidateClaimsResult list the possible results of a call to JWT.validateClaims method.
/// In case of successful validation, .success is returned, all other cases list various
/// problems that may occur during claims validation and indicate that the validation failed.
public struct ValidateClaimsResult: CustomStringConvertible, Equatable {
    
    /// The human readable description of the ValidateClaimsResult
    public let description: String
    
    /// Successful validation.
    public static let success = ValidateClaimsResult(description: "Success")

    /// Invalid Expiration claim.
    public static let invalidExpiration = ValidateClaimsResult(description: "Invalid Expiration claim")
    
    /// Expired token: expiration time claim is in the past.
    public static let expired = ValidateClaimsResult(description: "Expired token")
    
    /// Invalid Not Before claim.
    public static let invalidNotBefore = ValidateClaimsResult(description: "Invalid Not Before claim")
    
    /// Not Before claim is in the future.
    public static let notBefore = ValidateClaimsResult(description: "Token is not valid yet, Not Before claim is greater than the current time")
    
    /// Invalid Issued At claim.
    public static let invalidIssuedAt = ValidateClaimsResult(description: "Invalid Issued At claim")
    
    /// Issued At claim is in the future.
    public static let issuedAt = ValidateClaimsResult(description: "Issued At claim is greater than the current time")
 
    /// Check if two ValidateClaimsResults are equal. Required for the Equatable protocol
    public static func == (lhs: ValidateClaimsResult, rhs: ValidateClaimsResult) -> Bool {
        return lhs.description == rhs.description
    }
}
