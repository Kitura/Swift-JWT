import Crypto
import Foundation
import LoggerAPI

internal struct SwiftCryptoHMAC: VerifierAlgorithm, SignerAlgorithm {
	private let key: Data
	private let algorithm: Algorithm

	internal enum Algorithm {
		case hs256, hs384, hs512
	}

	internal init(key: Data, algorithm: Algorithm) {
		self.key = key
		self.algorithm = algorithm
	}

	internal func verify(jwt: String) -> Bool {
		verify(jwt)
	}

	internal func sign(header: String, claims: String) throws -> String {
		let unsignedJWT = header + "." + claims
		let signature = try sign(data: Data(unsignedJWT.utf8))
		return header + "." + claims + "." + signature
	}
}

extension SwiftCryptoHMAC {
	private func verify(_ jwt: String) -> Bool {
		let components = jwt.components(separatedBy: ".")
		if components.count == 3 {
			guard let signature = JWTDecoder.data(base64urlEncoded: components[2]),
			      let jwtData = (components[0] + "." + components[1]).data(using: .utf8)
			else {
				return false
			}
			return verify(signature: signature, for: jwtData)
		} else {
			return false
		}
	}

	private func verify(signature: Data, for data: Data) -> Bool {
		do {
			return try algorithm.verify(signature: signature, data: data, key: key)
		} catch {
			Log.error("Verification failed: \(error)")
			return false
		}
	}

	private func sign(data: Data) throws -> String {
		let signedData = try algorithm.signature(for: data, key: key)
		return JWTEncoder.base64urlEncodedString(data: signedData)
	}
}

private extension SwiftCryptoHMAC.Algorithm {
	func verify(signature: Data, data: Data, key: Data) throws -> Bool {
		let key = SymmetricKey(data: key)

		switch self {
		case .hs256:
			return HMAC<SHA256>.isValidAuthenticationCode(signature, authenticating: data, using: key)
		case .hs384:
			return HMAC<SHA384>.isValidAuthenticationCode(signature, authenticating: data, using: key)
		case .hs512:
			return HMAC<SHA512>.isValidAuthenticationCode(signature, authenticating: data, using: key)
		}
	}

	func signature(for data: Data, key: Data) throws -> Data {
		let key = SymmetricKey(data: key)

		switch self {
		case .hs256:
			let mac = HMAC<SHA256>.authenticationCode(for: data, using: key)
			return Data(mac)
		case .hs384:
			let mac = HMAC<SHA384>.authenticationCode(for: data, using: key)
			return Data(mac)
		case .hs512:
			let mac = HMAC<SHA512>.authenticationCode(for: data, using: key)
			return Data(mac)
		}
	}
}
