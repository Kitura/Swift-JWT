import Crypto
import Foundation
import LoggerAPI

internal struct SwiftCryptoECDSA: VerifierAlgorithm, SignerAlgorithm {
	private let key: Data
	private let algorithm: Algorithm

	internal enum Algorithm {
		case es256, es384, es512
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

extension SwiftCryptoECDSA {
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
		guard #available(macOS 10.12, iOS 10.3, tvOS 12.0, watchOS 3.3, *) else {
			return false
		}

		guard let publicKey = String(data: key, encoding: .utf8) else {
			return false
		}

		do {
			return try algorithm.verify(signature: signature, digest: data, publicKey: publicKey)
		} catch {
			Log.error("Verification failed: \(error)")
			return false
		}
	}

	private func sign(data: Data) throws -> String {
		guard let privateKey = String(data: key, encoding: .utf8) else {
			throw JWTError.invalidPrivateKey
		}

		let signature = try algorithm.signature(for: data, privateKey: privateKey)
		return JWTEncoder.base64urlEncodedString(data: signature)
	}
}

private extension SwiftCryptoECDSA.Algorithm {
	func verify(signature: Data, digest: Data, publicKey: String) throws -> Bool {
		switch self {
		case .es256:
			let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
			let publicKey = try P256.Signing.PublicKey(pemRepresentation: publicKey)
			return publicKey.isValidSignature(signature, for: digest)
		case .es384:
			let signature = try P384.Signing.ECDSASignature(rawRepresentation: signature)
			let publicKey = try P384.Signing.PublicKey(pemRepresentation: publicKey)
			return publicKey.isValidSignature(signature, for: digest)
		case .es512:
			let signature = try P521.Signing.ECDSASignature(rawRepresentation: signature)
			let publicKey = try P521.Signing.PublicKey(pemRepresentation: publicKey)
			return publicKey.isValidSignature(signature, for: digest)
		}
	}

	func signature(for digest: Data, privateKey: String) throws -> Data {
		switch self {
		case .es256:
			let privateKey = try P256.Signing.PrivateKey(pemRepresentation: privateKey)
			let signedData = try privateKey.signature(for: digest)
			return signedData.rawRepresentation
		case .es384:
			let privateKey = try P384.Signing.PrivateKey(pemRepresentation: privateKey)
			let signedData = try privateKey.signature(for: digest)
			return signedData.rawRepresentation
		case .es512:
			let privateKey = try P521.Signing.PrivateKey(pemRepresentation: privateKey)
			let signedData = try privateKey.signature(for: digest)
			return signedData.rawRepresentation
		}
	}
}
