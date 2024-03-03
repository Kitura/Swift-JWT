import _CryptoExtras
import Crypto
import Foundation
import LoggerAPI

struct SwiftCryptoRSA: VerifierAlgorithm, SignerAlgorithm {
	private let key: Key
	private let algorithm: Algorithm

	fileprivate enum Key {
		case privateKey(Data)
		case publicKey(Data)
	}

	enum Algorithm {
		case rs256, rs384, rs512
		case ps256, ps384, ps512
	}

	init(publicKey: Data, algorithm: Algorithm) {
		key = .publicKey(publicKey)
		self.algorithm = algorithm
	}

	init(privateKey: Data, algorithm: Algorithm) {
		key = .privateKey(privateKey)
		self.algorithm = algorithm
	}

	func verify(jwt: String) -> Bool {
		verify(jwt)
	}

	func sign(header: String, claims: String) throws -> String {
		let unsignedJWT = header + "." + claims
		let signature = try sign(data: Data(unsignedJWT.utf8))
		return header + "." + claims + "." + signature
	}
}

extension SwiftCryptoRSA {
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

private extension SwiftCryptoRSA.Algorithm {
	func verify(signature: Data, data: Data, key: SwiftCryptoRSA.Key) throws -> Bool {
		let publicKey = try publicKey(from: key)
		let signature = _RSA.Signing.RSASignature(rawRepresentation: signature)
		return publicKey.isValidSignature(signature, for: data, padding: padding)
	}

	func signature(for data: Data, key: SwiftCryptoRSA.Key) throws -> Data {
		let privateKey = try privateKey(from: key)
		let signature = try privateKey.signature(for: data, padding: padding)
		return signature.rawRepresentation
	}
}

private extension SwiftCryptoRSA.Algorithm {
	var padding: _RSA.Signing.Padding {
		switch self {
		case .rs256, .rs384, .rs512:
			return .insecurePKCS1v1_5
		case .ps256, .ps384, .ps512:
			return .PSS
		}
	}

	func publicKey(from key: SwiftCryptoRSA.Key) throws -> _RSA.Signing.PublicKey {
		switch key {
		case .privateKey(let data):
			let der = (try? pem2der(data)) ?? data
			return try _RSA.Signing.PrivateKey(derRepresentation: der).publicKey
		case .publicKey(let data):
			let der = (try? pem2der(data)) ?? data
			return try .init(derRepresentation: der)
		}
	}

	func privateKey(from key: SwiftCryptoRSA.Key) throws -> _RSA.Signing.PrivateKey {
		switch key {
		case .privateKey(let data):
			let der = (try? pem2der(data)) ?? data
			return try .init(derRepresentation: der)
		case .publicKey(let data):
			let der = (try? pem2der(data)) ?? data
			return try .init(derRepresentation: der)
		}
	}

	private var keySize: Int {
		switch self {
		case .rs256, .ps256:
			return 256
		case .rs384, .ps384:
			return 384
		case .rs512, .ps512:
			return 512
		}
	}
}

private func pem2der(_ pem: Data) throws -> Data {
	guard let pem = String(data: pem, encoding: .utf8) else {
		throw JWTError.invalidUTF8Data
	}
	let strippedKey = String(pem.filter { !" \n\t\r".contains($0) })
	let pemComponents = strippedKey.components(separatedBy: "-----")
	guard pemComponents.count >= 5 else {
		throw JWTError.missingPEMHeaders
	}
	guard let der = Data(base64Encoded: pemComponents[2]) else {
		throw JWTError.invalidPrivateKey
	}
	return der
}
