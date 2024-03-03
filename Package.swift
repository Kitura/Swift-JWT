// swift-tools-version:5.2

/**
 * Copyright IBM Corporation and the Kitura project authors 2018-2020
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

import PackageDescription

let package = Package(
	name: "SwiftJWT",
	platforms: [
		.iOS("14.0"),
		.macOS("11.0")
	],
	products: [
		// Products define the executables and libraries produced by a package, and make them visible to other packages.
		.library(
			name: "SwiftJWT",
			targets: ["SwiftJWT"]
		)
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-crypto.git", from: "2.6.0"),
		.package(url: "https://github.com/Kitura/LoggerAPI.git", from: "2.0.0"),
		.package(url: "https://github.com/Kitura/KituraContracts.git", from: "2.0.1"),
		.package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.50.4")
	],
	targets: [
		.target(name: "SwiftJWT", dependencies: [
			"LoggerAPI",
			"KituraContracts",
			.product(name: "Crypto", package: "swift-crypto"),
			.product(name: "_CryptoExtras", package: "swift-crypto")
		]),
		.testTarget(name: "SwiftJWTTests", dependencies: ["SwiftJWT"])
	]
)
