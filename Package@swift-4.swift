// swift-tools-version:4.0
/**
 * Copyright IBM Corporation 2018
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

var listDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/IBM-Swift/BlueCryptor.git", .upToNextMinor(from: "0.8.0")),
    .package(url: "https://github.com/IBM-Swift/HeliumLogger.git", .upToNextMinor(from: "1.7.0"))
]

var listTargets: [Target.Dependency] = [
    .byNameItem(name: "Cryptor"),
    .byNameItem(name: "HeliumLogger")
]

#if os(OSX) || os(iOS) || os(tvOS) || os(watchOS)
listDependencies.append(contentsOf: [
    .package(url: "https://github.com/IBM-Swift/BlueRSA.git", .upToNextMinor(from:"0.1.0"))
    ])
    
listTargets.append(contentsOf: [
    .byNameItem(name: "CryptorRSA")
    ])
#endif

let package = Package(
    name: "SwiftJWT",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "SwiftJWT",
            targets: ["SwiftJWT"]
        )
    ],
    dependencies: listDependencies,
    targets: [
        .target(name: "SwiftJWT", dependencies: listTargets),
        .testTarget(name: "SwiftJWTTests", dependencies: ["SwiftJWT"])
	]
)

