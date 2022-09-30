Pod::Spec.new do |s|
  s.name         = "SwiftJWT"
  s.version      = "4.0.0"
  s.summary      = "An implementation of JSON Web Token using Swift."
  s.homepage     = "https://github.com/Kitura/Swift-JWT"
  s.license      = { :type => "Apache License, Version 2.0" }
  s.authors      = 'IBM and the Kitura project authors'
  s.module_name  = 'SwiftJWT'
  s.swift_version = '5.2'
  s.osx.deployment_target = "10.13"
  s.ios.deployment_target = "11.0"
  s.tvos.deployment_target = "11.0"
  s.watchos.deployment_target = "4.0"
  s.source       = { :git => "https://github.com/Kitura/Swift-JWT.git", :tag => s.version }
  s.source_files  = "Sources/**/*.swift"
  s.dependency 'BlueRSA', '~> 1.0.200'
  s.dependency 'BlueCryptor', '~> 2.0.1'
  s.dependency 'BlueECC', '~> 1.2.200'
  s.dependency 'LoggerAPI', '~> 2.0.0'
  s.dependency 'KituraContracts', '~> 2.0.1'
end
