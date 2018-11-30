Pod::Spec.new do |s|
  s.name         = "SwiftJWT"
  s.version      = "3.0.0"
  s.summary      = "An implementation of JSON Web Token using Swift."
  s.homepage     = "https://github.com/IBM-Swift/Swift-JWT"
  s.license      = { :type => "Apache License, Version 2.0" }
  s.authors      = 'IBM'
  s.module_name  = 'SwiftJWT'
  s.ios.deployment_target = "10.3"
  s.source       = { :git => "https://github.com/IBM-Swift/Swift-JWT.git", :tag => s.version }
  s.source_files  = "Sources/SwiftJWT/*.swift"
  s.dependency 'BlueRSA', '~> 1.0'
end
