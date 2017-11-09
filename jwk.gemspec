lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'jwk/version'

Gem::Specification.new do |spec|
  spec.name          = 'jwk'
  spec.version       = JWK::VERSION
  spec.authors       = ['Francesco Boffa']
  spec.email         = ['fra.boffa@gmail.com']

  spec.summary       = 'JSON Web Keys implementation in Ruby'
  spec.description   = 'A Ruby implementation of the RFC 7517 JSON Web Keys (JWK) standard'
  spec.homepage      = 'https://github.com/aomega08/jwk'
  spec.license       = 'MIT'

  spec.files = `git ls-files`.split("\n")
  spec.require_paths = ['lib']

  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'codeclimate-test-reporter'
end
