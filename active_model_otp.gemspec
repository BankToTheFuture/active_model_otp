# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'active_model/otp/version'

Gem::Specification.new do |spec|
  spec.name          = "active_model_otp"
  spec.version       = ActiveModel::Otp::VERSION
  spec.authors       = ["Guillermo Iguaran", "Roberto Miranda", "Heapsource"]
  spec.email         = ["guilleiguaran@gmail.com", "rjmaltamar@gmail.com", "hello@firebase.co"]
  spec.description   = %q{Adds methods to set and authenticate against one time passwords. Inspired in AM::SecurePassword"}
  spec.summary       = "Adds methods to set and authenticate against one time passwords."
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "activemodel"
  spec.add_dependency "rotp", '~> 6.3'
  spec.add_dependency 'encryptor', '~> 3.0'

  spec.add_development_dependency "activerecord"
  spec.add_development_dependency "bundler", "~> 2.5.5"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "minitest", "~> 5.4.2"
  spec.add_development_dependency "devise"

  if RUBY_PLATFORM == "java"
    spec.add_development_dependency "activerecord-jdbcsqlite3-adapter"
  else
    spec.add_development_dependency "sqlite3"
  end
end
