require_relative "lib/action_policy/authzen/version"

Gem::Specification.new do |spec|
  spec.name = "action_policy-authzen"
  spec.version = ActionPolicy::AuthZEN::VERSION
  spec.authors = ["kajisha"]
  spec.license = "MIT"
  spec.summary = "AuthZEN authorization APIs for Action Policy"
  spec.homepage = "https://github.com/kajisha/action_policy-authzen"
  spec.required_ruby_version = ">= 3.3"
  spec.files = Dir["lib/**/*.rb", "docs/**/*.md", "README.md", "LICENSE.txt"]
  spec.require_paths = ["lib"]
  spec.add_dependency "action_policy", "~> 0.7.7"
  spec.add_dependency "net-http", ">= 0.3", "< 1.0"
  spec.add_dependency "json", ">= 2.6", "< 3.0"
end
