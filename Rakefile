require "rake/testtask"

Rake::TestTask.new(:test) do |task|
  task.libs << "test"
  task.pattern = "test/*_test.rb"
end

Rake::TestTask.new(:integration) do |task|
  task.libs << "test"
  task.pattern = "test/integration/*_test.rb"
end

task default: :test
