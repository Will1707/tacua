#!/usr/bin/env ruby
# SPDX-License-Identifier: Apache-2.0

require "optparse"
require "pathname"
require "xcodeproj"

harness_root = File.expand_path("..", __dir__)
default_sources = [
  File.join(
    harness_root,
    "physical-tests",
    "TacuaPhysicalHarnessState.swift"
  ),
  File.join(
    harness_root,
    "physical-tests",
    "TacuaPhysicalHarnessSupport.swift"
  ),
  File.join(
    harness_root,
    "physical-tests",
    "TacuaCaptureLabUITests.swift"
  ),
]
options = {
  project: File.join(harness_root, "ios", "TacuaCaptureLab.xcodeproj"),
  sources: default_sources,
}
source_override = false

OptionParser.new do |parser|
  parser.banner = "Usage: add_physical_ui_test_target.rb [options]"
  parser.on("--project PATH", "Generated TacuaCaptureLab.xcodeproj") do |path|
    options[:project] = File.expand_path(path)
  end
  parser.on(
    "--source PATH",
    "Tracked physical UI-test source (repeatable; first use replaces defaults)"
  ) do |path|
    unless source_override
      options[:sources] = []
      source_override = true
    end
    options[:sources] << File.expand_path(path)
  end
  parser.on("--development-team TEAM", "Apple development-team identifier") do |team|
    options[:development_team] = team
  end
  parser.on(
    "--replace-existing-source",
    "Replace mismatched generated UI-test source references"
  ) do
    options[:replace_existing_source] = true
  end
end.parse!

project_path = options.fetch(:project)
source_paths = options.fetch(:sources)
abort("TacuaCaptureLab.xcodeproj is missing") unless File.directory?(project_path)
abort("unexpected Xcode project") unless File.basename(project_path) == "TacuaCaptureLab.xcodeproj"
abort("at least one physical UI-test source is required") if source_paths.empty?
abort("physical UI-test source paths must be unique") unless source_paths.uniq.length == source_paths.length
source_basenames = source_paths.map { |path| File.basename(path) }
abort("physical UI-test source basenames must be unique") unless source_basenames.uniq.length == source_basenames.length
source_paths.each do |source_path|
  abort("physical UI-test source is missing") unless File.file?(source_path)
  abort("physical UI-test source must be Swift") unless File.extname(source_path) == ".swift"
end

project = Xcodeproj::Project.open(project_path)
app_target = project.targets.find { |target| target.name == "TacuaCaptureLab" }
abort("TacuaCaptureLab target is missing") unless app_target

test_target = project.targets.find { |target| target.name == "TacuaCaptureLabUITests" }
unless test_target
  test_target = project.new_target(
    :ui_test_bundle,
    "TacuaCaptureLabUITests",
    :ios,
    "17.0",
    project.products_group,
    :swift
  )
  test_target.add_dependency(app_target)
end
unless test_target.product_type == "com.apple.product-type.bundle.ui-testing"
  abort("TacuaCaptureLabUITests exists with an unexpected product type")
end
unexpected_dependencies = test_target.dependencies.reject do |dependency|
  dependency.target == app_target
end
abort("UI-test target has an unexpected target dependency") unless unexpected_dependencies.empty?
unless test_target.dependencies.any? { |dependency| dependency.target == app_target }
  test_target.add_dependency(app_target)
end

project_directory = Pathname.new(File.dirname(project_path))
all_test_sources = test_target.source_build_phase.files_references
unexpected_test_sources = all_test_sources.reject do |file|
  source_basenames.include?(file.display_name)
end
abort("UI-test target contains an unexpected source") unless unexpected_test_sources.empty?
source_paths.each do |source_path|
  relative_source = Pathname.new(source_path).relative_path_from(project_directory).to_s
  existing_test_sources = all_test_sources.select do |file|
    file.display_name == File.basename(source_path)
  end
  abort("UI-test target contains duplicate sources") if existing_test_sources.length > 1
  source_reference = existing_test_sources.find do |file|
    File.expand_path(file.real_path.to_s) == source_path
  end
  if source_reference.nil? && !existing_test_sources.empty?
    unless options[:replace_existing_source] && existing_test_sources.length == 1
      abort("UI-test target contains an unexpected source; run a clean Expo prebuild")
    end
    source_reference = existing_test_sources.first
    source_reference.source_tree = "<group>"
    source_reference.path = Pathname.new(source_path)
      .relative_path_from(source_reference.parent.real_path)
      .to_s
  end
  source_reference ||= project.files.find { |file| file.path == relative_source }
  source_reference ||= project.main_group.new_file(relative_source)
  unless test_target.source_build_phase.files_references.include?(source_reference)
    test_target.add_file_references([source_reference])
  end
end

debug_configuration = app_target.build_configurations.find do |configuration|
  configuration.name == "Debug"
end
development_team = options[:development_team] ||
  debug_configuration&.build_settings&.fetch("DEVELOPMENT_TEAM", nil)
abort("TacuaCaptureLab Debug development team is missing") unless development_team
abort("Apple development-team identifier is invalid") unless /\A[A-Z0-9]{10}\z/.match?(development_team)

test_target.build_configurations.each do |configuration|
  configuration.build_settings["CODE_SIGN_STYLE"] = "Automatic"
  configuration.build_settings["DEVELOPMENT_TEAM"] = development_team
  configuration.build_settings["GENERATE_INFOPLIST_FILE"] = "YES"
  configuration.build_settings["IPHONEOS_DEPLOYMENT_TARGET"] = "17.0"
  configuration.build_settings["PRODUCT_BUNDLE_IDENTIFIER"] =
    "com.tacua.capturelab.acceptance.uitests"
  configuration.build_settings["PRODUCT_NAME"] = "$(TARGET_NAME)"
  configuration.build_settings["SWIFT_VERSION"] = "5.0"
  configuration.build_settings["TARGETED_DEVICE_FAMILY"] = "1"
  configuration.build_settings["TEST_TARGET_NAME"] = app_target.name
end

project.save

scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(app_target)
scheme.add_test_target(test_target)
scheme.set_launch_target(app_target)
scheme.save_as(project_path, "TacuaCaptureLabAutomation", true)

puts "Installed TacuaCaptureLabAutomation into the generated Xcode project."
