# SPDX-License-Identifier: Apache-2.0

require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name             = 'TacuaCaptureSpike'
  s.version          = package['version']
  s.summary          = 'iOS capture, diagnostics, recovery, and transport for Tacua QA builds.'
  s.description      = 'Pre-release Expo native module for consent-gated ReplayKit capture and authenticated transport to a self-hosted Tacua backend.'
  s.author           = 'Tacua contributors'
  s.homepage         = 'https://github.com/Will1707/tacua'
  s.license          = { :type => 'Apache-2.0' }
  s.platforms        = { :ios => '17.0' }
  s.source           = {
    :git => 'https://github.com/Will1707/tacua.git',
    :tag => "mobile-sdk-v#{s.version}"
  }
  s.static_framework = true
  s.swift_version = '5.9'

  s.dependency 'ExpoModulesCore'
  s.frameworks = 'AVFAudio', 'AVFoundation', 'CoreMedia', 'ReplayKit', 'Security'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = '**/*.{h,m,mm,swift,hpp,cpp}'
end
