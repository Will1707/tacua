# SPDX-License-Identifier: Apache-2.0

require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name             = 'TacuaCaptureSpike'
  s.version          = package['version']
  s.summary          = 'ReplayKit capture and segmented-recovery probe for Tacua.'
  s.description      = 'Experiment-only Expo module for Tacua EXP-001/EXP-005. It is not a production SDK contract.'
  s.author           = 'Tacua contributors'
  s.homepage         = 'https://tacua.invalid'
  s.license          = { :type => 'Apache-2.0' }
  s.platforms        = { :ios => '17.0' }
  s.source           = { :git => '' }
  s.static_framework = true
  s.swift_version = '5.9'

  s.dependency 'ExpoModulesCore'
  s.frameworks = 'AVFAudio', 'AVFoundation', 'CoreMedia', 'ReplayKit'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = '**/*.{h,m,mm,swift,hpp,cpp}'
end
