// SPDX-License-Identifier: Apache-2.0
// Compile-only probe for EXP-001. This does not start capture or retain media.

import Foundation
import ReplayKit

@available(iOS 17.0, *)
func compileReplayKitCaptureBoundary(outputURL: URL) {
    let recorder = RPScreenRecorder.shared()

    _ = recorder.isAvailable
    _ = recorder.isRecording
    recorder.isMicrophoneEnabled = true

    recorder.startCapture(
        handler: { sampleBuffer, sampleBufferType, error in
            _ = sampleBuffer
            _ = sampleBufferType
            _ = error
        },
        completionHandler: { error in
            _ = error
        }
    )

    recorder.stopCapture { error in
        _ = error
    }

    recorder.stopRecording(withOutput: outputURL) { error in
        _ = error
    }
}
