# Third-party notices

The optional processor image contains software that is not part of Tacua's
Apache-2.0 source:

- **whisper.cpp**, revision
  `f24588a272ae8e23280d9c220536437164e6ed28`, MIT License. The image retains
  `/usr/share/doc/whisper.cpp/LICENSE`.
- **OpenAI Whisper model weights**, obtained separately by the operator, MIT
  License. Model weights are not redistributed by Tacua.
- **FFmpeg and its Debian dependencies**, obtained from the configured Debian
  package repository. Their package-specific copyright and license notices
  remain under `/usr/share/doc` in the image.

Operators distributing a built image remain responsible for retaining all
notices and satisfying the licenses of the exact Debian packages they select.
