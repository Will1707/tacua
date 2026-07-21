# iOS capture API compile probe

This is a compile-only input to `EXP-001`. It checks the smallest ReplayKit API boundary required by Tacua against the installed iPhone SDK and a generic Sample Mobile App target with an iOS 17 deployment floor:

- app-only recorder availability;
- microphone enablement;
- raw video/app-audio/microphone sample capture; and
- direct recording output to a caller-owned URL.

It intentionally does not claim runtime feasibility. Consent behavior, audio tracks, interruptions, backgrounding, duration, performance, segmentation, and recovery must be measured on an isolated physical-device spike before the long-term capture architecture is accepted.
