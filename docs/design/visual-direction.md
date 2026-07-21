# Tacua visual direction

Tacua's reviewer UI takes its palette from the founder-provided cicada
reference: dark translucent wings, bark, a pale chartreuse collar, turquoise
abdominal bands, red markings, and rust-orange wing veins.

The image is a visual reference, not a bundled product asset. Its provenance
and redistribution rights have not been established, so Tacua does not copy it
into the open-source repository.

## Palette

| Role | Light | Dark | Reference |
| --- | --- | --- | --- |
| Background | `#F7F7EE` | `#050806` | pale neutral / wing black |
| Surface | `#ECEFDF` | `#121916` | muted collar / wing charcoal |
| Primary action | `#006E67` | `#64DFD0` | turquoise abdominal bands |
| Highlight/success | `#5D7300` | `#C5DE68` | chartreuse collar |
| Warm neutral | `#6B5430` | `#B79A62` | bark |
| Attention | `#984500` | `#F08A45` | wing veins |
| Destructive/error | `#B4232A` | `#FF6B70` | red thorax markings |

Photographic accent colours are used sparingly. Long-form evidence and ticket
content stays on quiet, high-contrast surfaces. State is never communicated by
colour alone: labels, icons, and accessible roles remain required.

The V1 implementation provides an adaptive iOS light/dark palette. Android is
deferred by the product boundary and currently receives the accessible light
fallback until a platform-specific dynamic-colour pass is completed.
