// SPDX-License-Identifier: Apache-2.0

/**
 * Tacua's palette is sampled conceptually from the cicada reference:
 * ink-black wings, warm bark, a chartreuse collar, turquoise abdominal bands,
 * red markings, and rust-coloured wing veins.
 *
 * The brighter photographic colours are reserved for accents. Text and large
 * surfaces use quieter relatives so the reviewer can inspect evidence for a
 * long time without sacrificing contrast.
 */
export const palette = {
  light: {
    ink: "#111713",
    secondaryInk: "#4A5A50",
    tertiaryInk: "#5D6D62",
    background: "#F7F7EE",
    surface: "#ECEFDF",
    grouped: "#F2F3E7",
    outline: "#C5CEBA",
    aqua: "#006E67",
    onAqua: "#FFFFFF",
    chartreuse: "#5D7300",
    bark: "#6B5430",
    rust: "#984500",
    red: "#B4232A",
  },
  dark: {
    ink: "#F2F5EA",
    secondaryInk: "#B6C3B7",
    tertiaryInk: "#89978C",
    background: "#050806",
    surface: "#121916",
    grouped: "#0B100E",
    outline: "#33443B",
    aqua: "#64DFD0",
    onAqua: "#05201C",
    chartreuse: "#C5DE68",
    bark: "#B79A62",
    rust: "#F08A45",
    red: "#FF6B70",
  },
} as const;
