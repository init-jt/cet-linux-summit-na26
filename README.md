# A technical deep dive into Intel CET Implementation in Linux — Linux Security Summit North America 2026

**Hardware Control-Flow Integrity in the Linux Kernel**

| | |
|---|---|
| **Speaker** | Jay Tharwani |
| **Email** | jtharwan@alumni.uncc.edu |
| **Event** | Linux Security Summit North America 2026 |
| **Duration** | 20-minute technical talk + Q&A |

## Download

- [Slides (PPTX)](slides/Intel_CET_Linux_Summit_NA_2026.pptx)

## Abstract

Intel Control-flow Enforcement Technology (CET) brings hardware-assisted CFI to x86-64 Linux through two mechanisms:

- **Indirect Branch Tracking (IBT)** — validates forward edges via `ENDBR64` and `#CP` faults
- **Shadow Stacks** — protects backward edges with a hardware-managed, read-only return stack

This talk walks through the kernel implementation: `gen_endbr()`, ENDBR sealing at boot, `#CP` dispatch, signal delivery with shadow-stack tokens, fork/clone inheritance, and `arch_prctl` user-space integration.

## Contents

```
slides/   — Presentation (PPTX, 18 slides with speaker notes)
sources/  — Markdown source outline and speaker notes
```

## License

Presentation materials are shared for conference attendees and the Linux community. Kernel code references are from upstream Linux and remain under their respective licenses.
