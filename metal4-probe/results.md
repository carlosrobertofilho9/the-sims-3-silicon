# Sanitized result record

Run date: 2026-10-26, local time (`America/Sao_Paulo`).

| Check | Result | Evidence boundary |
| --- | --- | --- |
| ARM64 build | Passed | Xcode 27.1 / macOS 27 SDK; output identified as a Mach-O ARM64 executable. The app bundle property list also passes `plutil -lint`. |
| Metal 4 support | Detected | Launch output reports `metal.support=detected metal4=true` on Apple M1 Pro. This is device support evidence, not render evidence. |
| Runtime shader compilation | Passed | Launch output reports `shader.compile=passed compiler=MTL4Compiler`. |
| Synthetic square, orientation, resize, minimize, close | Pending visual verification | The native window opened, but screenshot inspection is waiting for the Mac to be unlocked. |
| GPU completion and drawable presentation | Pending runtime verification | The probe has callbacks for per-frame Metal completion and drawable presentation; completion has not yet been observed. |
| Local JPEG decode | Passed | ImageIO decoded the base-game JPEG in memory as a 128 × 128 image. REA inventory and runtime file read remained read-only; no game image is saved here. |
| Local JPEG display | Pending visual and GPU verification | The image-mode window opened; visual inspection is waiting for the Mac to be unlocked. |
| Missing app path and invalid JPEG | Passed | Both runs exited nonzero with distinct path and JPEG-type errors. The invalid test image existed only in a temporary directory and was removed afterward. |

The read-only REA package inventory confirmed one occurrence of the requested JPEG at the expected relative base-game `Game/Bin` path. The inventory was complete within its container-entry scope and returned no image bytes. Evidence IDs: package inventory `ev_8029e882782e9f1e7c48c430d4eae627bc72fc18b5db9c297e88571d67d2145f`; selected path occurrence `ev_31695204de64665b6adecd3786cd70a649bb8711dd3569d972acc9e900592c7b`. Image decoding and visible presentation remain separate checks.

Reproduction commands:

```sh
cd metal4-probe
./compile.sh
./run.sh
./run.sh --app "/path/to/The Sims 3.app"
```

The run script enables Metal API Validation and Shader Validation. A successful support query or shader build alone is not evidence that a frame appeared. The runtime and visual checks will be recorded separately after they are performed.
