# Metal 4 texture probe

This standalone macOS program opens a resizable 800 × 600 window and draws a centered textured square with Metal 4. It is separate from the C++ CPU lab and does not change the shared project documentation.

The default mode builds an in-memory checker texture with red, green, blue, and yellow corner markers. The markers make vertical and horizontal flips visible. The resource mode decodes `dialoglogo128x128.jpg` from a caller-supplied Sims 3 app bundle with ImageIO; it does not copy the image into this repository.

## Build and run

From this directory:

```sh
./compile.sh
./run.sh
./run.sh --app "/path/to/The Sims 3.app"
```

The build targets ARM64 and macOS 26 or later. `MTL_DEBUG_LAYER=1` and Metal Shader Validation are enabled by default by `run.sh`; set either variable to `0` to disable that layer for a run.

The app path is checked for the image in the standard `Contents/Resources/drive_c/Program Files (x86)/Electronic Arts/The Sims 3/Game/Bin/` location, with a few common `Program Files` and direct `Game/Bin` alternatives. If the file is missing, is not JPEG, or cannot be decoded, the command exits with a nonzero status and an error on standard error.

## Reading the output

- `metal.support=detected metal4=true` reports device support.
- `shader.compile=passed compiler=MTL4Compiler` means the system compiler produced the shader library and render pipeline.
- `image.decode=passed ...` confirms ImageIO read the local JPEG; it does not by itself prove the image reached the display.
- `gpu.completion=passed` reports the first completed GPU workload. A drawable callback separately reports actual presentation.
- `frames.summary` reports submitted, GPU-completed, presented, and failed workloads when the window closes.

The renderer keeps the texture, sampler, argument table, residency set, command buffer, allocator, and drawable alive for the relevant work. It uses three frame slots; each allocator is reset only after Metal reports completion for the command buffer using it.

## Result record

See [results.md](results.md) for the sanitized build and runtime observations. Game images, screenshots, captures, and install-specific paths do not belong in this directory.

## Apple references

- [Understanding the Metal 4 core API](https://developer.apple.com/documentation/metal/understanding-the-metal-4-core-api)
- [Using the Metal 4 compilation API](https://developer.apple.com/documentation/metal/using-the-metal-4-compilation-api)
- [Validating your app’s Metal API usage](https://developer.apple.com/documentation/xcode/validating-your-apps-metal-api-usage)
