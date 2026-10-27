import AppKit
import CoreGraphics
import ImageIO
import Metal
import MetalKit
import UniformTypeIdentifiers
import Darwin

private enum ProbeError: Error, CustomStringConvertible {
    case usage(String)
    case image(String)
    case metal(String)

    var description: String {
        switch self {
        case .usage(let message), .image(let message), .metal(let message):
            return message
        }
    }
}

private enum ProbeLog {
    private static let lock = NSLock()

    static func write(_ message: String, to handle: FileHandle = .standardOutput) {
        lock.lock()
        defer { lock.unlock() }
        if let data = (message + "\n").data(using: .utf8) {
            handle.write(data)
        }
    }
}

private struct ProbeOptions {
    let appPath: String?

    static func parse(_ arguments: [String]) throws -> ProbeOptions {
        guard !arguments.contains("--help") else {
            ProbeLog.write("Usage: metal4-probe [--app <path-to-app>]")
            ProbeLog.write("Without arguments, the app displays its synthetic orientation texture.")
            exit(EXIT_SUCCESS)
        }

        guard arguments.isEmpty || arguments.count == 2,
              arguments.isEmpty || arguments[0] == "--app" else {
            throw ProbeError.usage("Usage: metal4-probe [--app <path-to-app>]")
        }

        return ProbeOptions(appPath: arguments.first == "--app" ? arguments[1] : nil)
    }
}

private struct DecodedImage {
    let width: Int
    let height: Int
    let rgbaBytes: Data

    static func loadFromApp(at suppliedPath: String) throws -> DecodedImage {
        let root = URL(fileURLWithPath: suppliedPath).standardizedFileURL
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw ProbeError.image("App path does not exist or is not a directory: \(suppliedPath)")
        }

        let relativeCandidates = [
            "Contents/Resources/drive_c/Program Files (x86)/Electronic Arts/The Sims 3/Game/Bin/dialoglogo128x128.jpg",
            "Contents/Resources/drive_c/Program Files/Electronic Arts/The Sims 3/Game/Bin/dialoglogo128x128.jpg",
            "Contents/Resources/drive_c/Program Files (x86)/The Sims 3/Game/Bin/dialoglogo128x128.jpg",
            "Game/Bin/dialoglogo128x128.jpg",
        ]
        let found = relativeCandidates
            .map { (relative: $0, url: root.appending(path: $0)) }
            .first { FileManager.default.fileExists(atPath: $0.url.path) }

        guard let found else {
            throw ProbeError.image(
                "Could not find dialoglogo128x128.jpg in the expected Game/Bin locations under \(root.lastPathComponent)."
            )
        }

        let sourceOptions = [kCGImageSourceShouldCache: true] as CFDictionary
        guard let source = CGImageSourceCreateWithURL(found.url as CFURL, sourceOptions) else {
            throw ProbeError.image("ImageIO could not open \(found.relative).")
        }
        guard let imageType = CGImageSourceGetType(source), imageType as String == UTType.jpeg.identifier else {
            throw ProbeError.image("\(found.relative) is not a JPEG image.")
        }
        guard let image = CGImageSourceCreateImageAtIndex(source, 0, sourceOptions) else {
            throw ProbeError.image("ImageIO could not decode \(found.relative).")
        }

        let width = image.width
        let height = image.height
        guard width > 0, height > 0 else {
            throw ProbeError.image("ImageIO returned an empty image for \(found.relative).")
        }

        var rgbaBytes = Data(count: width * height * 4)
        let bitmapInfo = CGBitmapInfo.byteOrder32Big.union(
            CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue)
        )
        let rendered = rgbaBytes.withUnsafeMutableBytes { storage -> Bool in
            guard let baseAddress = storage.baseAddress,
                  let context = CGContext(
                    data: baseAddress,
                    width: width,
                    height: height,
                    bitsPerComponent: 8,
                    bytesPerRow: width * 4,
                    space: CGColorSpaceCreateDeviceRGB(),
                    bitmapInfo: bitmapInfo.rawValue
                  ) else {
                return false
            }
            context.translateBy(x: 0, y: CGFloat(height))
            context.scaleBy(x: 1, y: -1)
            context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
            return true
        }

        guard rendered else {
            throw ProbeError.image("ImageIO could not convert \(found.relative) to RGBA pixels.")
        }

        ProbeLog.write("image.decode=passed format=JPEG size=\(width)x\(height) source=Game/Bin/dialoglogo128x128.jpg")
        return DecodedImage(width: width, height: height, rgbaBytes: rgbaBytes)
    }
}

private struct TexturePixels {
    let width: Int
    let height: Int
    let rgbaBytes: Data

    static func synthetic() -> TexturePixels {
        let width = 256
        let height = 256
        var bytes = Data(count: width * height * 4)

        bytes.withUnsafeMutableBytes { storage in
            guard let pixels = storage.bindMemory(to: UInt8.self).baseAddress else { return }
            for y in 0..<height {
                for x in 0..<width {
                    let offset = (y * width + x) * 4
                    let color: (UInt8, UInt8, UInt8)
                    if x < 48 && y < 48 {
                        color = (238, 54, 58)       // top-left: red
                    } else if x >= width - 48 && y < 48 {
                        color = (54, 204, 112)      // top-right: green
                    } else if x < 48 && y >= height - 48 {
                        color = (58, 112, 238)      // bottom-left: blue
                    } else if x >= width - 48 && y >= height - 48 {
                        color = (244, 206, 55)      // bottom-right: yellow
                    } else {
                        let light = ((x / 32) + (y / 32)).isMultiple(of: 2)
                        color = light ? (222, 222, 222) : (44, 48, 58)
                    }
                    pixels[offset] = color.0
                    pixels[offset + 1] = color.1
                    pixels[offset + 2] = color.2
                    pixels[offset + 3] = 255
                }
            }
        }

        return TexturePixels(width: width, height: height, rgbaBytes: bytes)
    }
}

private final class FramePool: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 3)
    private let lock = NSLock()
    private var available = [0, 1, 2]

    func acquire() -> Int {
        semaphore.wait()
        lock.lock()
        defer { lock.unlock() }
        return available.removeFirst()
    }

    func release(_ slot: Int) {
        lock.lock()
        available.append(slot)
        lock.unlock()
        semaphore.signal()
    }
}

private final class ProbeStats: @unchecked Sendable {
    private let lock = NSLock()
    private var submitted = 0
    private var completed = 0
    private var presented = 0
    private var errors = 0

    func nextSubmission() -> Int {
        lock.lock()
        submitted += 1
        let frame = submitted
        lock.unlock()
        if frame == 1 {
            ProbeLog.write("frame.submitted=observed firstFrame=1")
        }
        return frame
    }

    func gpuCompleted(frame: Int, start: CFTimeInterval, end: CFTimeInterval, error: Error?) {
        lock.lock()
        completed += 1
        if error != nil { errors += 1 }
        let count = completed
        lock.unlock()

        if count == 1 {
            if let error {
                ProbeLog.write("gpu.completion=error frame=\(frame) message=\(error.localizedDescription)", to: .standardError)
            } else {
                let milliseconds = max(0, end - start) * 1_000
                ProbeLog.write(String(format: "gpu.completion=passed firstFrame=%d gpuTimeMs=%.3f", frame, milliseconds))
            }
        }
    }

    func drawablePresented(frame: Int) {
        lock.lock()
        presented += 1
        let count = presented
        lock.unlock()
        if count == 1 {
            ProbeLog.write("drawable.presentation=observed firstFrame=\(frame)")
        }
    }

    func runtimeFailure(_ message: String) {
        lock.lock()
        errors += 1
        lock.unlock()
        ProbeLog.write("runtime.error=\(message)", to: .standardError)
    }

    func summary() -> (submitted: Int, completed: Int, presented: Int, errors: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (submitted, completed, presented, errors)
    }
}

private final class FrameSlot {
    let allocator: any MTL4CommandAllocator
    let commandBuffer: any MTL4CommandBuffer
    let residencySet: any MTLResidencySet
    var renderTargetTexture: (any MTLTexture)?

    init(
        allocator: any MTL4CommandAllocator,
        commandBuffer: any MTL4CommandBuffer,
        residencySet: any MTLResidencySet
    ) {
        self.allocator = allocator
        self.commandBuffer = commandBuffer
        self.residencySet = residencySet
    }
}

private final class DrawableLease: @unchecked Sendable {
    let drawable: any CAMetalDrawable

    init(drawable: any CAMetalDrawable) {
        self.drawable = drawable
    }
}

@MainActor
private final class MetalRenderer: NSObject, MTKViewDelegate {
    private let device: any MTLDevice
    private let commandQueue: any MTL4CommandQueue
    private let pipeline: any MTLRenderPipelineState
    private let texture: any MTLTexture
    private let sampler: any MTLSamplerState
    private let argumentTable: any MTL4ArgumentTable
    private let frameSlots: [FrameSlot]
    private let framePool = FramePool()
    private let completionGroup = DispatchGroup()
    private let stats = ProbeStats()
    private var drawCallbackCount = 0
    private var didReportMissingDrawable = false

    init(view: MTKView, pixels: TexturePixels) throws {
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw ProbeError.metal("Metal is unavailable on this Mac.")
        }
        guard device.supportsFamily(.metal4) else {
            throw ProbeError.metal("The selected Metal device does not support Metal 4.")
        }
        ProbeLog.write("metal.support=detected metal4=true device=\(device.name)")

        view.device = device
        view.colorPixelFormat = .bgra8Unorm
        view.clearColor = MTLClearColorMake(0.10, 0.12, 0.16, 1.0)
        view.framebufferOnly = true
        view.enableSetNeedsDisplay = false
        view.isPaused = false
        view.preferredFramesPerSecond = 60

        let textureDescriptor = MTLTextureDescriptor.texture2DDescriptor(
            pixelFormat: .rgba8Unorm,
            width: pixels.width,
            height: pixels.height,
            mipmapped: false
        )
        textureDescriptor.storageMode = .shared
        textureDescriptor.usage = [.shaderRead]
        guard let texture = device.makeTexture(descriptor: textureDescriptor) else {
            throw ProbeError.metal("Metal could not allocate the texture.")
        }
        texture.label = "Probe source texture"
        pixels.rgbaBytes.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return }
            texture.replace(
                region: MTLRegionMake2D(0, 0, pixels.width, pixels.height),
                mipmapLevel: 0,
                withBytes: baseAddress,
                bytesPerRow: pixels.width * 4
            )
        }

        let samplerDescriptor = MTLSamplerDescriptor()
        samplerDescriptor.minFilter = .nearest
        samplerDescriptor.magFilter = .nearest
        samplerDescriptor.sAddressMode = .clampToEdge
        samplerDescriptor.tAddressMode = .clampToEdge
        guard let sampler = device.makeSamplerState(descriptor: samplerDescriptor) else {
            throw ProbeError.metal("Metal could not create the texture sampler.")
        }

        let compilerDescriptor = MTL4CompilerDescriptor()
        compilerDescriptor.label = "Metal 4 Probe Shader Compiler"
        let compiler = try device.makeCompiler(descriptor: compilerDescriptor)

        let libraryDescriptor = MTL4LibraryDescriptor()
        libraryDescriptor.name = "Metal 4 Probe Shaders"
        libraryDescriptor.source = Self.shaderSource
        let library = try compiler.makeLibrary(descriptor: libraryDescriptor)

        let vertexFunction = MTL4LibraryFunctionDescriptor()
        vertexFunction.library = library
        vertexFunction.name = "probeVertex"
        let fragmentFunction = MTL4LibraryFunctionDescriptor()
        fragmentFunction.library = library
        fragmentFunction.name = "probeFragment"

        let pipelineDescriptor = MTL4RenderPipelineDescriptor()
        pipelineDescriptor.vertexFunctionDescriptor = vertexFunction
        pipelineDescriptor.fragmentFunctionDescriptor = fragmentFunction
        pipelineDescriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat
        let pipeline = try compiler.makeRenderPipelineState(
            descriptor: pipelineDescriptor,
            compilerTaskOptions: nil
        )
        ProbeLog.write("shader.compile=passed compiler=MTL4Compiler")

        let tableDescriptor = MTL4ArgumentTableDescriptor()
        tableDescriptor.label = "Probe texture argument table"
        tableDescriptor.maxTextureBindCount = 1
        tableDescriptor.maxSamplerStateBindCount = 1
        tableDescriptor.initializeBindings = true
        let argumentTable = try device.makeArgumentTable(descriptor: tableDescriptor)
        argumentTable.setTexture(texture.gpuResourceID, index: 0)
        argumentTable.setSamplerState(sampler.gpuResourceID, index: 0)

        let queueDescriptor = MTL4CommandQueueDescriptor()
        queueDescriptor.label = "Metal 4 Probe Command Queue"
        let commandQueue = try device.makeMTL4CommandQueue(descriptor: queueDescriptor)

        var frameSlots: [FrameSlot] = []
        for index in 0..<3 {
            let allocatorDescriptor = MTL4CommandAllocatorDescriptor()
            allocatorDescriptor.label = "Probe frame allocator \(index)"
            let allocator = try device.makeCommandAllocator(descriptor: allocatorDescriptor)
            guard let commandBuffer = device.makeCommandBuffer() else {
                throw ProbeError.metal("Metal could not create the three frame command resources.")
            }
            commandBuffer.label = "Probe frame command buffer \(index)"
            let residencyDescriptor = MTLResidencySetDescriptor()
            residencyDescriptor.label = "Probe frame \(index) residency"
            residencyDescriptor.initialCapacity = 2
            let frameResidencySet = try device.makeResidencySet(descriptor: residencyDescriptor)
            frameResidencySet.addAllocation(texture)
            frameResidencySet.commit()
            commandQueue.addResidencySet(frameResidencySet)
            frameSlots.append(
                FrameSlot(
                    allocator: allocator,
                    commandBuffer: commandBuffer,
                    residencySet: frameResidencySet
                )
            )
        }

        self.device = device
        self.commandQueue = commandQueue
        self.pipeline = pipeline
        self.texture = texture
        self.sampler = sampler
        self.argumentTable = argumentTable
        self.frameSlots = frameSlots
        super.init()
        view.delegate = self
    }

    func draw(in view: MTKView) {
        drawCallbackCount += 1
        if drawCallbackCount == 1 {
            ProbeLog.write("draw.callback=entered size=\(Int(view.drawableSize.width))x\(Int(view.drawableSize.height)) paused=\(view.isPaused)")
        }
        guard let drawable = view.currentDrawable else {
            if !didReportMissingDrawable {
                didReportMissingDrawable = true
                ProbeLog.write("drawable.acquire=unavailable", to: .standardError)
            }
            return
        }
        let size = view.drawableSize
        guard size.width > 0, size.height > 0 else { return }

        let slotIndex = framePool.acquire()
        let slot = frameSlots[slotIndex]
        if let previousTarget = slot.renderTargetTexture {
            slot.residencySet.removeAllocation(previousTarget)
        }
        slot.residencySet.addAllocation(drawable.texture)
        slot.residencySet.commit()
        slot.renderTargetTexture = drawable.texture
        slot.allocator.reset()
        slot.commandBuffer.beginCommandBuffer(allocator: slot.allocator)
        slot.commandBuffer.useResidencySet(slot.residencySet)

        let passDescriptor = MTL4RenderPassDescriptor()
        guard let colorAttachment = passDescriptor.colorAttachments[0] else {
            slot.commandBuffer.endCommandBuffer()
            framePool.release(slotIndex)
            stats.runtimeFailure("Metal could not create the color attachment descriptor.")
            return
        }
        colorAttachment.texture = drawable.texture
        colorAttachment.loadAction = .clear
        colorAttachment.storeAction = .store
        colorAttachment.clearColor = view.clearColor

        guard let encoder = slot.commandBuffer.makeRenderCommandEncoder(
            descriptor: passDescriptor,
            options: []
        ) else {
            slot.commandBuffer.endCommandBuffer()
            framePool.release(slotIndex)
            stats.runtimeFailure("Metal could not create an MTL4RenderCommandEncoder.")
            return
        }

        encoder.setRenderPipelineState(pipeline)
        let side = min(size.width, size.height) * 0.74
        let viewport = MTLViewport(
            originX: (size.width - side) / 2,
            originY: (size.height - side) / 2,
            width: side,
            height: side,
            znear: 0,
            zfar: 1
        )
        encoder.setViewport(viewport)
        encoder.setArgumentTable(argumentTable, stages: .fragment)
        encoder.drawPrimitives(primitiveType: .triangle, vertexStart: 0, vertexCount: 6)
        encoder.endEncoding()
        slot.commandBuffer.endCommandBuffer()

        let submittedFrame = stats.nextSubmission()
        let framePool = self.framePool
        let completionGroup = self.completionGroup
        let stats = self.stats
        let drawableLease = DrawableLease(drawable: drawable)
        completionGroup.enter()

        let commitOptions = MTL4CommitOptions()
        commitOptions.addFeedbackHandler { feedback in
            stats.gpuCompleted(
                frame: submittedFrame,
                start: feedback.gpuStartTime,
                end: feedback.gpuEndTime,
                error: feedback.error
            )
            _ = drawableLease.drawable
            framePool.release(slotIndex)
            completionGroup.leave()
        }

        drawable.addPresentedHandler { _ in
            stats.drawablePresented(frame: submittedFrame)
        }

        commandQueue.commit([slot.commandBuffer], options: commitOptions)
        commandQueue.signalDrawable(drawable)
        drawable.present()
    }

    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
        // The square viewport is recalculated from the current drawable size for each frame.
    }

    func waitForGPUCompletion() {
        completionGroup.wait()
        let summary = stats.summary()
        ProbeLog.write(
            "frames.summary submitted=\(summary.submitted) gpuCompleted=\(summary.completed) presented=\(summary.presented) errors=\(summary.errors)"
        )
        ProbeLog.write("allocator.reuse=after-gpu-completion maxFramesInFlight=3")
    }

    private static let shaderSource = #"""
    #include <metal_stdlib>
    using namespace metal;

    struct ProbeVertexOut {
        float4 position [[position]];
        float2 texCoord;
    };

    vertex ProbeVertexOut probeVertex(uint vertexID [[vertex_id]]) {
        constexpr float2 positions[6] = {
            float2(-1.0,  1.0), float2(-1.0, -1.0), float2( 1.0,  1.0),
            float2( 1.0,  1.0), float2(-1.0, -1.0), float2( 1.0, -1.0)
        };
        constexpr float2 texCoords[6] = {
            float2(0.0, 0.0), float2(0.0, 1.0), float2(1.0, 0.0),
            float2(1.0, 0.0), float2(0.0, 1.0), float2(1.0, 1.0)
        };
        ProbeVertexOut out;
        out.position = float4(positions[vertexID], 0.0, 1.0);
        out.texCoord = texCoords[vertexID];
        return out;
    }

    fragment float4 probeFragment(
        ProbeVertexOut in [[stage_in]],
        texture2d<float> sourceTexture [[texture(0)]],
        sampler sourceSampler [[sampler(0)]]) {
        return sourceTexture.sample(sourceSampler, in.texCoord);
    }
    """#
}

@MainActor
private final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private let pixels: TexturePixels
    private var window: NSWindow?
    private var renderer: MetalRenderer?

    init(pixels: TexturePixels) {
        self.pixels = pixels
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let view = MTKView(frame: NSRect(x: 0, y: 0, width: 800, height: 600), device: nil)
        do {
            let renderer = try MetalRenderer(view: view, pixels: pixels)
            self.renderer = renderer
        } catch {
            ProbeLog.write("Metal 4 initialization failed: \(error)", to: .standardError)
            exit(EXIT_FAILURE)
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Metal 4 Texture Probe"
        window.contentView = view
        window.center()
        window.delegate = self
        self.window = window
        window.makeKeyAndOrderFront(nil)
        view.needsDisplay = true
        NSApp.activate(ignoringOtherApps: true)
        ProbeLog.write("window.open=passed content=800x600 resizable=true")
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        renderer?.waitForGPUCompletion()
    }
}

@main
@MainActor
private enum Metal4ProbeMain {
    static func main() {
        do {
            let options = try ProbeOptions.parse(Array(CommandLine.arguments.dropFirst()))
            let pixels: TexturePixels
            if let appPath = options.appPath {
                let image = try DecodedImage.loadFromApp(at: appPath)
                pixels = TexturePixels(width: image.width, height: image.height, rgbaBytes: image.rgbaBytes)
            } else {
                pixels = TexturePixels.synthetic()
                ProbeLog.write("image.mode=synthetic size=256x256 orientationMarkers=red-green-blue-yellow")
            }

            let application = NSApplication.shared
            application.setActivationPolicy(.regular)
            let delegate = AppDelegate(pixels: pixels)
            application.delegate = delegate
            application.run()
        } catch {
            ProbeLog.write("Metal 4 probe failed: \(error)", to: .standardError)
            exit(EXIT_FAILURE)
        }
    }
}
