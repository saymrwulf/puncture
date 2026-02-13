import AppKit
import ImageIO
import UniformTypeIdentifiers

let size = CGFloat(1024)
let canvas = NSImage(size: NSSize(width: size, height: size))

canvas.lockFocus()
defer { canvas.unlockFocus() }

let full = NSRect(x: 0, y: 0, width: size, height: size)
NSColor.clear.setFill()
full.fill()

let plateRect = NSRect(x: 42, y: 42, width: size - 84, height: size - 84)
let plate = NSBezierPath(roundedRect: plateRect, xRadius: 210, yRadius: 210)
let bg = NSGradient(colors: [
    NSColor(calibratedRed: 0.05, green: 0.54, blue: 0.66, alpha: 1.0),
    NSColor(calibratedRed: 0.05, green: 0.34, blue: 0.58, alpha: 1.0),
    NSColor(calibratedRed: 0.10, green: 0.18, blue: 0.35, alpha: 1.0)
])!
bg.draw(in: plate, angle: -35)

let gloss = NSGradient(colors: [
    NSColor(calibratedWhite: 1.0, alpha: 0.28),
    NSColor(calibratedWhite: 1.0, alpha: 0.04),
    NSColor(calibratedWhite: 1.0, alpha: 0.00)
])!
let glossPath = NSBezierPath(ovalIn: NSRect(x: 120, y: 585, width: 780, height: 360))
gloss.draw(in: glossPath, angle: -65)

let ringRect = NSRect(x: 168, y: 158, width: 688, height: 688)
let ringOuter = NSBezierPath(ovalIn: ringRect)
NSColor(calibratedRed: 0.62, green: 0.93, blue: 0.92, alpha: 0.22).setStroke()
ringOuter.lineWidth = 18
ringOuter.stroke()

let line = NSBezierPath()
line.lineCapStyle = .round
line.lineJoinStyle = .round
line.lineWidth = 22

func seg(_ x1: CGFloat, _ y1: CGFloat, _ x2: CGFloat, _ y2: CGFloat) {
    line.move(to: NSPoint(x: x1, y: y1))
    line.line(to: NSPoint(x: x2, y: y2))
}

seg(512, 770, 368, 640)
seg(512, 770, 656, 640)
seg(368, 640, 290, 520)
seg(368, 640, 450, 520)
seg(656, 640, 578, 520)
seg(656, 640, 736, 520)
seg(736, 520, 790, 405)
NSColor(calibratedRed: 0.78, green: 0.95, blue: 0.98, alpha: 0.90).setStroke()
line.stroke()

let cut = NSBezierPath()
cut.lineWidth = 24
cut.lineCapStyle = .round
cut.move(to: NSPoint(x: 740, y: 560))
cut.line(to: NSPoint(x: 834, y: 452))
NSColor(calibratedRed: 1.0, green: 0.28, blue: 0.31, alpha: 0.96).setStroke()
cut.stroke()

func dot(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat, _ color: NSColor) {
    let p = NSBezierPath(ovalIn: NSRect(x: x - r, y: y - r, width: r * 2, height: r * 2))
    color.setFill()
    p.fill()
}

dot(512, 770, 27, NSColor(calibratedRed: 0.93, green: 0.99, blue: 1.0, alpha: 0.96))
let nodeColor = NSColor(calibratedRed: 0.86, green: 0.97, blue: 0.99, alpha: 0.95)
for p in [
    (368.0, 640.0), (656.0, 640.0),
    (290.0, 520.0), (450.0, 520.0), (578.0, 520.0), (736.0, 520.0),
    (790.0, 405.0)
] {
    dot(CGFloat(p.0), CGFloat(p.1), 18, nodeColor)
}

dot(790, 405, 16, NSColor(calibratedRed: 1.0, green: 0.58, blue: 0.62, alpha: 0.98))

let lockBody = NSBezierPath(roundedRect: NSRect(x: 372, y: 225, width: 280, height: 248), xRadius: 62, yRadius: 62)
NSColor(calibratedRed: 0.03, green: 0.16, blue: 0.28, alpha: 0.94).setFill()
lockBody.fill()
NSColor(calibratedRed: 0.75, green: 0.95, blue: 0.99, alpha: 0.92).setStroke()
lockBody.lineWidth = 10
lockBody.stroke()

let shackle = NSBezierPath()
shackle.lineWidth = 28
shackle.lineCapStyle = .round
shackle.move(to: NSPoint(x: 430, y: 474))
shackle.curve(to: NSPoint(x: 594, y: 474), controlPoint1: NSPoint(x: 430, y: 560), controlPoint2: NSPoint(x: 594, y: 560))
NSColor(calibratedRed: 0.82, green: 0.97, blue: 1.0, alpha: 0.94).setStroke()
shackle.stroke()

let keyhole = NSBezierPath(ovalIn: NSRect(x: 492, y: 324, width: 40, height: 54))
NSColor(calibratedRed: 0.81, green: 0.97, blue: 1.0, alpha: 0.95).setFill()
keyhole.fill()
let stem = NSBezierPath(roundedRect: NSRect(x: 505, y: 286, width: 14, height: 58), xRadius: 7, yRadius: 7)
stem.fill()

guard let cgImage = NSBitmapImageRep(focusedViewRect: full)?.cgImage else {
    fputs("Failed to capture rendered image\n", stderr)
    exit(1)
}

let outURL = URL(fileURLWithPath: "/Users/oho/GitClone/CodexProjects/puncture/goapp/packaging/macos/icon_work/AppIcon-1024.png")
guard let destination = CGImageDestinationCreateWithURL(outURL as CFURL, UTType.png.identifier as CFString, 1, nil) else {
    fputs("Failed to create image destination\n", stderr)
    exit(1)
}
CGImageDestinationAddImage(destination, cgImage, nil)
if CGImageDestinationFinalize(destination) {
    print("Wrote \(outURL.path)")
} else {
    fputs("Failed to finalize PNG destination\n", stderr)
    exit(1)
}
