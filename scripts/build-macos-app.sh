#!/bin/sh
# Assemble dist/NaviScope.app: universal (arm64+amd64) macOS menu-bar agent
# with the proxy, console, secure DNS, and upstream chaining embedded.
# Ad-hoc signed so it launches locally without a developer ID.
#
# Minimum macOS: 10.15 (the Go runtime's floor; no supported toolchain can
# target older). Sierra 10.12 is not reachable with a maintained Go.
set -eu
cd "$(dirname "$0")/.."
app="dist/NaviScope.app"
contents="$app/Contents"
mkdir -p "$contents/MacOS" "$contents/Resources"

# Icon set from the generated compass mark.
go run ./scripts/genicon "$contents/Resources/icon1024.png"
iconset="$contents/Resources/AppIcon.iconset"
rm -rf "$iconset"; mkdir -p "$iconset"
for sz in 16 32 128 256 512; do
	sips -z "$sz" "$sz" "$contents/Resources/icon1024.png" --out "$iconset/icon_${sz}x${sz}.png" >/dev/null
	sz2=$((sz * 2))
	sips -z "$sz2" "$sz2" "$contents/Resources/icon1024.png" --out "$iconset/icon_${sz}x${sz}@2x.png" >/dev/null
done
iconutil -c icns -o "$contents/Resources/AppIcon.icns" "$iconset"
rm -rf "$iconset" "$contents/Resources/icon1024.png"

# Universal binary: both arm64 and amd64 slices, cgo for AppKit.
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -trimpath -o /tmp/nscope-menu-arm64 ./cmd/nscope-menu
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -trimpath -o /tmp/nscope-menu-amd64 ./cmd/nscope-menu
lipo -create -output "$contents/MacOS/nscope-menu" /tmp/nscope-menu-arm64 /tmp/nscope-menu-amd64
rm -f /tmp/nscope-menu-arm64 /tmp/nscope-menu-amd64

cat >"$contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>NaviScope</string>
	<key>CFBundleDisplayName</key><string>NaviScope</string>
	<key>CFBundleExecutable</key><string>nscope-menu</string>
	<key>CFBundleIdentifier</key><string>local.naviscopereborn.menu</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>0.1</string>
	<key>CFBundleVersion</key><string>1</string>
	<key>CFBundleIconFile</key><string>AppIcon</string>
	<key>NSPrincipalClass</key><string>NSApplication</string>
	<key>LSMinimumSystemVersion</key><string>10.15</string>
	<!-- Menu-bar agent: no Dock icon, no main window. -->
	<key>LSUIElement</key><true/>
</dict>
</plist>
PLIST
codesign --force --sign - "$app" >/dev/null 2>&1 || echo "warning: ad-hoc codesign unavailable; unsigned bundle may need Gatekeeper approval"
echo "Built $app (universal)"
