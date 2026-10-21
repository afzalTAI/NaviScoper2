#!/bin/sh
# Package dist/NaviScope.app into dist/NaviScope-<version>-universal.dmg with
# an /Applications symlink for drag-install. Uses hdiutil only; no Developer
# ID or notarization (first launch: right-click → Open, or System Settings
# approval) until an Apple signing identity is available.
set -eu
cd "$(dirname "$0")/.."
version="0.1"
stage="dist/dmg-stage"
dmg="dist/NaviScope-$version-universal.dmg"
rm -rf "$stage" "$dmg"
mkdir -p "$stage"
sh scripts/build-macos-app.sh
cp -R dist/NaviScope.app "$stage/NaviScope.app"
ln -s /Applications "$stage/Applications"
hdiutil create -volname "NaviScope" -srcfolder "$stage" -format UDZO -ov "$dmg" >/dev/null
rm -rf "$stage"
echo "Built $dmg"
