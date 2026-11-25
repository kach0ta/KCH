#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_JAR="${ANDROID_JAR:-/data/data/com.termux/files/usr/share/android-sdk/platforms/android-34/android.jar}"
OUT="$ROOT/dist"
BUILD="$ROOT/build/android"
for tool in aapt javac d8 zip zipalign apksigner keytool; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing tool: $tool"; exit 1; }
done
[ -f "$ANDROID_JAR" ] || { echo "android.jar not found: $ANDROID_JAR"; exit 1; }
KEYSTORE_DIR="$HOME/.config/kch"
KEYSTORE="$KEYSTORE_DIR/debug.keystore"
mkdir -p "$KEYSTORE_DIR"
# Preserve the existing local signing identity when upgrading from older project builds.
if [ ! -f "$KEYSTORE" ] && [ -f "$BUILD/debug.keystore" ]; then
  cp "$BUILD/debug.keystore" "$KEYSTORE"
fi
rm -rf "$BUILD"
mkdir -p "$BUILD/classes" "$BUILD/dex" "$OUT"
aapt package -f -M "$ROOT/app/src/main/AndroidManifest.xml" -I "$ANDROID_JAR" -F "$BUILD/base.apk"
javac -source 8 -target 8 -bootclasspath "$ANDROID_JAR" -d "$BUILD/classes" "$ROOT/app/src/main/java/com/kach0ta/kch/MainActivity.java"
mapfile -d '' CLASS_FILES < <(find "$BUILD/classes" -type f -name '*.class' -print0)
if [ "${#CLASS_FILES[@]}" -eq 0 ]; then
  echo "No compiled .class files found"
  exit 1
fi
d8 --min-api 23 --lib "$ANDROID_JAR" --output "$BUILD/dex" "${CLASS_FILES[@]}"
cp "$BUILD/base.apk" "$BUILD/unsigned.apk"
(cd "$BUILD/dex" && zip -q "$BUILD/unsigned.apk" classes.dex)
zipalign -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"
if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair -keystore "$KEYSTORE" -storepass android -alias kchdebug -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=KCH Debug,O=Kach0ta,C=XX"
fi
apksigner sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android --out "$OUT/KCH-debug.apk" "$BUILD/aligned.apk"
apksigner verify "$OUT/KCH-debug.apk"
echo "Built: $OUT/KCH-debug.apk"
