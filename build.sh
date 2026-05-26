#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
rm -rf build/classes
mkdir -p build/classes
find src/main/java -name '*.java' > sources.txt
javac -source 17 -target 17 \
  --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.commons=ALL-UNNAMED \
  -d build/classes @sources.txt
if [ -d src/main/resources ]; then cp -R src/main/resources/. build/classes/; fi
cat > MANIFEST.MF <<'MANIFEST'
Manifest-Version: 1.0
Main-Class: dev.mcshield.obf.McShieldObf
Implementation-Title: McShield Obfuscator
Implementation-Version: 1.0.0

MANIFEST
jar cfm mcshield-1.0.jar MANIFEST.MF -C build/classes .
echo "Built: $(pwd)/mcshield-1.0.jar"
