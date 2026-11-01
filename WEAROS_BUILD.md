# Arnauth on WearOS (Galaxy Watch)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WearOS App (Kotlin)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ UI Layer    │  │ Bridge      │  │ arnauth-core (Rust) │  │
│  │ Compose     │◄─►│ JNI / FFI   │◄─►│ aarch64-linux-android│  │
│  │ Watch Face  │  │ (JNA/Rust)  │  │ + wupz SIMD (Zig)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         │                    ▲                    │
         ▼                    │                    ▼
   Bluetooth LE          arnauth mcp          Encrypted spool
   (courier relay)       (stdio bridge)       (/data/local/arnauth)
```

## Build Steps

### 1. Prerequisites

```bash
# Android SDK + NDK r27+
# Via Android Studio or:
# sdkmanager "ndk;27.0.12077973" "cmake;3.22.1"

export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.0.12077973"
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
```

### 2. Rust Target

```bash
rustup target add aarch64-linux-android
```

### 3. Cross-compile arnauth-core + CLI

```bash
cd /Users/wraith/source/8b-is/arnauth
./build-android.sh
```

Output: `target/aarch64-linux-android/release/arnauth`

### 4. Zig SIMD Kernels for Android (optional but recommended)

```bash
# Build Zig staticlib for aarch64-linux-android
cd /Users/wraith/source/8b-is/wupz/wupz-zig
zig build -Dtarget=aarch64-linux-android -Doptimize=ReleaseSafe

# Output: zig-out/lib/libwupz_kernels.a
# Link with: -Lzig-out/lib -lwupz_kernels
```

### 5. Deploy to Watch

```bash
adb push target/aarch64-linux-android/release/arnauth /data/local/tmp/arnauth
adb shell chmod +x /data/local/tmp/arnauth

# Test
adb shell /data/local/tmp/arnauth --help
adb shell /data/local/tmp/arnauth quickstart watch.eth
```

## MCP Bridge on Watch

The `arnauth mcp` stdio server runs on the watch and exposes 6 tools:
- `arnauth_whoami` — active identity
- `arnauth_identities` — list identities
- `arnauth_peers` — beehive peers
- `arnauth_send` — send sealed message
- `arnauth_inbox` — read queue
- `arnauth_receipt` — hive consolidation receipt

### Ultra-Omni Bridge Integration

From the watch, messages route via:
1. Watch → Phone (Bluetooth LE courier relay)
2. Phone → WhatsApp / OpenCode / Discord (existing ultra-omni.mjs)
3. Replies return via same path

## Store Layout on WearOS

```
/data/local/arnauth/              ($ARNAUTH_HOME)
├── active
├── identities/watch.eth/
│   ├── identity.json
│   ├── key.bin
│   ├── pq.bin
│   └── pq.json
├── beehive.json
├── contacts.json
├── transport/
└── downloads/
```

## Known Constraints

| Constraint | Mitigation |
|------------|------------|
| No background execution | Foreground service + periodic work |
| Limited battery | Batch sync, aggressive forget |
| No direct internet | Courier relay via phone |
| Small screen | Voice-first UI, haptic confirm |

## Next Steps

1. **WearOS app scaffold** (Kotlin + Compose for Wear)
2. **JNI bridge** — `cargo ndk` + `jni` crate for arnauth-core
3. **BLE courier** — Phone app relays sealed boxes
4. **MCP stdio** — Watch runs `arnauth mcp`, phone proxies
