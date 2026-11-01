package com.eightbis.arnauth.wearos

import jnr.ffi.LibraryLoader
import jnr.ffi.Pointer
import jnr.ffi.Runtime
import jnr.ffi.Struct
import jnr.ffi.byref
import jnr.ffi.annotations.Out

/**
 * JNI bridge to arnauth-core (Rust) via dynamic library.
 * 
 * Build: cargo build --release --target aarch64-linux-android -p arnauth-cli
 * Deploy: adb push target/aarch64-linux-android/release/libarnauth_core.so /data/local/tmp/
 * 
 * Alternative: Use `cargo ndk` + `jni` crate for proper JNI bindings.
 * This is a minimal FFI prototype using JNR-FFI.
 */
object ArnauthBridge {
    private val runtime = Runtime.getRuntime(jnr.ffi.provider.jffi.Provider.getInstance())
    private val lib: ArnauthLib by lazy {
        LibraryLoader.create(ArnauthLib.class.java).load("/data/local/tmp/libarnauth_core.so")
    }

    interface ArnauthLib : jnr.ffi.Library {
        // Opaque context
        fun arnauth_init(home: Pointer): Int
        fun arnauth_free(ctx: Pointer)

        // Identity
        fun arnauth_quickstart(ctx: Pointer, label: Pointer, out_label: Pointer): Int
        fun arnauth_whoami(ctx: Pointer, out_json: Pointer): Int

        // Messaging
        fun arnauth_send(ctx: Pointer, to: Pointer, text: Pointer, via: Pointer): Int
        fun arnauth_inbox(ctx: Pointer, take: Int, out_json: Pointer): Int

        // Swarm
        fun arnauth_swarm_show(ctx: Pointer, out_json: Pointer): Int
    }

    private val ctx: Pointer by lazy {
        val home = "/data/local/arnauth"
        val p = runtime.newDirectMemory(home.toByteArray().size + 1)
        p.put(0, home.toByteArray(), 0, home.length)
        p.put(home.length, 0)
        val ctxPtr = runtime.newDirectMemory(8)
        lib.arnauth_init(p)
        ctxPtr
    }

    fun quickstart(label: String) {
        val labelPtr = runtime.newDirectMemory(label.toByteArray().size + 1)
        labelPtr.put(0, label.toByteArray(), 0, label.length)
        labelPtr.put(label.length, 0)
        val outPtr = runtime.newDirectMemory(256)
        val rc = lib.arnauth_quickstart(ctx, labelPtr, outPtr)
        if (rc != 0) throw RuntimeException("quickstart failed: $rc")
    }

    fun whoami(): String {
        val outPtr = runtime.newDirectMemory(4096)
        val rc = lib.arnauth_whoami(ctx, outPtr)
        if (rc != 0) throw RuntimeException("whoami failed: $rc")
        return outPtr.getString(0)
    }

    fun send(to: String, text: String, via: String? = null) {
        val toPtr = runtime.newDirectMemory(to.toByteArray().size + 1)
        toPtr.put(0, to.toByteArray(), 0, to.length)
        toPtr.put(to.length, 0)
        val textPtr = runtime.newDirectMemory(text.toByteArray().size + 1)
        textPtr.put(0, text.toByteArray(), 0, text.length)
        textPtr.put(text.length, 0)
        val viaPtr = if (via != null) {
            val p = runtime.newDirectMemory(via.toByteArray().size + 1)
            p.put(0, via.toByteArray(), 0, via.length)
            p.put(via.length, 0)
            p
        } else Pointer.NULL
        val rc = lib.arnauth_send(ctx, toPtr, textPtr, viaPtr)
        if (rc != 0) throw RuntimeException("send failed: $rc")
    }

    fun inbox(take: Boolean): List<String> {
        val outPtr = runtime.newDirectMemory(16384)
        val rc = lib.arnauth_inbox(ctx, if (take) 1 else 0, outPtr)
        if (rc != 0) throw RuntimeException("inbox failed: $rc")
        val json = outPtr.getString(0)
        return parseJsonArray(json)
    }

    fun swarmShow(): List<String> {
        val outPtr = runtime.newDirectMemory(16384)
        val rc = lib.arnauth_swarm_show(ctx, outPtr)
        if (rc != 0) throw RuntimeException("swarm failed: $rc")
        val json = outPtr.getString(0)
        return parseJsonArray(json)
    }

    private fun parseJsonArray(json: String): List<String> {
        // Minimal JSON array parsing — replace with kotlinx.serialization in production
        if (!json.startsWith("[") || !json.endsWith("]")) return emptyList()
        val inner = json.substring(1, json.length - 1).trim()
        if (inner.isBlank()) return emptyList()
        return inner.split("},{").map { it.replace("{", "").replace("}", "").trim() }
    }
}
