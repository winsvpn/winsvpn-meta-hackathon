package org.winsvpn.app

import java.io.File

/*
 * winn3_conformance_kotlin_harness.kt — the ANDROID half of the winn/3
 * cross-host conformance suite.
 *
 * ===========================================================================
 * WHAT IT PROVES
 * ===========================================================================
 *
 * That WinnV3Sizing and WinnV3Keys — the REAL sources, compiled unmodified from
 * android/app/src/main/kotlin — derive the same plan floors and the same
 * admission-tag inputs as winn3/carrier, winn3/session and cmd/winn3-gateway do
 * from the same operator configuration.
 *
 * WinnV3Posture.kt already says the important thing in a comment:
 *
 *   > THE TWO FILES ARE A PAIR: a change to a header cost, a class, or the
 *   > clamps in one of them is a change that must be made in the other in the
 *   > same commit.
 *
 * This harness is what makes that enforceable. A comment asking people not to
 * let two implementations drift is worth strictly less than a test that fails
 * when they do — and the drift it is asking about is defect 2, which shipped an
 * inner MTU of 1443 where the plan floor was 1359 and black-holed every
 * full-size flow the moment the session left UDP.
 *
 * ===========================================================================
 * WHAT IT DELIBERATELY DOES NOT DO
 * ===========================================================================
 *
 * It does not compare anything. It reads a TASK LIST of inputs — which never
 * carries an expected answer — runs the host's own derivation, and prints the
 * result as JSON. `cmd/winn3-conformance -verify` does the comparing, once, in
 * the same function the Go hosts are checked with.
 *
 * That split is deliberate. Three languages with three assertion
 * implementations is three chances to write a comparison that passes when it
 * should not, and the one nobody would have written carefully is the one that
 * would have had to catch defect 1.
 *
 * ===========================================================================
 * WHY IT RUNS WITHOUT GRADLE
 * ===========================================================================
 *
 * tools/verify_winn3_conformance.sh compiles this against the real sources with
 * kotlinc and android.jar on the classpath, and runs it on a plain JVM. No
 * Gradle daemon, no build lock — so a conformance run cannot collide with
 * another lane's build, and it cannot be skipped because the Android toolchain
 * was busy. WinnV3Posture.kt is deliberately free of Android imports.
 * WinnV3Keys.kt also has Android libcore descriptor operations for device key
 * custody; the runner selects its explicit SDK_INT=0 plain-JVM java.nio path
 * and supplies only the Android catch type needed by class verification. The
 * production derivation class itself is still compiled and run unmodified.
 *
 * Usage: winn3ConformanceMain <task-list-path>   (report JSON to stdout)
 */

private const val REPORT_HOST =
    "android/app/src/main/kotlin/org/winsvpn/app/{WinnV3Posture.kt:WinnV3Sizing, WinnV3Keys.kt}"

private class Task(val key: String, val args: List<String>)

private fun readTasks(path: String): List<Task> =
    File(path).readLines()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .map { line ->
            val parts = line.split(' ').filter { it.isNotEmpty() }
            Task(parts[0], parts.drop(1))
        }

private fun unhex(s: String): ByteArray =
    ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

/**
 * Standard-alphabet base64 with padding — the encoding a served `[winn]`
 * section carries and the one the signed gateway descriptor uses.
 *
 * Written out rather than taken from `java.util.Base64` so this harness stays
 * runnable on the same floor `android/app` targets (`minSdk` 24, where
 * `java.util.Base64` does not exist), and so it does not silently differ from
 * the decoder `WinnV3Keys` implements for exactly that reason.
 */
private fun base64(raw: ByteArray): String {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    val out = StringBuilder((raw.size + 2) / 3 * 4)
    var i = 0
    while (i < raw.size) {
        val remaining = raw.size - i
        val b0 = raw[i].toInt() and 0xFF
        val b1 = if (remaining > 1) raw[i + 1].toInt() and 0xFF else 0
        val b2 = if (remaining > 2) raw[i + 2].toInt() and 0xFF else 0
        val block = (b0 shl 16) or (b1 shl 8) or b2
        out.append(alphabet[(block shr 18) and 0x3F])
        out.append(alphabet[(block shr 12) and 0x3F])
        out.append(if (remaining > 1) alphabet[(block shr 6) and 0x3F] else '=')
        out.append(if (remaining > 2) alphabet[block and 0x3F] else '=')
        i += 3
    }
    return out.toString()
}

private fun jsonString(value: String): String = buildString {
    append('"')
    for (ch in value) {
        when (ch) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (ch < ' ') append("\\u%04x".format(ch.code)) else append(ch)
        }
    }
    append('"')
}

/**
 * The admission-tag inputs THIS HOST derives, by driving `WinnV3Keys.from` with
 * the operator's own `[winn]` values and reading back what it wrote.
 *
 * Read back off the FILES, not off the constructor arguments. `WinnV3Keys`
 * writes `admission.key` and a document naming it, and the engine keys with
 * whatever ended up in that file — so the file is the derivation and the
 * argument is only an intention. Reading the intention back would test nothing
 * that could ever be wrong.
 */
private class AdmissionInputs(val gatewayIdHex: String, val admissionKeyHex: String)

private fun deriveAdmission(
    gatewayId: String,
    admissionFile: String,
    workDir: File,
): AdmissionInputs {
    // THE SERVED ENCODINGS, since 2026-08-09. `[winn]` carries every
    // byte-valued field base64 — the encoding the ML-DSA-65-signed descriptor
    // uses and the one Apple, Windows and Linux also read — so the harness
    // hands this host exactly what a control plane sends.
    //
    // The task list carries the operator values as RAW TEXT (it is a
    // line-oriented file and cannot carry a decision about encoding), so the
    // base64 is applied HERE, at the boundary, which is precisely the step a
    // real hub performs. What comes back out of the key document and the key
    // file must be the operator's values again, byte for byte.
    //
    // The static keys are irrelevant to the admission tag but WinnV3Keys.from
    // refuses without them, correctly: there is no anonymous mode.
    val section = mapOf(
        WinnV3Keys.KEY_GATEWAY_ID to base64(gatewayId.toByteArray(Charsets.UTF_8)),
        WinnV3Keys.KEY_STATIC to base64(unhex("11".repeat(32))),
        WinnV3Keys.KEY_GATEWAY_STATIC to base64(unhex("22".repeat(32))),
        // TRIMMED ONCE, HERE, AND NEVER AGAIN. `admission_file` is the key
        // file's bytes as keygen wrote them, trailing newline included. The
        // rule the whole tree follows is "trim a trailing CR/LF and stop", and
        // the place it happens for a served config is the HUB — ServedWinnSection
        // base64-encodes Operator.AdmissionSecret(), which is exactly this.
        //
        // So the trim belongs to this line and not to WinnV3Keys. A host that
        // trimmed the DECODED bytes would be interpreting an opaque secret, and
        // an operator whose secret legitimately ends in a newline byte would
        // then be keyed one byte short of the gateway — silently, because the
        // tag inputs are never transmitted.
        WinnV3Keys.KEY_ADMISSION to
            base64(admissionFile.trimEnd('\r', '\n').toByteArray(Charsets.UTF_8)),
    )
    val keys = WinnV3Keys.from(section)
    val document = keys.writeTo(workDir)

    // The document is this host's own JSON. gateway_id is read back out of it
    // rather than out of the object, for the same reason the secret is read out
    // of the file: what the engine sees is the document.
    val text = document.readText()
    val marker = "\"gateway_id\":\""
    val start = text.indexOf(marker) + marker.length
    val end = text.indexOf('"', start)
    val emittedGatewayId = text.substring(start, end)
        .replace("\\\"", "\"").replace("\\\\", "\\")
        .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")

    val admissionBytes = File(workDir, "admission.key").readBytes()
    return AdmissionInputs(
        gatewayIdHex = hex(emittedGatewayId.toByteArray(Charsets.UTF_8)),
        admissionKeyHex = hex(admissionBytes),
    )
}

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("usage: winn3_conformance_kotlin_harness <task-list-path> [work-dir]")
        kotlin.system.exitProcess(2)
    }
    val tasks = readTasks(args[0])
    val workDir = File(if (args.size > 1) args[1] else System.getProperty("java.io.tmpdir"), "winn3-conformance-kotlin")
    workDir.deleteRecursively()
    workDir.mkdirs()

    var gatewayId = ""
    var admissionFile = ""
    var pathMtu = 0
    var classes: List<String> = emptyList()
    val floors = StringBuilder()
    val overheads = StringBuilder()
    var floorCount = 0
    var overheadCount = 0

    for (task in tasks) {
        when (task.key) {
            "operator_gateway_id_hex" -> gatewayId = String(unhex(task.args[0]), Charsets.UTF_8)
            "operator_admission_file_hex" -> admissionFile = String(unhex(task.args[0]), Charsets.UTF_8)
            "operator_path_mtu" -> pathMtu = task.args[0].toInt()
            "operator_classes" -> classes = task.args[0].split(',')
            "floor" -> {
                val plan = task.args[0].split(',')
                val mtu = task.args[1].toInt()
                // planFloorMessageSize / planFloorInnerMtu are the SHIPPING
                // functions WinnV3EngineConfig's constructor checks against.
                // Nothing is recomputed here.
                val message = WinnV3Sizing.planFloorMessageSize(mtu, plan)
                val inner = WinnV3Sizing.planFloorInnerMtu(mtu, plan)
                val v6 = WinnV3Sizing.planCarriesInnerIpv6(mtu, plan)
                if (floorCount++ > 0) floors.append(',')
                floors.append("{\"classes\":[")
                floors.append(plan.joinToString(",") { jsonString(it) })
                floors.append("],\"path_mtu\":").append(mtu)
                floors.append(",\"message_size\":").append(message)
                floors.append(",\"inner_mtu\":").append(inner)
                floors.append(",\"inner_ipv6\":").append(v6)
                // The suite's own two extra columns, so a Kotlin row is
                // directly diffable against a Go one.
                floors.append(",\"dialled_udp_v4_inner_mtu\":")
                    .append(WinnV3Sizing.innerMtuForPath(mtu, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD))
                floors.append(",\"gap_bytes\":")
                    .append(WinnV3Sizing.innerMtuForPath(mtu, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD) - inner)
                floors.append('}')
            }
            "overhead" -> {
                val cls = task.args[0]
                val ipv4 = task.args[1] == "4"
                if (overheadCount++ > 0) overheads.append(',')
                overheads.append("{\"class\":").append(jsonString(cls))
                overheads.append(",\"ipv4\":").append(ipv4)
                overheads.append(",\"overhead\":").append(WinnV3Sizing.carrierOverhead(cls, ipv4))
                overheads.append('}')
            }
        }
    }

    val admission = deriveAdmission(gatewayId, admissionFile, workDir)
    val refMessage = WinnV3Sizing.planFloorMessageSize(pathMtu, classes)
    val refInner = WinnV3Sizing.planFloorInnerMtu(pathMtu, classes)

    val report = buildString {
        append('{')
        append("\"host\":").append(jsonString(REPORT_HOST)).append(',')
        append("\"language\":\"kotlin\",")
        append("\"gateway_id_hex\":").append(jsonString(admission.gatewayIdHex)).append(',')
        append("\"admission_key_hex\":").append(jsonString(admission.admissionKeyHex)).append(',')
        // tag_size: this host never sets one. core.GatewayParams.TagSize zero
        // means DefaultTagSize, and the Kotlin document has no field for it, so
        // the value the gateway uses is the engine's default. Reported as the
        // default rather than declared not_derived, because "this host cannot
        // change it" is a stronger statement than "this host does not compute
        // it" and is the one a reader needs.
        append("\"tag_size\":32,")
        append("\"path_mtu\":").append(pathMtu).append(',')
        append("\"carrier_classes\":[")
        append(classes.joinToString(",") { jsonString(it) })
        append("],")
        append("\"message_size\":").append(refMessage).append(',')
        append("\"inner_mtu\":").append(refInner).append(',')
        append("\"inner_ipv6\":").append(WinnV3Sizing.planCarriesInnerIpv6(pathMtu, classes)).append(',')
        append("\"floors\":[").append(floors).append("],")
        append("\"overheads\":[").append(overheads).append("],")
        // This harness derives configuration and key material only. It does
        // not start an engine or send traffic, so it cannot honestly report a
        // transport observation. Android runtime transport proof remains
        // covered by WinnV3StagedStart and the Android engine tests.
        append("\"not_derived\":[\"transport_observed_both_ways\"]")
        append('}')
    }
    println(report)

    // The host's own self-check, run for its side effect only: it throws if
    // WinnV3Sizing no longer agrees with the worked examples winn3/tun and
    // winn3/carrier state in their own doc comments. Kept because it fails with
    // a better message than a numeric diff for the specific case of somebody
    // editing a header constant, and because it is what WinnV3PostureTest
    // already runs on device.
    WinnV3Sizing.assertsAgreeWithGo()
    workDir.deleteRecursively()
}
