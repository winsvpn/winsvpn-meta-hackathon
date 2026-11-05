package org.winsvpn.app

import java.io.IOException
import kotlin.io.encoding.Base64

/**
 * Converts an awg-quick INI document to the UAPI key=value document official
 * amneziawg-go v3 [IpcSet] consumes.
 *
 * The archived zaneschepke native layer parsed INI itself. Official
 * amnezia-vpn/amneziawg-android v3.1.20260814 does not. This is the
 * adaptation that lets the existing Dart INI stay in place without retaining
 * that fork.
 *
 * Field names and omit-zero rules follow official
 * `Interface.toAwgUserspaceString` / `Peer.toAwgUserspaceString`.
 */
internal object AwgUserspaceConfig {

    private val skippedInterfaceKeys = setOf(
        "address",
        "dns",
        "mtu",
        "table",
        "excludedapplications",
        "includedapplications",
    )

    private val boolInterfaceKeys = mapOf(
        "randomtrailers" to "random_trailers",
        "disablecookies" to "disable_cookies",
    )

    private val copiedInterfaceKeys = mapOf(
        "listenport" to "listen_port",
        "jc" to "jc",
        "jmin" to "jmin",
        "jmax" to "jmax",
        "s1" to "s1",
        "s2" to "s2",
        "s3" to "s3",
        "s4" to "s4",
        "h1" to "h1",
        "h2" to "h2",
        "h3" to "h3",
        "h4" to "h4",
        "i1" to "i1",
        "i2" to "i2",
        "i3" to "i3",
        "i4" to "i4",
        "i5" to "i5",
        "contentpaddingaddition" to "content_padding_addition",
        "rekeyaftertime" to "rekey_after_time",
        "rekeytimeout" to "rekey_timeout",
        "rejectaftertime" to "reject_after_time",
        "keepalivetimeout" to "keepalive_timeout",
        "maxhandshakeattempts" to "max_handshake_attempts",
    )

    private val omitZeroKeys = setOf(
        "listenport", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
    )

    @Throws(IOException::class)
    fun fromQuick(settings: String): String {
        if (!looksLikeAwgQuick(settings)) {
            return settings
        }
        return convert(settings, peersOnly = false)
    }

    @Throws(IOException::class)
    fun peerUpdateFromQuick(settings: String): String {
        if (!looksLikeAwgQuick(settings)) {
            return settings
        }
        return convert(settings, peersOnly = true)
    }

    fun looksLikeAwgQuick(settings: String): Boolean {
        for (raw in settings.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val lower = line.lowercase()
            if (lower == "[interface]" || lower == "[peer]") return true
        }
        return false
    }

    @Throws(IOException::class)
    private fun convert(settings: String, peersOnly: Boolean): String {
        data class Section(val name: String, val attrs: MutableList<Pair<String, String>>)

        val sections = ArrayList<Section>()
        var current: Section? = null
        for (raw in settings.split("\n")) {
            var line = raw.trim()
            val hash = line.indexOf('#')
            if (hash >= 0) line = line.substring(0, hash).trim()
            if (line.isEmpty()) continue
            if (line.startsWith("[")) {
                if (!line.endsWith("]")) {
                    throw IOException("malformed section header")
                }
                val name = line.substring(1, line.length - 1).trim().lowercase()
                if (name != "interface" && name != "peer") {
                    throw IOException("unsupported section [${printable(name)}]")
                }
                val next = Section(name, mutableListOf())
                sections.add(next)
                current = next
                continue
            }
            val owner = current ?: throw IOException("attribute outside a section")
            val sep = line.indexOf('=')
            if (sep <= 0) throw IOException("malformed attribute in [${owner.name}]")
            owner.attrs.add(
                line.substring(0, sep).trim().lowercase() to line.substring(sep + 1).trim(),
            )
        }
        if (sections.isEmpty()) throw IOException("empty AmneziaWG configuration")

        val out = StringBuilder()
        var sawInterface = false
        var sawPeer = false
        for (section in sections) {
            when (section.name) {
                "interface" -> {
                    if (peersOnly) continue
                    if (sawInterface) throw IOException("multiple [Interface] sections")
                    sawInterface = true
                    out.append(interfaceUserspace(section.attrs))
                }
                "peer" -> {
                    if (!peersOnly && !sawInterface) {
                        throw IOException("[Peer] before [Interface]")
                    }
                    if (!peersOnly && !sawPeer) {
                        out.append("replace_peers=true\n")
                    }
                    sawPeer = true
                    out.append(peerUserspace(section.attrs))
                }
            }
        }
        if (!peersOnly && !sawInterface) throw IOException("missing [Interface] section")
        if (!sawPeer) throw IOException("missing [Peer] section")
        return out.toString()
    }

    @Throws(IOException::class)
    private fun interfaceUserspace(attrs: List<Pair<String, String>>): String {
        var privateKey: String? = null
        val rest = StringBuilder()
        for ((key, value) in attrs) {
            if (key in skippedInterfaceKeys) continue
            when (key) {
                "privatekey" -> privateKey = wgKeyToHex(value, "PrivateKey")
                "headerprotectionkey" -> {
                    if (value.isEmpty()) continue
                    rest.append("header_protection_key=")
                        .append(wgKeyToHex(value, "HeaderProtectionKey"))
                        .append('\n')
                }
                else -> {
                    val boolKey = boolInterfaceKeys[key]
                    if (boolKey != null) {
                        if (value.isEmpty()) continue
                        rest.append(boolKey).append('=').append(toUapiBool(value)).append('\n')
                        continue
                    }
                    val copied = copiedInterfaceKeys[key]
                        ?: throw IOException("unknown [Interface] attribute ${printable(key)}")
                    if (value.isEmpty() || omitZero(key, value)) continue
                    rest.append(copied).append('=').append(value).append('\n')
                }
            }
        }
        val key = privateKey ?: throw IOException("missing PrivateKey")
        return "private_key=$key\n$rest"
    }

    @Throws(IOException::class)
    private fun peerUserspace(attrs: List<Pair<String, String>>): String {
        var publicKey: String? = null
        val rest = StringBuilder()
        for ((key, value) in attrs) {
            when (key) {
                "publickey" -> publicKey = wgKeyToHex(value, "PublicKey")
                "presharedkey" -> {
                    if (value.isEmpty()) continue
                    rest.append("preshared_key=")
                        .append(wgKeyToHex(value, "PresharedKey"))
                        .append('\n')
                }
                "endpoint" -> {
                    if (value.isEmpty()) continue
                    rest.append("endpoint=").append(numericEndpoint(value)).append('\n')
                }
                "persistentkeepalive" -> {
                    val trimmed = value.trim()
                    if (trimmed.isEmpty() || trimmed.equals("off", ignoreCase = true)) continue
                    rest.append("persistent_keepalive_interval=").append(trimmed).append('\n')
                }
                "allowedips" -> {
                    for (cidr in value.split(',')) {
                        val part = cidr.trim()
                        if (part.isNotEmpty()) rest.append("allowed_ip=").append(part).append('\n')
                    }
                }
                else -> throw IOException("unknown [Peer] attribute ${printable(key)}")
            }
        }
        val key = publicKey ?: throw IOException("missing PublicKey")
        return "public_key=$key\n$rest"
    }

    private fun omitZero(key: String, value: String): Boolean {
        if (key !in omitZeroKeys) return false
        return value.trim().toIntOrNull() == 0
    }

    private fun toUapiBool(value: String): String =
        when (value.trim().lowercase()) {
            "on", "1", "true", "t", "yes" -> "1"
            else -> "0"
        }


    /** A config token safe to echo into an error message, which release logcat keeps. */
    private fun printable(token: String): String =
        if (token.length in 1..32 && token.all { it.isLetterOrDigit() || it == '_' || it == '-' }) {
            token
        } else {
            "<redacted>"
        }

    @Throws(IOException::class)
    private fun wgKeyToHex(b64: String, label: String): String {
        val raw = try {
            Base64.Default.decode(b64.trim())
        } catch (error: IllegalArgumentException) {
            throw IOException("$label is not standard base64", error)
        }
        if (raw.size != 32) {
            throw IOException("$label must be 32 bytes, got ${raw.size}")
        }
        return raw.joinToString("") { byte -> "%02x".format(byte) }
    }

    /**
     * The peer endpoint, which must already be numeric. This converter runs on
     * the engine thread AFTER establish(), when this app's own lookups are
     * routed into its own tun, so a name is pinned by [pinPeerEndpoint] before
     * the tunnel exists and is never resolved here.
     */
    @Throws(IOException::class)
    private fun numericEndpoint(value: String): String {
        val trimmed = value.trim()
        if (!WinnEngineConfig.isIpLiteralEndpoint(trimmed)) {
            throw IOException(
                "AmneziaWG peer endpoint must be a numeric address; pin it before establish()",
            )
        }
        return trimmed
    }

}
