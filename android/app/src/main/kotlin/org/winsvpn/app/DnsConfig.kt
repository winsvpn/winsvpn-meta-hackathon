package org.winsvpn.app

import android.net.InetAddresses
import android.os.Build
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Parses a WireGuard / AmneziaWG `DNS =` value into numeric addresses plus search domains.
 *
 * wg-quick semantics: entries that parse as IP literals are resolvers, entries
 * that do not are DNS search domains. Feeding a search domain to
 * VpnService.Builder.addDnsServer() throws IllegalArgumentException.
 *
 * Never performs network lookups or getByName() on hostnames.
 */
internal object DnsConfig {

    /** Commas, semicolons, and any run of whitespace all separate entries. */
    private val SEPARATORS = Regex("[,;\\s]+")

    private val IPV4 = Regex(
        "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$"
    )

    data class Parsed(
        val servers: List<InetAddress>,
        val searchDomains: List<String>,
    ) {
        val hasIpv6: Boolean get() = servers.any { it is Inet6Address }
    }

    fun parse(raw: String?, defaultServer: String = "10.8.1.1"): Parsed {
        if (raw.isNullOrBlank()) {
            val fallback = parseNumericOrNull(defaultServer)
            return Parsed(
                servers = if (fallback != null) listOf(fallback) else emptyList(),
                searchDomains = emptyList()
            )
        }

        // LinkedHashMap keyed on canonical host address: dedupes while preserving order.
        val servers = LinkedHashMap<String, InetAddress>()
        val domains = LinkedHashSet<String>()

        for (token in raw.split(SEPARATORS)) {
            val cleaned = token
                .trim()
                .trim('"', '\'')
                .substringBefore('/')          // strip CIDR prefix
                .removeSurrounding("[", "]")   // strip IPv6 URL brackets
                .trim()
            if (cleaned.isEmpty()) continue

            if (cleaned.contains('%')) continue // scoped addresses are never tunnel resolvers
            val ip = parseNumericOrNull(cleaned)
            if (ip != null) {
                if (ip.isLinkLocalAddress || ip.isAnyLocalAddress || ip.isMulticastAddress) continue
                servers.putIfAbsent(ip.hostAddress ?: cleaned, ip)
            } else if (isValidSearchDomain(cleaned)) {
                domains.add(cleaned)
            }
        }

        if (servers.isEmpty() && defaultServer.isNotEmpty()) {
            val fallback = parseNumericOrNull(defaultServer)
            if (fallback != null) {
                servers.putIfAbsent(fallback.hostAddress ?: defaultServer, fallback)
            }
        }

        return Parsed(servers.values.toList(), domains.toList())
    }

    private fun parseNumericOrNull(value: String): InetAddress? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return try {
                if (InetAddresses.isNumericAddress(value)) {
                    InetAddresses.parseNumericAddress(value)
                } else {
                    null
                }
            } catch (_: IllegalArgumentException) {
                null
            }
        }

        // Pre-Q fallback: check IPv4 regex directly before calling getByName
        if (IPV4.matches(value)) {
            return try {
                val parts = value.split('.').map { it.toInt().toByte() }.toByteArray()
                InetAddress.getByAddress(parts)
            } catch (_: Exception) {
                null
            }
        }

        // IPv6 hex literal check without DNS lookup
        if (value.contains(':') && WinnEngineConfig.isIpLiteralEndpoint("[$value]:1")) {
            return try {
                val addr = InetAddress.getByName(value)
                if (addr is Inet6Address) addr else null
            } catch (_: Exception) {
                null
            }
        }

        return null
    }

    private fun isValidSearchDomain(value: String): Boolean {
        if (value.length > 253) return false
        val domainRegex = Regex("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        return domainRegex.matches(value)
    }
}
