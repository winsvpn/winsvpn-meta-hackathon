package org.winsvpn.app

internal data class VpnIpv4Route(
    val address: String,
    val prefixLength: Int,
)

/** Parses only the IPv4 routes in Peer.AllowedIPs for VpnService.Builder. */
internal object VpnRouteParser {
    fun allowedIpv4Routes(config: String): List<VpnIpv4Route> {
        // Same reading as AwgUserspaceConfig: '#' starts a comment anywhere on
        // a line, and every AllowedIPs line of every [Peer] counts. A route
        // set narrower than what AmneziaWG accepts sends the remainder
        // outside the tunnel.
        var inPeer = false
        val entries = ArrayList<String>()
        for (rawLine in config.lineSequence()) {
            val line = rawLine.substringBefore('#').trim()
            if (line.isEmpty() || line.startsWith(";")) continue
            if (line.startsWith("[") && line.endsWith("]")) {
                inPeer = line.substring(1, line.length - 1).trim().equals("Peer", ignoreCase = true)
                continue
            }
            if (!inPeer) continue
            val equals = line.indexOf('=')
            if (equals <= 0) continue
            if (line.substring(0, equals).trim().equals("AllowedIPs", ignoreCase = true)) {
                entries += line.substring(equals + 1).split(',')
            }
        }
        val allowedIps = entries.joinToString(",")
        val routes = LinkedHashSet<VpnIpv4Route>()
        for (rawRoute in allowedIps.split(',')) {
            val route = rawRoute.trim()
            if (route.isEmpty() || route.contains(':')) continue
            val parts = route.split('/', limit = 2)
            if (parts.size != 2) continue
            val octets = parts[0].split('.').map { it.toIntOrNull() }
            val prefix = parts[1].toIntOrNull()
            if (octets.size != 4 || octets.any { it == null || it !in 0..255 } ||
                prefix == null || prefix !in 0..32
            ) {
                continue
            }
            routes += VpnIpv4Route(octets.joinToString(".") { it.toString() }, prefix)
        }
        return routes.toList()
    }
}
