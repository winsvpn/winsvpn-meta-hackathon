package org.winsvpn.app

import java.io.File
import java.util.zip.ZipFile
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Document
import org.w3c.dom.Element

/**
 * Byte-level contract for the phone/TV exported-component surface and the VPN
 * binding permission, read from the produced artifacts the manifest merger
 * actually consumes.
 *
 * The app must be the ONLY VpnService binding in the merged release manifest.
 * The bundled AWG AAR ships its own `GoBackend$VpnService`; the main manifest
 * must strip it by the EXACT name the AAR declares, or two services would offer
 * the same `android.net.VpnService` grant and the consent/`Settings > VPN`
 * surface would be widened. A `tools:node="remove"` against a name that does not
 * match the AAR's declared service is a silent no-op, so this test parses the
 * AAR itself rather than trusting the removal text.
 *
 * These are source/byte pins, not evidence that a signed AAB was produced.
 */
class AndroidExportedComponentAndVpnPermissionContractTest {

    @Test
    fun `AWG library duplicate VpnService is removed by the exact AAR declared name`() {
        val declared = aarVpnServiceName()
        assertNotNull("AAR must declare a VpnService binding", declared)
        val mainManifest = read("android/app/src/main/AndroidManifest.xml")
        assertTrue(
            "main manifest must tools:node=remove the AAR-declared VpnService $declared",
            mainManifest.contains("tools:node=\"remove\"") &&
                mainManifest.contains("android:name=\"$declared\""),
        )
    }

    @Test
    fun `the app VpnTunnelService is the only surviving VPN service and is bound but not exported`() {
        val doc = parseXml(read("android/app/src/main/AndroidManifest.xml"))
        val services = doc.getElementsByTagName("service")
        val surviving = mutableListOf<Element>()
        for (i in 0 until services.length) {
            val el = services.item(i) as Element
            if (toolsNodeRemove(el)) continue
            surviving.add(el)
        }
        // Exactly one non-removed service may offer the android.net.VpnService
        // grant. WatchCommandService survives too, but it is the Wear Data Layer
        // MESSAGE_RECEIVED binding, not a VpnService.
        val vpnBindings = surviving.filter { hasVpnServiceAction(it) }
        assertEquals(
            "the AWG duplicate must be stripped so only the app tunnel offers the VpnService grant",
            1,
            vpnBindings.size,
        )
        val tunnel = vpnBindings.single()
        assertEquals(".VpnTunnelService", attr(tunnel, androidNs, "name"))
        assertEquals(
            "VpnTunnelService must not be exported; the system is exempt from exported gating for the BIND_VPN_SERVICE binding",
            "false",
            attr(tunnel, androidNs, "exported"),
        )
        assertEquals(
            "VpnTunnelService must restrict binders to the system via BIND_VPN_SERVICE",
            "android.permission.BIND_VPN_SERVICE",
            attr(tunnel, androidNs, "permission"),
        )
    }

    @Test
    fun `every exported component is on the justified whitelist across phone and TV`() {
        val whitelist = setOf(
            "org.winsvpn.app.LauncherReal", // phone home-screen launcher alias
            "org.winsvpn.app.LauncherDecoy", // phone decoy launcher alias
            // SecretCodeReceiver was removed by the Round 36 treaty (OI-10): the
            // dialer secret code fingerprinted the covert app in the manifest.
            "org.winsvpn.app.WatchCommandService", // Wear Data Layer MESSAGE_RECEIVED, path-filtered
            "org.winsvpn.app.MainActivity", // TV LAUNCHER/LEANBACK_LAUNCHER entry
        )
        val exported = exportedComponentClassNames()
        assertEquals(
            "the exported surface drifted from the justified whitelist",
            whitelist,
            exported,
        )
    }

    @Test
    fun `the phone MainActivity and launcher targets are not exported`() {
        val doc = parseXml(read("android/app/src/main/AndroidManifest.xml"))
        val expectedClosed = mapOf(
            ".MainActivity" to "false",
            ".RealLauncherActivity" to "false",
            ".DecoyLauncherActivity" to "false",
        )
        for ((name, want) in expectedClosed) {
            val el = findElementByName(doc, listOf("activity"), name)
                ?: throw AssertionError("missing activity $name")
            assertEquals("$name exported state", want, attr(el, androidNs, "exported"))
        }
    }

    @Test
    fun `library merged profileinstall receiver is stripped so produced bytes match the whitelist`() {
        // androidx.profileinstaller declares ProfileInstallReceiver exported=true,
        // guarded only by the DUMP signature grant. It is merged in by Gradle, so
        // it never appears in a SOURCE manifest and the exported-component census
        // above could pass while the produced release bytes export a component the
        // app neither declares nor needs. The main manifest must strip it by the
        // exact name the AAR declares, just like the AWG duplicate VpnService.
        val mainManifest = read("android/app/src/main/AndroidManifest.xml")
        assertTrue(
            "main manifest must strip the profileinstaller receiver by its exact AAR name",
            mainManifest.contains("androidx.profileinstaller.ProfileInstallReceiver") &&
                mainManifest.contains("tools:node=\"remove\""),
        )
    }

    private fun hasVpnServiceAction(service: Element): Boolean {
        val filters = service.getElementsByTagName("intent-filter")
        for (i in 0 until filters.length) {
            val filter = filters.item(i) as Element
            val actions = filter.getElementsByTagName("action")
            for (j in 0 until actions.length) {
                val action = actions.item(j) as Element
                if (attr(action, androidNs, "name") == "android.net.VpnService") return true
            }
        }
        return false
    }

    private fun exportedComponentClassNames(): Set<String> {
        val namespace = appNamespace()
        val out = linkedSetOf<String>()
        for (relative in listOf(
            "android/app/src/main/AndroidManifest.xml",
            "android/app/src/tv/AndroidManifest.xml",
        )) {
            out += exportedComponentNames(parseXml(read(relative)), namespace)
        }
        return out
    }

    private fun exportedComponentNames(doc: Document, namespace: String): Set<String> {
        val out = linkedSetOf<String>()
        for (tag in listOf("activity", "activity-alias", "service", "receiver", "provider")) {
            val nodes = doc.getElementsByTagName(tag)
            for (i in 0 until nodes.length) {
                val el = nodes.item(i) as Element
                if (toolsNodeRemove(el)) continue
                if (attr(el, androidNs, "exported") != "true") continue
                val raw = attr(el, androidNs, "name")
                if (raw.isBlank() || raw.startsWith("\${")) continue
                out += resolveClassName(raw, namespace)
            }
        }
        return out
    }

    private fun findElementByName(
        doc: Document,
        tags: List<String>,
        name: String,
    ): Element? {
        for (tag in tags) {
            val nodes = doc.getElementsByTagName(tag)
            for (i in 0 until nodes.length) {
                val el = nodes.item(i) as Element
                if (attr(el, androidNs, "name") == name) return el
            }
        }
        return null
    }

    private fun aarVpnServiceName(): String? {
        val aar = repoPath("android/app/libs/amneziawg.aar")
        if (!aar.isFile) return null
        ZipFile(aar).use { zip ->
            val entry = zip.getEntry("AndroidManifest.xml") ?: return null
            val text = zip.getInputStream(entry).bufferedReader().use { it.readText() }
            val services = parseXml(text).getElementsByTagName("service")
            for (i in 0 until services.length) {
                val el = services.item(i) as Element
                if (hasVpnServiceAction(el)) return attr(el, androidNs, "name")
            }
        }
        return null
    }

    private fun parseXml(text: String): Document {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        return factory.newDocumentBuilder().parse(text.byteInputStream())
    }

    private fun toolsNodeRemove(el: Element): Boolean {
        val namespaced = el.getAttributeNS(toolsNs, "node")
        if (namespaced.isNotBlank()) return namespaced == "remove"
        return el.getAttribute("tools:node").orEmpty().trim() == "remove"
    }

    private fun attr(el: Element, ns: String, local: String): String =
        el.getAttributeNS(ns, local).orEmpty()

    private fun resolveClassName(raw: String, namespace: String): String = when {
        raw.startsWith('.') -> namespace + raw
        raw.contains('.') -> raw
        else -> "$namespace.$raw"
    }

    private fun appNamespace(): String {
        val match = Regex("""namespace\s*=\s*"([^"]+)"""")
            .find(read("android/app/build.gradle.kts"))
            ?: throw AssertionError("missing namespace in android/app/build.gradle.kts")
        return match.groupValues[1]
    }

    private fun read(relative: String): String {
        val file = repoPath(relative)
        assertTrue("missing $relative", file.isFile)
        return file.readText()
    }

    private fun repoPath(relative: String): File {
        val root = repositoryRoot() ?: throw AssertionError("cannot locate repository root")
        return File(root, relative)
    }

    private fun repositoryRoot(): File? {
        var directory: File? = File(System.getProperty("user.dir") ?: return null).absoluteFile
        while (directory != null) {
            if (File(directory, "winn_protocol_experimental/go.mod").isFile) return directory
            directory = directory.parentFile
        }
        return null
    }

    private companion object {
        val androidNs = "http://schemas.android.com/apk/res/android"
        val toolsNs = "http://schemas.android.com/tools"
    }
}