package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AwgOfficialEnginePinTest {

    @Test
    fun buildScriptPinsOfficialV31AndReviewedGo() {
        val script = readRepoFile("tools/build_amneziawg_android_engine.sh")
        assertTrue(script.contains("AWG_ANDROID_REPO=\"https://github.com/amnezia-vpn/amneziawg-android.git\""))
        assertTrue(script.contains("AWG_ANDROID_TAG=\"v3.1.20260814\""))
        assertTrue(script.contains("AWG_ANDROID_COMMIT=\"5c16489e2cd9ed3a0a7a27c7445bba5238132f86\""))
        assertTrue(script.contains("REVIEWED_GO_VERSION=\"1.27.1\""))
        assertTrue(script.contains("AWG_GO_MODULE=\"github.com/amnezia-vpn/amneziawg-go/v3\""))
        assertTrue(script.contains("awgUpdateTunnelPeers"))
        assertFalse(script.contains("zaneschepke/amneziawg-android.git"))
        assertFalse(script.contains("ffb71fb3bcd15ac011ad7cfbe05f76d150fc37f9"))
        assertFalse(script.contains("AWG_ANDROID_TAG=\"v2.3.7\""))
    }

    @Test
    fun jniOverlayIsOfficialV3PlusLivePeerPort() {
        val api = readRepoFile("tools/amneziawg_android_official_jni/api-android.go")
        val jni = readRepoFile("tools/amneziawg_android_official_jni/jni.c")
        val adapt = readRepoFile("tools/amneziawg_android_official_jni/uapi_adapt.go")
        assertTrue(api.contains("github.com/amnezia-vpn/amneziawg-go/v3"))
        assertTrue(api.contains("func awgUpdateTunnelPeers"))
        assertTrue(api.contains("func awgTurnOn(interfaceName string, tunFd int32, settings string, uapiPath string) int32"))
        assertTrue(jni.contains("Java_org_amnezia_awg_GoBackend_awgUpdateTunnelPeers"))
        assertTrue(adapt.contains("adaptPeerUpdate"))
        for (banned in listOf("zaneschepke", "wgtunnel", "wireproxyawg")) {
            assertFalse("$banned must not appear in the official JNI port", api.contains(banned))
            assertFalse("$banned must not appear in the official JNI port", adapt.contains(banned))
        }
    }

    @Test
    fun tunnelServiceConvertsIniAndKeepsLivePeerJni() {
        val service = readRepoFile("android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt")
        assertTrue(service.contains("AwgUserspaceConfig.fromQuick(awgConfig)"))
        assertTrue(service.contains("AwgNativeApi.awgTurnOn(\"winsvpn\", tunFd, userspace, dataDir.absolutePath)"))
        assertTrue(service.contains("AwgNativeApi.awgUpdateTunnelPeers(handle, settings)"))
        assertFalse(service.contains("awgTurnOn(\"winsvpn\", tunFd, awgConfig, dataDir.absolutePath)"))
    }

    @Test
    fun committedAarEmbedsOfficialV3AndGo127() {
        val root = repositoryRoot() ?: throw AssertionError("cannot locate repository root")
        val aar = File(root, "android/app/libs/amneziawg.aar")
        assertTrue("missing committed AAR", aar.isFile)
        java.util.zip.ZipFile(aar).use { zip ->
            val member = zip.getEntry("jni/arm64-v8a/libam-go.so")
            assertTrue("AAR missing arm64 libam-go.so", member != null)
            val bytes = zip.getInputStream(member).use { it.readBytes() }
            val text = bytes.toString(Charsets.ISO_8859_1)
            assertTrue("committed libam-go.so must name official amneziawg-go/v3", text.contains("github.com/amnezia-vpn/amneziawg-go/v3"))
            assertTrue("committed libam-go.so must embed go1.27.1", text.contains("go1.27.1"))
            assertFalse("committed libam-go.so must not embed the archived wgtunnel replace", text.contains("github.com/wgtunnel/amneziawg-go"))
        }
    }

    @Test
    fun provenanceDoesNotCallTheArchivedForkCurrent() {
        val provenance = readRepoFile("docs/AMNEZIAWG_ENGINE_PROVENANCE.md")
        assertTrue(provenance.contains("v3.1.20260814"))
        assertTrue(provenance.contains("5c16489e2cd9ed3a0a7a27c7445bba5238132f86"))
        assertTrue(provenance.contains("30.0.16248370"))
        assertFalse(provenance.contains("FAIL-RED"))
        assertFalse(provenance.contains("The shipping Android engine is **`github.com/wgtunnel/amneziawg-go`"))
    }

    private fun readRepoFile(relative: String): String {
        val root = repositoryRoot() ?: throw AssertionError("cannot locate repository root")
        val file = File(root, relative)
        assertTrue("missing $relative", file.isFile)
        return file.readText()
    }

    private fun repositoryRoot(): File? {
        var directory: File? = File(System.getProperty("user.dir") ?: return null).absoluteFile
        while (directory != null) {
            if (File(directory, "winn_protocol_experimental/go.mod").isFile) return directory
            directory = directory.parentFile
        }
        return null
    }
}
