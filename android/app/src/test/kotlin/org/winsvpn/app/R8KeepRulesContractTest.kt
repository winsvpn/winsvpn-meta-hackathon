package org.winsvpn.app

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.w3c.dom.Element

/**
 * Static contract for `android/app/proguard-rules.pro`.
 *
 * These tests pin keep rules to real entrypoints (manifest components, JNI
 * native names, Flutter plugin construction) and forbid `{ *; }` keep-all
 * member wildcards on internal classes, including the VpnTunnelService
 * implementation surface. They do not inspect mapping.txt and a green run
 * is not evidence that minifyReleaseWithR8 succeeded.
 */
class R8KeepRulesContractTest {

    @Test
    fun `the keep file forbids keep-all member wildcards`() {
        val keepAll = keepRules().filter { it.keepsAllMembers }
        assertTrue(
            "proguard-rules.pro must not use `{ *; }` keep-all member rules; found: $keepAll",
            keepAll.isEmpty(),
        )
    }

    @Test
    fun `internal app classes are not kept`() {
        val namespace = appNamespace()
        val entrypoints = manifestComponentClasses()
        val internal = declaredAppClasses() - entrypoints
        assertTrue("expected internal implementation classes", internal.isNotEmpty())
        assertTrue(
            "WinnAndroidEngineHost is implementation, not a manifest/JNI/plugin entrypoint",
            "$namespace.WinnAndroidEngineHost" in internal,
        )
        assertTrue(
            "VpnTunnelService remains a manifest entrypoint",
            "$namespace.VpnTunnelService" in entrypoints,
        )
        for (internalClass in internal) {
            val matching = keepRules().filter {
                it.kind.startsWith("keep") &&
                    it.classSpec != "*" &&
                    it.matchesClass(internalClass)
            }
            assertTrue(
                "$internalClass is not an entrypoint and must not have a keep rule: $matching",
                matching.isEmpty(),
            )
        }
    }

    @Test
    fun `every release manifest component is kept by class name and constructor only`() {
        val components = manifestComponentClasses()
        val expected = setOf(
            "org.winsvpn.app.MainActivity",
            "org.winsvpn.app.RealLauncherActivity",
            "org.winsvpn.app.DecoyLauncherActivity",
            "org.winsvpn.app.VpnTunnelService",
            "org.winsvpn.app.WatchCommandService",
        )
        assertEquals("release manifest components drifted", expected, components)

        for (component in components) {
            val keep = keepRules().singleOrNull {
                it.kind.startsWith("keep") && it.classSpec == component
            }
            if (keep == null) {
                fail("missing keep rule for manifest component $component")
                return
            }
            assertFalse("$component must not be kept with `{ *; }`", keep.keepsAllMembers)
            assertTrue(
                "$component must keep a constructor for system instantiation: ${keep.members}",
                keep.members.any { it.contains("<init>") },
            )
            val extra = keep.members.filter { member ->
                val token = member.trim().trimEnd(';').replace(" ", "")
                token.isNotEmpty() && token != "<init>()" && token != "public<init>()" && token != "<init>"
            }
            assertTrue(
                "$component keep must not retain arbitrary members: ${keep.members}",
                extra.isEmpty(),
            )
        }
    }

    @Test
    fun `removed AWG VpnService is not a kept entrypoint`() {
        val rules = keepRules()
        assertTrue(
            rules.none {
                it.classSpec.contains("GoBackend\$VpnService") ||
                    it.classSpec.contains("GoBackend.VpnService")
            },
        )
        assertTrue(
            "the unused AAR Java backend must not be kept wholesale",
            rules.none {
                it.kind.startsWith("keep") &&
                    (it.classSpec == "org.amnezia.awg.**" ||
                        it.classSpec == "org.amnezia.awg.*" ||
                        it.classSpec.startsWith("org.amnezia.awg.backend"))
            },
        )
        assertTrue(
            "TProxyService stay-silent rule is required; the AAR still references HEV",
            rules.any {
                it.kind == "dontwarn" && it.classSpec == "org.amnezia.awg.hevtunnel.TProxyService"
            },
        )
    }

    @Test
    fun `AWG JNI native methods are kept by signature, not by package wildcard`() {
        val goBackend = keepRules().single {
            it.kind.startsWith("keep") && it.classSpec == "org.amnezia.awg.GoBackend"
        }
        assertFalse(goBackend.keepsAllMembers)
        assertTrue(
            "GoBackend keep must retain native methods: ${goBackend.members}",
            goBackend.members.any { it.contains("native") },
        )
        val jniNames = JNI_NATIVE_RE.findAll(repoFile("tools/amneziawg_android_official_jni/jni.c"))
            .map { it.groupValues[1] }
            .toSet()
        val javaNatives = JAVA_NATIVE_RE.findAll(
            repoFile("tools/amneziawg_android_official_jni/GoBackend.java"),
        ).map { it.groupValues[1] }.toSet()
        assertEquals(EXPECTED_AWG_NATIVES, jniNames)
        assertEquals(EXPECTED_AWG_NATIVES, javaNatives)
        val coversAllNatives = goBackend.members.any { it.contains("native <methods>") } ||
            EXPECTED_AWG_NATIVES.all { name -> goBackend.members.any { it.contains(name) } }
        assertTrue(
            "GoBackend keep must cover $EXPECTED_AWG_NATIVES; members=${goBackend.members}",
            coversAllNatives,
        )
        val globalNative = keepRules().single {
            it.raw.contains("keepclasseswithmembernames") && it.raw.contains("native <methods>")
        }
        assertTrue(globalNative.raw.contains("includedescriptorclasses"))
    }

    @Test
    fun `Flutter plugin registrant and constructed plugins are kept`() {
        val registrantSource = repoFile(
            "android/app/src/main/java/io/flutter/plugins/GeneratedPluginRegistrant.java",
        )
        assertTrue(registrantSource.contains("@Keep"))
        val plugins = PLUGIN_CTOR_RE.findAll(registrantSource).map { it.groupValues[1] }.toSet()
        assertEquals(
            setOf(
                "com.github.dart_lang.jni.JniPlugin",
                "com.github.dart_lang.jni_flutter.JniFlutterPlugin",
            ),
            plugins,
        )

        val registrantKeep = keepRules().single {
            it.classSpec == "io.flutter.plugins.GeneratedPluginRegistrant"
        }
        assertFalse(registrantKeep.keepsAllMembers)
        assertTrue(
            registrantKeep.members.any { it.contains("registerWith") && it.contains("FlutterEngine") },
        )

        for (plugin in plugins) {
            val keep = keepRules().single { it.classSpec == plugin }
            assertFalse("$plugin must not use `{ *; }`", keep.keepsAllMembers)
            assertTrue(
                "$plugin must keep a constructor: ${keep.members}",
                keep.members.any { it.contains("<init>") },
            )
        }
        val jniFlutterKeep = keepRules().single {
            it.classSpec == "com.github.dart_lang.jni_flutter.JniFlutterPlugin"
        }
        assertTrue(jniFlutterKeep.members.any { it.contains("getApplicationContext") })
        assertTrue(jniFlutterKeep.members.any { it.contains("getActivity") })
        val jniKeep = keepRules().single { it.classSpec == "com.github.dart_lang.jni.JniPlugin" }
        assertTrue(jniKeep.members.any { it.contains("native") })
    }

    @Test
    fun `release Gradle configuration enables minify and this keep file`() {
        val gradle = repoFile("android/app/build.gradle.kts")
        val releaseBody = buildTypeBody(gradle, "release")
        assertTrue(
            "release must enable R8 minify:\n$releaseBody",
            releaseBody.contains("isMinifyEnabled = true"),
        )
        assertTrue(
            "release must shrink resources:\n$releaseBody",
            releaseBody.contains("isShrinkResources = true"),
        )
        assertTrue(
            "release must apply android/app/proguard-rules.pro:\n$releaseBody",
            releaseBody.contains("\"proguard-rules.pro\""),
        )
        val debugBody = buildTypeBody(gradle, "debug")
        assertFalse(
            "debug must not enable minify:\n$debugBody",
            debugBody.contains("isMinifyEnabled = true"),
        )
    }

    @Test
    fun `this contract does not treat R8 output as evidence`() {
        val source = repoFile(
            "android/app/src/test/kotlin/org/winsvpn/app/R8KeepRulesContractTest.kt",
        )
        assertTrue(source.contains("do not inspect mapping.txt"))
        assertTrue(source.contains("is not evidence that minifyReleaseWithR8 succeeded"))
        val keepFile = repoFile("android/app/proguard-rules.pro")
        assertTrue(keepFile.contains("do not prove a successful R8 run"))
    }

    private fun manifestComponentClasses(): Set<String> {
        val namespace = appNamespace()
        val names = linkedSetOf<String>()
        for (relative in listOf(
            "android/app/src/main/AndroidManifest.xml",
            "android/app/src/tv/AndroidManifest.xml",
            "android/app/src/release/AndroidManifest.xml",
        )) {
            names += componentClassNames(repoPath(relative), namespace)
        }
        return names
    }

    private fun declaredAppClasses(): Set<String> {
        val namespace = appNamespace()
        val dir = repoPath("android/app/src/main/kotlin/org/winsvpn/app")
        val names = linkedSetOf<String>()
        val classRe = Regex(
            """^(?:(?:public|internal|abstract|data|sealed|open)\s+)*class\s+(\w+)""",
        )
        for (file in dir.listFiles().orEmpty().filter { it.extension == "kt" }) {
            for (line in file.readLines()) {
                val match = classRe.find(line.trim()) ?: continue
                names += "$namespace.${match.groupValues[1]}"
            }
        }
        return names
    }

    private fun appNamespace(): String {
        val match = Regex("""namespace\s*=\s*"([^"]+)"""")
            .find(repoFile("android/app/build.gradle.kts"))
            ?: throw AssertionError("missing namespace in android/app/build.gradle.kts")
        return match.groupValues[1]
    }

    private fun componentClassNames(manifest: File, namespace: String): Set<String> {
        if (!manifest.isFile) return emptySet()
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        val document = factory.newDocumentBuilder().parse(manifest)
        val androidNs = "http://schemas.android.com/apk/res/android"
        val toolsNs = "http://schemas.android.com/tools"
        val names = linkedSetOf<String>()
        for (tag in listOf("activity", "service", "receiver", "provider")) {
            val nodes = document.getElementsByTagName(tag)
            for (index in 0 until nodes.length) {
                val element = nodes.item(index) as Element
                if (attribute(element, toolsNs, "node", "tools:node") == "remove") continue
                val raw = attribute(element, androidNs, "name", "android:name")
                if (raw.isBlank() || raw.startsWith("\${")) continue
                names += resolveClassName(raw, namespace)
            }
        }
        return names
    }

    private fun attribute(
        element: Element,
        namespaceUri: String,
        localName: String,
        qualifiedName: String,
    ): String {
        val namespaced = element.getAttributeNS(namespaceUri, localName)
        if (!namespaced.isNullOrBlank()) return namespaced
        val qualified = element.getAttribute(qualifiedName)
        if (!qualified.isNullOrBlank()) return qualified
        return element.getAttribute(localName).orEmpty()
    }

    private fun resolveClassName(raw: String, namespace: String): String = when {
        raw.startsWith('.') -> namespace + raw
        raw.contains('.') -> raw
        else -> "$namespace.$raw"
    }

    private fun keepRules(): List<KeepRule> =
        parseKeepRules(repoFile("android/app/proguard-rules.pro"))

    private fun buildTypeBody(gradle: String, name: String): String {
        val header = Regex("""getByName\("$name"\)\s*\{""")
        val match = header.find(gradle) ?: throw AssertionError("missing getByName(\"$name\")")
        val open = gradle.indexOf('{', match.range.last)
        var depth = 0
        var index = open
        while (index < gradle.length) {
            when (gradle[index]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return gradle.substring(open, index + 1)
                }
            }
            index++
        }
        throw AssertionError("unterminated build type $name")
    }

    private fun repoFile(relative: String): String {
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

    private data class KeepRule(
        val kind: String,
        val classSpec: String,
        val members: List<String>,
        val raw: String,
    ) {
        val keepsAllMembers: Boolean
            get() = members.any { it.replace(" ", "").trimEnd(';') == "*" }

        fun matchesClass(fqcn: String): Boolean {
            if (classSpec == fqcn) return true
            if (classSpec == "*") return true
            if (classSpec.endsWith(".**")) {
                val prefix = classSpec.removeSuffix(".**")
                return fqcn == prefix || fqcn.startsWith("$prefix.")
            }
            if (classSpec.endsWith(".*")) {
                val prefix = classSpec.removeSuffix(".*")
                return fqcn.startsWith("$prefix.") && fqcn.indexOf('.', prefix.length + 1) < 0
            }
            return false
        }
    }

    private fun parseKeepRules(text: String): List<KeepRule> {
        val stripped = text.replace(Regex("""#.*"""), "")
        val directive = Regex("""-(keep\w*|dontwarn)\b([^\{;\n]*)(\{([^}]*)\})?""")
        return directive.findAll(stripped).map { match ->
            val kind = match.groupValues[1]
            val specChunk = match.groupValues[2]
            val classSpec = CLASS_SPEC_RE.find(specChunk)?.groupValues?.get(1)?.trim()
                ?: specChunk.trim()
            val members = match.groupValues[4]
                .split('\n', ';')
                .map { it.trim().trimEnd(';') }
                .filter { it.isNotEmpty() }
            KeepRule(kind, classSpec, members, match.value.trim())
        }.toList()
    }

    private companion object {
        val JNI_NATIVE_RE = Regex("""Java_org_amnezia_awg_GoBackend_(\w+)""")
        val JAVA_NATIVE_RE = Regex("""native\s+[\w.<>,\s\[\]]+\s+(\w+)\s*\(""")
        val PLUGIN_CTOR_RE = Regex("""new\s+([A-Za-z0-9_.]+)\s*\(""")
        val CLASS_SPEC_RE = Regex("""class\s+(\S+)""")
        val EXPECTED_AWG_NATIVES = setOf(
            "awgTurnOn",
            "awgTurnOff",
            "awgGetSocketV4",
            "awgGetSocketV6",
            "awgGetConfig",
            "awgVersion",
            "awgUpdateTunnelPeers",
        )
    }
}
