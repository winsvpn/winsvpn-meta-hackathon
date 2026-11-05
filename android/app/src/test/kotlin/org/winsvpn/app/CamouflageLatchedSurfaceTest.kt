package org.winsvpn.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Some camouflage surfaces are *latched*: the OS captures their value once and
 * then keeps it, with no API to re-read or rename them afterwards. Three exist
 * in this app and all three are read by an inspector long after the moment that
 * decided them:
 *
 *  - the VPN session name, fixed at `VpnService.Builder.establish()`;
 *  - the announcement notification channel, created on the first announcement
 *    and then listed in Settings > Apps > Calculator > Notifications for the
 *    life of the install, whether or not a notification is showing;
 *  - the tunnel foreground-service notification channel, created the first time
 *    a tunnel starts and listed on that same Settings screen thereafter -- with
 *    no tunnel running, no notification showing, and after the decoy has been
 *    disarmed.
 *
 * The trap all three share is that the obvious signal -- "is the decoy armed
 * right now?" -- is evaluated at the one instant the decoy is guaranteed to be
 * DOWN. The ordinary flow is unlock-with-PIN (decoy disarmed) -> act ->
 * background (decoy re-arms), so a momentary-state check latches the real
 * identity and then holds it for exactly the window in which the device gets
 * inspected. For the tunnel channel that instant is the press of Connect.
 *
 * `latchedSurfaceIsDisguised` is the shared answer: sticky enrollment OR live
 * decoy state, never the live state alone.
 *
 * Surfaces that are NOT latched deliberately do not use this. The tunnel
 * notification's own title, text and icons are rebuilt by
 * `refreshForegroundNotificationForCamouflage` on every icon swap and vanish
 * with the tunnel, so they can safely track the live decoy state and stay
 * truthful for users who have turned camouflage off. The channel they are
 * posted on cannot: it outlives all of that.
 *
 * The watch module (`wear_os/`) joined the census below because it carries
 * the same class of exposure through a different mechanism. Its naming
 * surface -- `app_name`, which the watch's manifest, its own Settings > Apps
 * entry and two on-screen strings all resolve through -- is baked into the
 * compiled resource table at build time, and the watch has no camouflage
 * signal of its own to read even if that were not so: the wire snapshot it
 * renders from the phone carries no enrollment or decoy field, and building
 * one would fail OPEN, silently, whenever the watch is out of Bluetooth
 * range of the phone. So unlike the five surfaces above, the watch's naming
 * surface does not toggle between two states -- it is always the disguise,
 * unconditionally, and the census below simply requires that no file in
 * either module's main sources ever disagrees with that.
 */
class CamouflageLatchedSurfaceTest {

    @Test
    fun `an install that never enrolled camouflage is not disguised`() {
        assertFalse(
            VpnTunnelService.latchedSurfaceIsDisguised(
                camouflageEnrolled = false,
                decoyActive = false,
            ),
        )
    }

    @Test
    fun `an enrolled install stays disguised while the decoy is momentarily down`() {
        // The case the whole predicate exists for: the user has unlocked with
        // their PIN, so the decoy is disarmed at this instant, but whatever is
        // latched now is what gets read after it re-arms.
        assertTrue(
            VpnTunnelService.latchedSurfaceIsDisguised(
                camouflageEnrolled = true,
                decoyActive = false,
            ),
        )
    }

    @Test
    fun `an armed decoy disguises even if the enrollment flag never landed`() {
        // Defence in depth: if the SharedPreferences write failed, the live
        // launcher-alias state still forces the disguise.
        assertTrue(
            VpnTunnelService.latchedSurfaceIsDisguised(
                camouflageEnrolled = false,
                decoyActive = true,
            ),
        )
    }

    @Test
    fun `the session name agrees with the predicate in every camouflage state`() {
        // vpnSessionNameFor delegates here, and the two must not drift: if the
        // predicate says "disguised" the session name must not carry the real
        // identity, and vice versa.
        for (enrolled in listOf(true, false)) {
            for (armed in listOf(true, false)) {
                val disguised = VpnTunnelService.latchedSurfaceIsDisguised(enrolled, armed)
                val name = VpnTunnelService.vpnSessionNameFor(enrolled, armed)
                if (disguised) {
                    org.junit.Assert.assertEquals(
                        "predicate says disguised but the session name does not",
                        VpnTunnelService.DISGUISED_DISPLAY_NAME,
                        name,
                    )
                } else {
                    org.junit.Assert.assertEquals(
                        "predicate says undisguised but the session name is the decoy",
                        "WinsVPN",
                        name,
                    )
                }
            }
        }
    }

    @Test
    fun `the announcement channel name agrees with the predicate in every camouflage state`() {
        // The second latched surface, and the one that is WORSE than the
        // session name: the session name lasts as long as the tunnel, whereas
        // the channel row in Settings > Apps > Calculator > Notifications
        // outlives the decoy being disarmed and lasts for the life of the
        // install.
        for (enrolled in listOf(true, false)) {
            for (armed in listOf(true, false)) {
                val disguised = VpnTunnelService.latchedSurfaceIsDisguised(enrolled, armed)
                val name = VpnTunnelService.announcementChannelNameFor(enrolled, armed)
                val description =
                    VpnTunnelService.announcementChannelDescriptionFor(enrolled, armed)
                if (disguised) {
                    org.junit.Assert.assertEquals(
                        "predicate says disguised but the channel name does not",
                        VpnTunnelService.DISGUISED_DISPLAY_NAME,
                        name,
                    )
                    // Settings renders the description directly under the
                    // name, so it leaks just as readily.
                    assertFalse(
                        "the channel description names the real app while disguised",
                        description.contains("Win's VPN"),
                    )
                } else {
                    org.junit.Assert.assertEquals(
                        "predicate says undisguised but the channel name is the decoy",
                        "Win's VPN Announcements",
                        name,
                    )
                }
            }
        }
    }

    @Test
    fun `the tunnel channel name agrees with the predicate in every camouflage state`() {
        // The third latched surface, and the one that was still open after the
        // announcement channel was closed: it was named from the live decoy
        // state alone, so an enrolled user pressing Connect -- necessarily with
        // the decoy momentarily down, because they have just unlocked with
        // their PIN to press it -- carved the real name into Settings > Apps >
        // Calculator > Notifications permanently.
        for (enrolled in listOf(true, false)) {
            for (armed in listOf(true, false)) {
                val disguised = VpnTunnelService.latchedSurfaceIsDisguised(enrolled, armed)
                val name = VpnTunnelService.tunnelChannelNameFor(enrolled, armed)
                if (disguised) {
                    org.junit.Assert.assertEquals(
                        "predicate says disguised but the tunnel channel name does not",
                        VpnTunnelService.DISGUISED_DISPLAY_NAME,
                        name,
                    )
                } else {
                    org.junit.Assert.assertEquals(
                        "predicate says undisguised but the tunnel channel name is the decoy",
                        "Win's VPN Core Services",
                        name,
                    )
                }
            }
        }
        // The case the whole change exists for, stated on its own so it cannot
        // be lost in the loop: enrolled, decoy down, which is the state at the
        // press of Connect.
        org.junit.Assert.assertEquals(
            "an enrolled install must not latch the real name while the decoy is down",
            VpnTunnelService.DISGUISED_DISPLAY_NAME,
            VpnTunnelService.tunnelChannelNameFor(
                camouflageEnrolled = true,
                decoyActive = false,
            ),
        )
    }

    @Test
    fun `the real channel names are each reachable from exactly one main source line`() {
        // THE POINT OF THIS TEST. The camouflage guarantee is "that string
        // cannot appear in Settings while the decoy is armed". A truth table
        // over a name function only proves that for callers who go through the
        // name function. This asserts there is no other caller: each literal
        // occurs in the application's main sources exactly once, inside the
        // policy function whose disguised branch cannot return it. Anyone who
        // hardcodes one again -- which is exactly how both leaks got in, one at
        // a time -- fails here.
        //
        // The tunnel channel's literal joined this guard rather than getting a
        // parallel test of its own, because "which real-identity strings may
        // exist in main sources, and where" is a single invariant and splitting
        // it is how the second one survived the first fix.
        //
        // The sweep is over the WHOLE main source set -- every .kt and every
        // .xml under src/main, discovered rather than listed -- not a
        // hand-written file list. A list is a fourth place to forget: a new
        // Activity, or a channel name moved into strings.xml, would simply not
        // be looked at. It now spans the watch module too (mainSourceFiles),
        // keyed by censusKey rather than bare file name so a same-named file
        // on that side cannot hide behind this one's expected count.
        val owners = mapOf(
            "Win's VPN Announcements" to "VpnTunnelService.announcementChannelNameFor",
            "Win's VPN Core Services" to "VpnTunnelService.tunnelChannelNameFor",
        )
        for ((literal, owner) in owners) {
            val offenders = mutableMapOf<String, Int>()
            for (file in mainSourceFiles()) {
                val occurrences = censusText(file).split(literal).size - 1
                if (occurrences > 0) offenders[censusKey(file)] = occurrences
            }
            org.junit.Assert.assertEquals(
                "this real channel name must live in exactly one place, $owner; found $offenders",
                mapOf("android/VpnTunnelService.kt" to 1),
                offenders,
            )
        }
    }

    @Test
    fun `the announcement channel is reconciled and not merely created`() {
        // The name is latched at CREATION, so choosing it correctly when the
        // channel is created is necessary but not sufficient: an install that
        // was announced to before the user ever enrolled already has the real
        // name in Settings, and enrolling afterwards must rewrite it rather
        // than wait for an announcement that may never arrive.
        val source = mainSource("MainActivity.kt")
        assertTrue(
            "no refresh hook: an already-latched channel would keep the real name forever",
            source.contains("private fun refreshAnnouncementChannelForCamouflage()"),
        )
        // Once at every Activity start, once on the camouflage swap, plus the
        // declaration itself.
        assertTrue(
            "the refresh hook must be called from both the swap handler and onCreate",
            source.split("refreshAnnouncementChannelForCamouflage").size - 1 >= 3,
        )
        // The fail-closed leg: if the rename does not take, the row is removed
        // rather than left showing the real identity.
        assertTrue(
            "no delete fallback: a rename the platform refused would leak",
            source.contains("deleteNotificationChannel(ANNOUNCEMENT_CHANNEL_ID)"),
        )
    }

    @Test
    fun `the tunnel channel is reconciled even when no tunnel is running`() {
        // The half of the fix that is easy to leave out, and without which it
        // only helps fresh installs. `refreshForegroundNotificationForCamouflage`
        // does rebuild the tunnel channel, but only through `activeInstance`,
        // which is non-null only while a tunnel is actually running. The
        // install that needs help is the opposite one: it connected once before
        // enrolling, latched the real name, disconnected, and only then decided
        // it needed to hide. So the reconciler must take a Context, not a
        // service instance.
        val service = mainSource("VpnTunnelService.kt")
        assertTrue(
            "no Context-based reconciler: an already-latched channel would keep the " +
                "real name until the user happened to connect again",
            service.contains("fun refreshTunnelChannelForCamouflage(context: Context)"),
        )
        assertTrue(
            "the reconciler must not create a channel the app has not needed",
            service.contains("createIfAbsent = false,"),
        )
        // The fail-closed leg: if the rename does not take, the row is removed
        // rather than left showing the real identity.
        assertTrue(
            "no delete fallback: a rename the platform refused would leak",
            service.contains("deleteNotificationChannel(TUNNEL_CHANNEL_ID)"),
        )
        // ...and nothing is posted, which for a foreground service means the
        // tunnel does not run.
        assertTrue(
            "startAsForegroundService must be able to refuse",
            service.contains("if (!createNotificationChannel()) return false"),
        )
        assertTrue(
            "a refusal must tear the tunnel down rather than be ignored",
            service.contains("if (!startAsForegroundService()) executeTunnelTeardown()"),
        )
        // The service's own entry point must hand the policy BOTH signals.
        // Scoped to that function's own body rather than to the whole file,
        // because `camouflageEnrolled = isCamouflageEnrolled(this)` also
        // appears in vpnSessionName and would satisfy a file-wide check from
        // there while the channel kept reading the live decoy state alone --
        // which is precisely the defect this closes.
        val createChannel = functionBody(service, "private fun createNotificationChannel()")
        assertTrue(
            "the tunnel channel must be settled against the sticky enrollment fact, " +
                "not the momentary decoy state alone; body was:\n$createChannel",
            createChannel.contains("camouflageEnrolled = isCamouflageEnrolled(this)"),
        )
        assertTrue(
            "the live decoy state must remain the second input, so an armed decoy " +
                "still disguises when the enrollment write failed; body was:\n$createChannel",
            createChannel.contains("decoyActive = isDecoyLauncherActive()"),
        )

        val activity = mainSource("MainActivity.kt")
        // Once at every Activity start, once on the camouflage swap.
        org.junit.Assert.assertEquals(
            "the reconciler must be called from both onCreate and the swap handler",
            2,
            activity.split("VpnTunnelService.refreshTunnelChannelForCamouflage(this)").size - 1,
        )
    }

    @Test
    fun `only a never-enrolled install with the decoy down is left undisguised`() {
        // Stated as a whole-truth-table assertion so a future change that
        // narrows the disguise has to edit this test on purpose rather than
        // slip through: erring toward the disguise is the fail-safe direction,
        // and the cost of a false positive is only mild confusion for a user
        // who abandoned camouflage.
        var undisguised = 0
        for (enrolled in listOf(true, false)) {
            for (armed in listOf(true, false)) {
                if (!VpnTunnelService.latchedSurfaceIsDisguised(enrolled, armed)) undisguised++
            }
        }
        org.junit.Assert.assertEquals(1, undisguised)
    }

    @Test
    fun `the Recents task label agrees with the predicate in every camouflage state`() {
        // The fourth surface, and the one the tunnel-channel lane flagged as a
        // near miss rather than widening into. It is not latched in the
        // Settings sense -- the card dies with the task -- but it fails the
        // same way: the task description is applied by a RUNNING Activity and
        // the Recents ENTRY outlives that Activity and the whole process. So
        // "unlock with the PIN -> onCreate applies the real label -> process is
        // killed before the decoy re-arms" leaves a card naming the product
        // with nothing running that could correct it.
        for (enrolled in listOf(true, false)) {
            for (armed in listOf(true, false)) {
                val disguised = VpnTunnelService.latchedSurfaceIsDisguised(enrolled, armed)
                val label = VpnTunnelService.taskDescriptionLabelFor(enrolled, armed)
                if (disguised) {
                    org.junit.Assert.assertEquals(
                        "predicate says disguised but the Recents label does not",
                        VpnTunnelService.DISGUISED_DISPLAY_NAME,
                        label,
                    )
                } else {
                    org.junit.Assert.assertEquals(
                        "predicate says undisguised but the Recents label is the decoy",
                        "Win's VPN",
                        label,
                    )
                }
            }
        }
        // Stated on its own so it cannot be lost in the loop: enrolled, decoy
        // momentarily down, which is the state at every onCreate that follows
        // a PIN unlock -- and the state whose card can outlive its process.
        org.junit.Assert.assertEquals(
            "an enrolled install must not draw the real name on a card that outlives it",
            VpnTunnelService.DISGUISED_DISPLAY_NAME,
            VpnTunnelService.taskDescriptionLabelFor(
                camouflageEnrolled = true,
                decoyActive = false,
            ),
        )
    }

    @Test
    fun `the Recents card takes both its label and its icon from the predicate`() {
        // A card reading the decoy name over the product icon is a worse tell
        // than either alone, so the two must not be allowed to drift apart.
        val activity = mainSource("MainActivity.kt")
        val apply = functionBody(activity, "private fun applyTaskIdentity(")
        assertTrue(
            "the Recents label must come from the policy, not from a local " +
                "conditional on the momentary signal; body was:\n$apply",
            apply.contains("VpnTunnelService.taskDescriptionLabelFor("),
        )
        assertTrue(
            "the Recents card must be decided against the sticky enrollment " +
                "fact, not the live decoy state alone; body was:\n$apply",
            apply.contains("VpnTunnelService.isCamouflageEnrolled(this)"),
        )
        assertTrue(
            "the icon must follow the same predicate as the label; body was:\n$apply",
            apply.contains("if (disguised) R.mipmap.ic_calculator else R.mipmap.ic_launcher"),
        )
        // Both call sites -- every Activity start, and the swap handler --
        // must hand it the live decoy state under that name, so the old
        // `showRealVpn` inversion cannot creep back in at one of them.
        org.junit.Assert.assertEquals(
            "applyTaskIdentity must be called from onCreate and the swap handler, " +
                "both passing decoyActive",
            2,
            activity.split("applyTaskIdentity(decoyActive = ").size - 1,
        )
    }

    @Test
    fun `the application label in the manifest is permanently the disguise`() {
        // THE SURFACE THAT CANNOT BE RENAMED AT RUNTIME. `android:label` on
        // <application> is resolved by the package manager at INSTALL time
        // into ApplicationInfo.nonLocalizedLabel and cached for the life of
        // the install; the SDK exposes getApplicationLabel with no counterpart
        // setter, and because the value is a literal rather than an @string
        // reference there is not even a resource id for an overlay to
        // retarget. It therefore cannot FOLLOW the disguise the way the
        // channels above do -- it can only BE the disguise, permanently.
        //
        // It is also the widest surface the app has: Settings > Apps, the
        // title of the very Notifications screen the channel rows live on,
        // Settings > Network and internet > VPN, the VPN consent dialog, the
        // runtime permission prompts, and the app-name byline over every
        // notification -- none of which needs a tunnel, a notification or any
        // user action to be visible.
        //
        // Scoped to the PHONE's manifest specifically (censusKey, not a bare
        // name match) now that mainSourceFiles() also returns the watch's
        // AndroidManifest.xml, which is a deliberately different shape: no
        // activity-alias pair, and a label that is a resource reference, not
        // a literal. Asserting this test's alias-shaped invariants against
        // that file would be asserting the wrong design onto it rather than
        // catching a real defect. Its own, differently-shaped invariant is
        // the next test below.
        for (manifest in mainSourceFiles().filter { censusKey(it) == "android/AndroidManifest.xml" }) {
            val text = stripXmlComments(manifest.readText())
            org.junit.Assert.assertEquals(
                "${manifest.name}: the application label is what Settings > Apps " +
                    "renders, and no API can rename it after install, so it must be " +
                    "the disguise and must not drift from DISGUISED_DISPLAY_NAME",
                VpnTunnelService.DISGUISED_DISPLAY_NAME,
                attributeOf(text, "<application", "android:label"),
            )
            // The un-camouflaged identity is carried by the alias instead --
            // that is the whole reason the label above can be given away. If
            // the decoy alias ever stopped matching, Settings and the home
            // screen would disagree while camouflage is ON, which is the
            // failure this scheme exists to prevent.
            org.junit.Assert.assertEquals(
                "${manifest.name}: the decoy alias must carry the same disguise as " +
                    "the application label",
                VpnTunnelService.DISGUISED_DISPLAY_NAME,
                aliasLabel(text, ".LauncherDecoy"),
            )
            org.junit.Assert.assertNotEquals(
                "${manifest.name}: the real alias is the ONLY thing left telling an " +
                    "un-camouflaged user the truth on their home screen; disguising " +
                    "it too would leave them with no way to find their own app",
                VpnTunnelService.DISGUISED_DISPLAY_NAME,
                aliasLabel(text, ".LauncherReal"),
            )
        }
    }

    @Test
    fun `the watch application label defers to the disguised resource, never a literal`() {
        // The watch's counterpart to the test above, shaped around what is
        // actually true of that module rather than reusing the phone's
        // alias-shaped assertions on a manifest that has no aliases.
        //
        // wear_os has no camouflage signal and no alias scheme (the long
        // comment on wear_os/app/src/main/res/values/strings.xml's app_name
        // spells out why neither can be built there safely), so it is
        // disguised exactly once, unconditionally, through that one string
        // resource -- which WatchAppNameCamouflageTest pins from the watch
        // module's own build. That test reads strings.xml; it has no way to
        // notice if the manifest stopped deferring to that resource and
        // inlined a copy of its value instead. A literal would still read as
        // the disguise today, passing that test and the bare-substring
        // census right below, and would only drift the next time the
        // disguise's value changed and this second copy was not updated with
        // it -- precisely the class of bug a single point of truth exists to
        // rule out, restated here as the structural check it deserves.
        val manifest = mainSourceFiles().single { censusKey(it) == "wear_os/AndroidManifest.xml" }
        org.junit.Assert.assertEquals(
            "the watch manifest must keep pointing at the string resource, not " +
                "inline a copy of its value",
            "@string/app_name",
            attributeOf(stripXmlComments(manifest.readText()), "<application", "android:label"),
        )
    }

    @Test
    fun `the real display name is reachable from exactly two main source lines`() {
        // The same invariant as the channel-name test above, applied to the
        // bare product name, and extended into a full census because this
        // literal legitimately appears in more than one place.
        //
        // The bare name is a SUBSTRING of every longer real-identity string in
        // the app ("... Announcements", "... Core Services", "... Active"), so
        // counting it naively measures those instead. Each longer phrase is
        // removed first, longest first -- "... Announcements" before
        // "... Announcement", or the trailing "s" would strand the longer one
        // -- leaving exactly the occurrences that ARE the application's
        // display name, quoted or not, in Kotlin or in any resource.
        //
        // Two are expected and both are deliberate:
        //
        //   AndroidManifest.xml  -- the .LauncherReal alias label, which the
        //     OS renders only while that alias is enabled, i.e. never while
        //     the decoy is armed. Guarded by construction.
        //   VpnTunnelService.kt  -- taskDescriptionLabelFor, whose disguised
        //     branch cannot return it.
        //
        // Anything else -- a third hardcode, a resource string, a comment, a
        // file that did not exist when this was written -- fails here. That is
        // the point: every leak closed so far got in as exactly one more
        // hardcoded copy.
        //
        // Also spans the watch module now (mainSourceFiles), which is
        // expected to contribute NOTHING: it has no alias and no policy
        // function permitted to return the real name, so any occurrence
        // there at all is itself the defect, not a third deliberate one to
        // add to the expected map below. censusText normalises the watch's
        // `strings.xml`-style apostrophe escaping before the search, and
        // censusKey disambiguates the offender map so a watch-side file
        // cannot silently share a bucket with a same-named phone one.
        val offenders = mutableMapOf<String, Int>()
        for (file in mainSourceFiles()) {
            var text = censusText(file)
            for (phrase in LONGER_REAL_IDENTITY_PHRASES) text = text.replace(phrase, "")
            val occurrences = text.split(REAL_DISPLAY_NAME).size - 1
            if (occurrences > 0) offenders[censusKey(file)] = occurrences
        }
        org.junit.Assert.assertEquals(
            "the real display name may reach only the .LauncherReal alias and " +
                "VpnTunnelService.taskDescriptionLabelFor; found $offenders",
            mapOf("android/AndroidManifest.xml" to 1, "android/VpnTunnelService.kt" to 1),
            offenders,
        )
    }

    @Test
    fun `the TV manifest is never disguised`() {
        // OPPOSITE INVARIANT to the phone's AndroidManifest.xml above.
        // On Android TV (UiModeManager TELEVISION or leanback feature) the
        // decoy calculator has no D-pad focus handling (Material+InkWell+onTap)
        // so a TV build that arms the disguise permanently locks the user out.
        // The TV manifest must therefore never carry the disguise: its
        // application label is the real product name, unconditionally, and no
        // file under src/tv may ever contain the disguised name.
        var dir: java.io.File? = java.io.File(System.getProperty("user.dir") ?: ".").absoluteFile
        var tvManifest: java.io.File? = null
        while (dir != null) {
            for (relative in listOf("src/tv/AndroidManifest.xml", "android/app/src/tv/AndroidManifest.xml")) {
                val candidate = java.io.File(dir, relative)
                if (candidate.isFile) {
                    tvManifest = candidate
                    break
                }
            }
            if (tvManifest != null) break
            dir = dir.parentFile
        }
        assertTrue("TV manifest not found at android/app/src/tv/AndroidManifest.xml", tvManifest != null && tvManifest!!.isFile)
        val text = stripXmlComments(tvManifest!!.readText())
        org.junit.Assert.assertEquals(
            "TV manifest must never be disguised; application label must be the real product name",
            "Win's VPN",
            attributeOf(text, "<application", "android:label"),
        )
        // No disguised name may appear anywhere in the TV source set.
        val tvRootCandidates = listOf(
            java.io.File(tvManifest!!.parentFile.parentFile, "tv"),
            java.io.File(System.getProperty("user.dir") ?: ".", "src/tv"),
        )
        for (root in tvRootCandidates) {
            if (!root.isDirectory) continue
            for (file in root.walkTopDown().filter { it.isFile && (it.name.endsWith(".xml") || it.name.endsWith(".kt")) }) {
                val content = file.readText()
                assertFalse(
                    "TV source ${file.path} must never contain the disguised display name",
                    content.contains("Calculator") && content.contains("android:label=\"Calculator\""),
                )
            }
        }
        // Also assert the TV detection hook exists in MainActivity.
        val mainActivity = mainSource("MainActivity.kt")
        assertTrue(
            "MainActivity must guard triggerCamouflageSwap on TV form factor",
            mainActivity.contains("isTelevision()") && mainActivity.contains("triggerCamouflageSwap"),
        )
        assertTrue(
            "isTelevision must check UiModeManager TELEVISION and leanback",
            mainActivity.contains("UI_MODE_TYPE_TELEVISION") && mainActivity.contains("FEATURE_LEANBACK"),
        )
        // VpnTunnelService.setLauncherComponentState is a second writer: several
        // teardown paths default keepVpnLauncher=false and would enable the
        // decoy after a session. TV must refuse that path too.
        val tunnel = mainSource("VpnTunnelService.kt")
        assertTrue(
            "VpnTunnelService.setLauncherComponentState must guard on isTelevision",
            tunnel.contains("setLauncherComponentState") && tunnel.contains("isTelevision()"),
        )
        assertTrue(
            "VpnTunnelService.isTelevision must check TELEVISION and leanback",
            tunnel.contains("UI_MODE_TYPE_TELEVISION") && tunnel.contains("FEATURE_LEANBACK"),
        )
    }

    /**
     * Every file under **both** Android modules' `src/main` that could carry
     * a user-visible string: all Kotlin, and all XML (manifests, resources)
     * -- the phone app and, since 2026-08-08, the watch companion.
     *
     * Discovered by walking the tree rather than enumerated, so a source added
     * tomorrow is covered without anyone remembering to add it here. macOS
     * AppleDouble sidecars (`._Foo.kt`) are skipped -- they are binary resource
     * forks, not sources.
     *
     * A single combined list rather than two separate sweeps, for the same
     * reason the tunnel channel's literal joined the announcement channel's
     * guard instead of getting one of its own: "which real-identity strings
     * may exist in main sources, and where" is one invariant, and splitting
     * it across two lists is how a literal hides in whichever list nobody is
     * looking at.
     */
    private fun mainSourceFiles(): List<java.io.File> {
        var dir: java.io.File? = java.io.File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf("src/main", "android/app/src/main")) {
                val root = java.io.File(dir, relative)
                if (root.isDirectory) {
                    // `dir` is anchored: `android/app` when `relative` is the
                    // short form (Gradle's own test-task working directory),
                    // the repo root when it is the long form (an IDE, or any
                    // other working directory). The watch module hangs off
                    // that SAME anchor, at the path that differs by exactly
                    // the same prefix, so it does not need its own walk-up.
                    val wearRelative = if (relative == "src/main") {
                        "../../wear_os/app/src/main"
                    } else {
                        "wear_os/app/src/main"
                    }
                    val phoneFiles = sourceFilesUnder(root)
                    val wearRoot = java.io.File(dir, wearRelative)
                    val wearFiles = sourceFilesUnder(wearRoot)
                    assertTrue("no main sources found under $root", phoneFiles.isNotEmpty())
                    // Asserted separately from the phone's own non-emptiness
                    // above: `phoneFiles + wearFiles` being non-empty would
                    // still hold even if the watch half silently resolved to
                    // nothing, which is precisely the shape of gap that let a
                    // hardcoded six-file list stand in for a real sweep
                    // before this class existed.
                    assertTrue(
                        "no watch main sources found under $wearRoot -- the combined " +
                            "census would silently stop covering the watch module",
                        wearFiles.isNotEmpty(),
                    )
                    return phoneFiles + wearFiles
                }
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate src/main from ${System.getProperty("user.dir")}",
        )
    }

    /** Every `.kt`/`.xml` file under [root], skipping AppleDouble sidecars. */
    private fun sourceFilesUnder(root: java.io.File): List<java.io.File> {
        if (!root.isDirectory) return emptyList()
        return root.walkTopDown()
            .filter { it.isFile && !it.name.startsWith("._") }
            .filter { it.name.endsWith(".kt") || it.name.endsWith(".xml") }
            .toList()
    }

    /**
     * A stable, collision-free label for [file], used as the key in the
     * offender maps below instead of bare [java.io.File.getName].
     *
     * Bare file names stopped being unique the moment `mainSourceFiles()`
     * started covering two modules: both ship an `AndroidManifest.xml` and a
     * `colors.xml`, a `MainActivity.kt` exists on both sides of the watch
     * link, and the watch alone ships two `strings.xml` (one per locale). A
     * collision there would not throw -- `MutableMap` just overwrites one
     * file's count with another's -- which silently drops one module's
     * offender from the map. That is exactly the shape of false pass this
     * class exists to prevent, so every key is tagged with its module and,
     * where the name is still ambiguous within a module (a resource whose
     * parent directory name starts with "values"), with its immediate
     * parent directory too.
     */
    private fun censusKey(file: java.io.File): String {
        val module = if ("/wear_os/" in file.path.replace('\\', '/')) "wear_os" else "android"
        val parent = file.parentFile?.name.orEmpty()
        return if (parent.startsWith("values")) "$module/$parent/${file.name}" else "$module/${file.name}"
    }

    /**
     * [file]'s text, with Android's resource-string apostrophe escape (`\'`)
     * normalised to a bare apostrophe first -- XML resources only, since the
     * escape is a `strings.xml` convention (an XML *attribute* value such as
     * `android:label="Win's VPN"` needs no such escaping, and neither does a
     * Kotlin string literal).
     *
     * The watch's `values/strings.xml` writes its disguise-relevant string as
     * `Win\'s VPN` -- a real backslash byte before the apostrophe -- so a
     * search for the bare phrase below would silently not match it: the
     * escaped and unescaped forms are different strings by exact substring
     * comparison, and this class only ever does exact substring comparison.
     * Restricted to `.xml` so it cannot also touch the two unrelated `\'`
     * sequences already living in the phone's own Kotlin (Char literals for
     * a backslash and a double quote, nowhere near a real-identity string).
     */
    private fun censusText(file: java.io.File): String {
        val text = file.readText()
        return if (file.name.endsWith(".xml")) text.replace("\\'", "'") else text
    }

    /**
     * The brace-balanced body of the first declaration whose text starts with
     * [signature]. Scoping an assertion to one function is what stops a
     * file-wide `contains` passing on a match that lives somewhere else
     * entirely.
     */
    private fun functionBody(source: String, signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("could not find $signature", start >= 0)
        val open = source.indexOf('{', start)
        assertTrue("no body for $signature", open >= 0)
        var depth = 0
        var i = open
        while (i < source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> depth--
            }
            if (depth == 0) return source.substring(open, i + 1)
            i++
        }
        throw AssertionError("unterminated body for $signature")
    }

    /**
     * Reads one of the application's own main sources. Walks up from the test
     * working directory so it does not depend on whether Gradle runs this from
     * `android/app` or from the repository root.
     */
    private fun mainSource(name: String): String {
        var dir: java.io.File? = java.io.File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/main/kotlin/org/winsvpn/app/$name",
                "android/app/src/main/kotlin/org/winsvpn/app/$name",
            )) {
                val candidate = java.io.File(dir, relative)
                if (candidate.isFile) return candidate.readText()
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate $name from ${System.getProperty("user.dir")}",
        )
    }

    /**
     * The value of [attribute] on the start tag beginning with [tag]. Comments
     * must already be stripped, or a `>` inside one would end the tag early.
     */
    private fun attributeOf(xml: String, tag: String, attribute: String): String? {
        val start = xml.indexOf(tag)
        assertTrue("no $tag element", start >= 0)
        val end = xml.indexOf('>', start)
        assertTrue("unterminated $tag element", end >= 0)
        return Regex(attribute + "=\"([^\"]*)\"")
            .find(xml.substring(start, end))
            ?.groupValues
            ?.get(1)
    }

    /** The `android:label` of the `<activity-alias>` named [name]. */
    private fun aliasLabel(xml: String, name: String): String? {
        val start = xml.indexOf("android:name=\"" + name + "\"")
        assertTrue("no activity-alias $name", start >= 0)
        val open = xml.lastIndexOf("<activity-alias", start)
        assertTrue("no activity-alias start tag for $name", open >= 0)
        return attributeOf(xml.substring(open), "<activity-alias", "android:label")
    }

    private fun stripXmlComments(xml: String): String =
        xml.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")

    private companion object {
        /** The application's real, un-camouflaged display name. */
        const val REAL_DISPLAY_NAME = "Win's VPN"

        /**
         * Longer real-identity strings that legitimately CONTAIN
         * [REAL_DISPLAY_NAME] and are owned by their own policy or decision.
         * Removed longest-first before the display name is counted, so the
         * census measures the standalone name and not these. Adding an entry
         * here is a decision, not a formality.
         */
        val LONGER_REAL_IDENTITY_PHRASES = listOf(
            // announcementChannelNameFor
            "Win's VPN Announcements",
            // tunnelChannelNameFor
            "Win's VPN Core Services",
            // the announcement title default, MainActivity
            "Win's VPN Announcement",
            // the tunnel notification title -- rebuilt on every icon swap, so
            // deliberately NOT a latched surface
            "Win's VPN Active",
            // PROPERTY_SPECIAL_USE_FGS_SUBTYPE -- Play-review metadata, not a
            // Settings surface; left in place deliberately, see the handoff
            "Win's VPN encrypted network tunnel",
            // announcementChannelDescriptionFor
            "Important Win's VPN service announcements",
        ).sortedByDescending { it.length }
    }
}
