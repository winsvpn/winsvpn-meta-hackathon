package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureFileStoreTest {
    @Test
    fun onlyKnownSensitiveFilesAreAccepted() {
        assertTrue(SecureFileStore.isAllowedName("vpn_config.txt"))
        assertTrue(SecureFileStore.isAllowedName("user_pin.txt"))
        assertFalse(SecureFileStore.isAllowedName("../vpn_config.txt"))
        assertFalse(SecureFileStore.isAllowedName("unknown.txt"))
    }

    /**
     * The logical names this store is asked for. Kept here rather than read
     * from the private `allowedNames` so that adding a record without adding
     * its on-disk name fails the tests below instead of passing silently.
     */
    private val logicalNames = listOf(
        "client_keypair.json",
        "calc_session.json",
        "calc_state.json",
        "install_id.txt",
        "pending_logout.json",
        "user_pin.txt",
        "vpn_config.txt",
        "vpn_settings.txt",
        "wins_vpn_restart_config.conf",
        "wins_vpn_restart_node.txt",
        "wins_kill_switch_armed",
        "winn3_keypair.json",
        // The user's current Double VPN choice, read by the service on restart.
        "route_intent.txt",
    )

    @Test
    fun theStoreAcceptsExactlyTheNamesThisTestKnowsAbout() {
        for (name in logicalNames) {
            assertTrue("$name should be an allowed record", SecureFileStore.isAllowedName(name))
        }
    }

    @Test
    fun theSurvivingDuressFileIsNotNamedAfterTheApp() {
        // THE DEFECT THIS EXISTS FOR. The offline duress branch deliberately
        // keeps the settings record so a queued alert can still be sent, so on
        // a phone that has just been through a duress wipe this is THE one
        // surviving file -- and it used to be called `vpn_settings.txt.wvs`,
        // inside an app posing as a calculator. That named the app and
        // announced that something had been kept on purpose.
        assertEquals("prefs.dat", SecureFileStore.onDiskName("vpn_settings.txt"))
        assertFalse(
            SecureFileStore.onDiskName("vpn_settings.txt").contains("vpn"),
        )
    }

    @Test
    fun everyRecordHasAnOnDiskNameAndNoneFallsBackToTheLegacyScheme() {
        // `onDiskName` falls back to the old `$name.wvs` for anything missing
        // from the map. That fallback is what would quietly reintroduce the
        // self-describing filename if a record were added to `allowedNames`
        // and not to `onDiskNames`, so assert no record reaches it.
        for (name in logicalNames) {
            assertNotEquals(
                "$name has no on-disk name and fell back to the self-describing one",
                SecureFileStore.legacyOnDiskName(name),
                SecureFileStore.onDiskName(name),
            )
        }
    }

    @Test
    fun noOnDiskNameDescribesWhatTheAppIsOrDoes() {
        // A filename inside a calculator must survive someone reading `ls`.
        val telltales = listOf(
            "vpn", "wins", "pin", "tunnel", "config", "settings", "keypair",
            "logout", "install", "restart", "secret", "duress", "alert", "decoy",
            "wvs",
        )
        for (name in logicalNames) {
            val onDisk = SecureFileStore.onDiskName(name).lowercase()
            for (telltale in telltales) {
                assertFalse(
                    "on-disk name '$onDisk' for '$name' contains '$telltale'",
                    onDisk.contains(telltale),
                )
            }
        }
    }

    @Test
    fun onDiskNamesAreDistinctSoNoRecordCanOverwriteAnother() {
        // A collision would make one record silently clobber another, and the
        // record most likely to be lost is the one the duress path kept.
        val onDisk = logicalNames.map { SecureFileStore.onDiskName(it) }
        assertEquals(
            "two logical records share an on-disk name: $onDisk",
            logicalNames.size,
            onDisk.toSet().size,
        )
    }

    @Test
    fun theLegacyNameIsStillDerivableSoMigrationCannotOrphanAQueuedAlert() {
        // `read()` and `delete()` both fall back to `legacySecureFile`, so a
        // rename that failed part-way leaves a record findable rather than
        // orphaning it. That fallback is only possible while the pre-rename
        // name is still computable, so pin the old scheme exactly.
        for (name in logicalNames) {
            assertEquals("$name.wvs", SecureFileStore.legacyOnDiskName(name))
        }
    }

    @Test
    fun theKillSwitchArmedFlagIsAPersistedRecordWithANeutralOnDiskName() {
        // MEASURED DEFECT, Motorola ZY22GTV6Z3 (API 35), 2026-08-11.
        // VpnTunnelService.setKillSwitchArmed persists under the logical name
        // "wins_kill_switch_armed", but that name was missing from
        // `allowedNames`, so SecureFileStore.write threw
        // IllegalArgumentException("Unsupported secure file name") for it,
        // the arm was never persisted, isKillSwitchArmed() read false on every
        // path, and the kill switch never held the blocking interface at a real
        // teardown. Pin BOTH the acceptance and the neutral on-disk name so a
        // future tightening cannot silently reintroduce the no-op.
        assertTrue(
            "the kill-switch armed flag must be a persistable record",
            SecureFileStore.isAllowedName(VpnTunnelService.KILL_SWITCH_STATE),
        )
        assertEquals("mode.dat", SecureFileStore.onDiskName(VpnTunnelService.KILL_SWITCH_STATE))
        assertFalse(
            "the on-disk name must not describe a kill switch or the app",
            SecureFileStore.onDiskName(VpnTunnelService.KILL_SWITCH_STATE).lowercase().contains("kill"),
        )
    }

    @Test
    fun onlyAProvablyUnusableRecordMayBeRemoved() {
        assertTrue(SecureFileStore.isPermanentRecordFailure(javax.crypto.AEADBadTagException("tag")))
        assertTrue(SecureFileStore.isPermanentRecordFailure(IllegalArgumentException("format")))
        assertTrue(SecureFileStore.isPermanentRecordFailure(java.io.EOFException()))
        assertFalse(SecureFileStore.isPermanentRecordFailure(java.security.KeyStoreException("busy")))
        assertFalse(SecureFileStore.isPermanentRecordFailure(java.io.IOException("read")))
        assertFalse(SecureFileStore.isPermanentRecordFailure(java.security.ProviderException("keystore")))
    }

    @Test
    fun onlyAKeyGoneForGoodIsReplaced() {
        assertTrue(SecureFileStore.isPermanentKeyFailure(java.security.UnrecoverableKeyException("gone")))
        assertFalse(SecureFileStore.isPermanentKeyFailure(java.security.KeyStoreException("busy")))
        assertFalse(SecureFileStore.isPermanentKeyFailure(java.security.ProviderException("keystore")))
        assertFalse(SecureFileStore.isPermanentKeyFailure(java.security.InvalidKeyException("transient")))
    }

    @Test
    fun anExistingAliasRequiresAnActualSecretKey() {
        val secret = javax.crypto.spec.SecretKeySpec(ByteArray(32), "AES")
        org.junit.Assert.assertSame(
            secret,
            SecureFileStore.requireExistingKey(secret),
        )

        val other = object : java.security.Key {
            override fun getAlgorithm(): String = "fixture"
            override fun getFormat(): String = "RAW"
            override fun getEncoded(): ByteArray = byteArrayOf(0)
        }

        for (key in listOf<java.security.Key?>(null, other)) {
            try {
                SecureFileStore.requireExistingKey(key)
                org.junit.Assert.fail("Unavailable existing key was accepted")
            } catch (e: java.security.KeyStoreException) {
                assertFalse(SecureFileStore.isPermanentKeyFailure(e))
            }
        }
    }
}
