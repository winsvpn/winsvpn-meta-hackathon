package org.winsvpn.app

import android.content.Context
import android.content.ContextWrapper
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A migration that stopped after its encrypted write left the plaintext copy
 * beside a record that authenticates. The next read must retire that copy.
 * Fixture text only; a throwaway files dir and Keystore alias per run.
 */
@RunWith(AndroidJUnit4::class)
class SecureFileStoreMigrationRecoveryTest {
    @Test
    fun successfulReadFinishesInterruptedPlaintextMigration() {
        val base = ApplicationProvider.getApplicationContext<Context>()
        val root = Files.createTempDirectory(base.cacheDir.toPath(), "migration-").toFile()
        val identity = base.packageName + ".migration_" + UUID.randomUUID().toString()
        val context = object : ContextWrapper(base) {
            override fun getFilesDir(): File = root
            override fun getPackageName(): String = identity
        }
        val legacy = File(root, "legacy-vpn-config.txt")
        try {
            // The state a process exit between write() and the plaintext wipe
            // leaves behind: a current record plus an older plaintext copy.
            SecureFileStore(context).write("vpn_config.txt", "current fixture")
            legacy.writeText("older plaintext fixture")
            val restarted = SecureFileStore(context)
            assertEquals("current fixture", restarted.read("vpn_config.txt", legacy))
            assertFalse("an authenticated read must retire the plaintext copy", legacy.exists())
            assertEquals("current fixture", restarted.read("vpn_config.txt", legacy))
        } finally {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry("$identity.secure-files.v1")
            root.deleteRecursively()
        }
    }
}
