// Exact latest-stable toolchain snapshot verified from primary upstreams on
// 2026-10-06. AGP 9.4 requires Gradle 9.6.0 or newer; the shared Gradle 9.8.0
// wrapper and Kotlin Compose compiler 2.4.20 pins are the latest stables.
plugins {
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}

allprojects {
    // STRICT makes every configuration REQUIRE lock state, so the lockfiles
    // in gradle/dependency-locking/ must cover every project this build
    // resolves. Adding a configuration that resolves without a lock row fails
    // the build until its lockfile is regenerated with --write-locks. Hash
    // integrity of the artifacts themselves is enforced separately by
    // gradle/verification-metadata.xml (file presence enables verification).
    dependencyLocking {
        lockAllConfigurations()
        lockMode = LockMode.STRICT
        val lockName =
            if (project.path == ":") {
                "root"
            } else {
                project.path.removePrefix(":").replace(":", "__")
            }
        lockFile =
            rootProject.layout.projectDirectory.file(
                "gradle/dependency-locking/$lockName.lockfile",
            )
    }
}
