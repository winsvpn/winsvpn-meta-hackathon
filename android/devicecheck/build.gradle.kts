plugins {
    id("com.android.application") apply false
}

allprojects {
    // STRICT makes every configuration REQUIRE lock state, so the lockfiles
    // in gradle/dependency-locking/ must cover every project this standalone
    // DeviceCheck build resolves. Adding a configuration that resolves without
    // a lock row fails the build until its lockfile is regenerated with
    // --write-locks. Hash integrity of the artifacts themselves is enforced
    // separately by gradle/verification-metadata.xml (file presence enables
    // verification). This harness stays outside android/settings.gradle.kts.
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
