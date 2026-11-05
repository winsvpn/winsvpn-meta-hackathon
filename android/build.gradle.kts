allprojects {
    repositories {
        google()
        mavenCentral()
    }
    // Gradle dependency locking, ported from wins_security's
    // platform/android/build.gradle.kts (lines 13-26). LockMode.STRICT is
    // explicit and live (see SUPPLY_CHAIN_PARITY_AUDIT_20260806.md ss5).
    // STRICT makes every configuration REQUIRE lock state, so the lockfiles in
    // gradle/dependency-locking/ must cover every project the build resolves:
    // :app (app.lockfile) plus the Flutter JNI tooling included as subprojects
    // (:jni -> jni.lockfile, :jni_flutter -> jni_flutter.lockfile), generated
    // 2026-08-25 with `gradlew --write-locks` on the macOS release host against
    // the reviewed Flutter 3.47.1/6655482ec0 SDK. Adding a project or a config
    // that resolves without a lock row will now FAIL the build until its
    // lockfile is regenerated -- that is the point of STRICT. Hash integrity of
    // the artifacts themselves is enforced separately by gradle/verification-
    // metadata.xml (file presence enables verification; <verify-metadata>true>)
    // matching wins_security's convention.
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

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
