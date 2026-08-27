plugins {
    // No versions here: when include'd into android-light-node (the only
    // Gradle consumer today), the root settings' pluginManagement forces
    // AGP/Kotlin versions via eachPlugin — a second explicit `version`
    // on the shared buildscript classpath is rejected by Gradle
    // ("already on the classpath with an unknown version"). Standalone
    // builds must supply versions via their own pluginManagement.
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "uniffi.kovanica"
    compileSdk = 34

    defaultConfig {
        minSdk = 24          // matches --platform 24 in build-android.sh
        consumerProguardFiles("consumer-rules.pro")
    }

    // The generated Kotlin bindings stay committed one level up
    // (bindings/kotlin/uniffi/kovanica/kovanica.kt) so CI can drift-check
    // them; this module just compiles them in.
    sourceSets["main"].java.srcDirs("../bindings/kotlin")
    // jniLibs/src/main/jniLibs is the default — populated by build-android.sh.
}

dependencies {
    // uniffi 0.32 generates JNA-based bindings: this is the sole runtime dep.
    api("net.java.dev.jna:jna:5.14.0@aar")
}
