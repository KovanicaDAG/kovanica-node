plugins {
    id("com.android.library") version "8.5.2"
    id("org.jetbrains.kotlin.android") version "2.0.20"
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
