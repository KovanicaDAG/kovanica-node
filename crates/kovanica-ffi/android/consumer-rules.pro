# JNA loads libjnidispatch reflectively and uniffi's generated code reaches
# the native library through it — both must survive R8 minification in the
# consuming app.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-keep class uniffi.kovanica.** { *; }
-dontwarn java.awt.*
-dontwarn javax.swing.*
