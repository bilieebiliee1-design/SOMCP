-keep class com.soreverse.mcp.core.BackupCrypto {
    *;
}

-keep class com.lambdapioneer.argon2kt.** {
    *;
}

-keep class com.soreverse.mcp.nativecore.RizinNativeEngine {
    *;
}

-keep class com.soreverse.mcp.engine.LiefEngine {
    *;
}

-keep class com.soreverse.mcp.blutter.** {
    *;
}

-keep class com.github.unidbg.** {
    *;
}

# scijava-native-lib-loader is transitively pulled in by zhkl0228:unicorn:1.0.15.
# Unicorn2Factory's static init block calls NativeLoader.loadLibrary("unicorn"),
# and the call site only catches IOException. If R8 strips NativeLoader, the
# class load fails with NoClassDefFoundError (a LinkageError, NOT an IOException)
# and Unicorn2Factory can never be initialized — Unidbg degrades completely.
# Keep all scijava.nativelib classes so NativeLoader remains on the classpath.
-keep class org.scijava.nativelib.** {
    *;
}

-keep class unicorn.** {
    *;
}

-keep class net.fornwall.jelf.** {
    *;
}

-keep class capstone.** {
    *;
}

-keep class unicorn.** {
    *;
}

-keep class com.sun.jna.** {
    *;
}

-keep class com.sun.jna.ptr.** {
    *;
}

-keep class com.sun.jna.win32.** {
    *;
}

-keep class net.dongliu.apk.parser.** {
    *;
}

-keep class com.lambdapioneer.argon2kt.** {
    *;
}

-dontwarn com.github.unidbg.**
-dontwarn unicorn.**
-dontwarn net.fornwall.jelf.**
-dontwarn capstone.**
-dontwarn com.sun.jna.**
-dontwarn net.dongliu.apk.parser.**
-dontwarn com.google.common.collect.ArrayListMultimap
-dontwarn com.google.common.collect.Multimap
-dontwarn java.awt.Color
-dontwarn java.awt.Font
-dontwarn java.awt.Point
-dontwarn java.awt.Rectangle
-dontwarn javax.money.CurrencyUnit
-dontwarn javax.money.Monetary
-dontwarn org.javamoney.moneta.Money
-dontwarn org.joda.time.**
-dontwarn springfox.documentation.spring.web.json.Json

-keepclasseswithmembernames class * {
    native <methods>;
}

-keepattributes *Annotation*,InnerClasses,EnclosingMethod,Signature

-keep class kotlinx.coroutines.flow.Flow { *; }
-keep class kotlin.reflect.jvm.internal.LazyKProperty { *; }
-keepclassmembers class ** {
    static kotlin.reflect.KProperty[] $$delegatedProperties;
}

-dontwarn java.lang.management.**
-dontwarn org.slf4j.**
