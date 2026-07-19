-keep class com.soreverse.mcp.nativecore.RizinNativeEngine {
    *;
}

-keep class com.soreverse.mcp.engine.LiefEngine {
    *;
}

-keep class com.github.unidbg.** {
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
