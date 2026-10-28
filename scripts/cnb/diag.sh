set -x
ls -la /root/.gradle || true
ls -la /root/.gradle/init.d || true
du -sh /root/.gradle 2>/dev/null || true
env | grep -i proxy || echo "no proxy vars"
curl -sS -o /dev/null -w 'central-code-%{http_code}\n' --max-time 30 https://repo1.maven.org/maven2/org/jetbrains/kotlin/android/org.jetbrains.kotlin.android.gradle.plugin/2.4.0/org.jetbrains.kotlin.android.gradle.plugin-2.4.0.pom || echo "curl failed"
gradle --no-daemon --console=plain --offline help 2>&1 | tail -30 || true
