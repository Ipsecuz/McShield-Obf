#include <jni.h>
JNIEXPORT jint JNICALL Java_boot_Axis_probe(JNIEnv* env, jclass cls, jint x) {
    (void)env; (void)cls;
    return (jint)((x ^ 0x6D63732A) + 0x00001234);
}
