//
// Created by Administrator on 2025/8/29.
//
#include "anti.h"
#include "utils.h"
#include <jni.h>

extern "C" JNIEXPORT void JNICALL
Java_com_example_anti_1fr_MainActivity_initHardening(JNIEnv*, jclass) {
    InitHardening();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_anti_1fr_MainActivity_runDetections(JNIEnv* env, jclass) {
    auto rep = RunAllDetections();
    auto json = ToJson(rep);
    return env->NewStringUTF(json.c_str());
}


