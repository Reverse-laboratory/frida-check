#pragma once
#include <jni.h>
#include <string>

struct AntiReport {
    bool traced = false;
    bool badModules = false;
    bool badMaps = false;
    bool fridaPort = false;
    bool badThreads = false;
    bool dlsymHijack = false;
    bool suspiciousBranch = false;
};

void InitHardening();
AntiReport RunAllDetections();
std::string ToJson(const AntiReport& rep);
