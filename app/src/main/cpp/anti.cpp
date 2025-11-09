//
// Created by Administrator on 2025/8/29.
//
#include "anti.h"
#include "utils.h"

#include <sys/prctl.h>
#include <unistd.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <android/log.h>
#define LOG_TAG "AntiFrida"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
// 1) 关闭 dump
void InitHardening() { prctl(PR_SET_DUMPABLE, 0); }

// ---------- 工具 ----------
static std::string readAll(const char* path) {
    std::ifstream ifs(path);
    std::stringstream ss; ss << ifs.rdbuf(); return ss.str();
}
static bool fileExists(const char* p) { return access(p, F_OK) == 0; }

// ---------- 具体检测 ----------
static bool IsTraced() {
    std::ifstream ifs("/proc/self/status");
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            int v = atoi(line.c_str() + 10);
            return v != 0;
        }
    }
    return false;
}

static const char* kBadMods[] = {
        "frida", "gadget", "xposed", "lsposed", "zygisk",
        "magisk", "substrate", "r2frida", "whale"
};

static int phdr_cb(struct dl_phdr_info *info, size_t, void *data) {
    if (!info || !info->dlpi_name) return 0;
    for (auto &p : kBadMods) {
        if (strcasestr(info->dlpi_name, p)) { *(int*)data = 1; return 1; }
    }
    return 0;
}
static bool DetectBadModules() {
    int found = 0; dl_iterate_phdr(phdr_cb, &found); return found != 0;
}

static bool ScanMapsForBadStrings() {
    std::ifstream ifs("/proc/self/maps");
    std::string line;
    while (std::getline(ifs, line)) {
        for (auto &p : kBadMods) {
            if (strcasestr(line.c_str(), p)) return true;
        }
    }
    return false;
}

static bool HasFridaPort(const char* path) {
    LOGD("开始检查文件: %s", path);

    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        LOGD("无法打开文件: %s", path);
        return false;
    }

    std::string line;
    std::getline(ifs, line); // 跳过标题行

    int lineCount = 0;
    while (std::getline(ifs, line)) {
        lineCount++;
        std::istringstream iss(line);
        std::string idx, local, remote, state;
        if (!(iss >> idx >> local >> remote >> state)) continue;

        // 只检查监听状态的连接
        if (state != "0A") continue;

        auto pos = local.find(':');
        if (pos == std::string::npos) continue;

        std::string portHex = local.substr(pos+1);
        LOGD("行%d: 本地地址=%s, 端口=%s, 状态=%s", lineCount, local.c_str(), portHex.c_str(), state.c_str());

        // 方法1: 直接数字比较（更可靠）
        try {
            uint16_t port = std::stoul(portHex, nullptr, 16);
            LOGD("端口数字值: %d", port);
            if (port == 27042 || port == 27043) {
                LOGD("!!! 检测到Frida端口: %d", port);
                return true;
            }
        } catch (...) {
            LOGD("端口转换失败: %s", portHex.c_str());
        }

        // 方法2: 字符串比较（备用）
        auto norm = [](std::string s){
            for (auto &c : s) c = (char)toupper(c);
            size_t p = s.find_first_not_of('0');
            return p == std::string::npos ? std::string("0") : s.substr(p);
        };

        std::string h = norm(portHex);
        LOGD("标准化端口: %s", h.c_str());

        if (h == "A269" || h == "A369" ||  // 小端格式
            h == "69A2" || h == "69A3") {  // 大端格式
            LOGD("!!! 检测到Frida端口(字符串匹配): %s", h.c_str());
            return true;
        }
    }

    LOGD("未在 %s 中检测到Frida端口，共检查了 %d 行", path, lineCount);
    return false;
}

static bool DetectFridaPorts() {
    LOGD("=== 开始Frida端口检测 ===");
    bool tcp = HasFridaPort("/proc/net/tcp");
    bool tcp6 = HasFridaPort("/proc/net/tcp6");
    LOGD("=== 端口检测结果: TCP=%s, TCP6=%s, 最终=%s ===",
         tcp ? "是" : "否", tcp6 ? "是" : "否", (tcp || tcp6) ? "是" : "否");
    return tcp || tcp6;
}

static bool DetectBadThreads() {
    DIR* d = opendir("/proc/self/task");
    if (!d) return false;
    dirent* e; char path[256], name[256];
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        FILE* f = fopen(path, "r"); if (!f) continue;
        if (fgets(name, sizeof(name), f)) {
            if (strcasestr(name, "frida") || strcasestr(name, "xposed") || strcasestr(name, "zygisk")) {
                fclose(f); closedir(d); return true;
            }
        }
        fclose(f);
    }
    closedir(d); return false;
}

static bool IsPtrInTrustedLib(void* p, const std::vector<std::string>& trust) {
    Dl_info info{};
    if (dladdr(p, &info) == 0 || !info.dli_fname) return false;
    std::string so(info.dli_fname);
    for (auto &t : trust) if (so.find(t) != std::string::npos) return true;
    return false;
}

#if defined(__aarch64__)
static inline uint32_t I32(const void* p) { return *(const uint32_t*)p; }

// 粗略判断 ADRP/ADD/LDR-literal/BR/BLR 等组合
static bool IsSuspiciousA64Branch(void* p) {
    if (!p) return true;
    const uint32_t *ins = (const uint32_t*)p;

    auto is_B_imm = [&](uint32_t w){ return ((w>>26)&0x3F)==0b000101; };            // B #
    auto is_BR    = [&](uint32_t w){ return (w & 0xFFFFFC1F)==0xD61F0000; };        // BR Xn
    auto is_BLR   = [&](uint32_t w){ return (w & 0xFFFFFC1F)==0xD63F0000; };        // BLR Xn

    auto is_ADRP  = [&](uint32_t w){ return ((w>>24)&0x1F)==0b10000; };             // ADRP
    auto is_ADDxn = [&](uint32_t w){ return ((w>>24)&0x1F)==0b10001; };             // ADD (imm) reg
    // LDR (literal): opc=01 size=64, op0=0b00, op1=0b01 -> 0x58000000..0x5BFFFFFF
    auto is_LDR_lit = [&](uint32_t w){ return (w & 0x1F000000) == 0x18000000; };

    // 检查前 5~8 条指令
    const int N = 8;
    bool seen_indirect = false, seen_setup = false;
    for (int i=0; i<N; ++i) {
        uint32_t w = ins[i];
        if (is_B_imm(w)) return true;                // 直接跳
        if (is_BR(w) || is_BLR(w)) {                 // 间接跳
            if (seen_setup) return true;             // 先有 setup（ADRP/ADD/LDR），再 BR → 可疑
            // 也可能没有 setup（短桩）也判可疑
            return true;
        }
        if (is_ADRP(w) || is_ADDxn(w) || is_LDR_lit(w)) {
            seen_setup = true;                       // 典型桩的“取地址准备”
        }
    }
    return false;
}
#else
static bool IsSuspiciousA64Branch(void*) { return false; }
#endif

static bool CheckDlsymHijackAndBranch(bool* outSuspiciousBranch) {
    std::vector<const char*> syms = {"open", "read", "dlopen", "dlsym","system"};
    std::vector<std::string> trust = {
            "/bionic/libc.so", "/lib64/libc.so", "/system/lib64/libc.so",
            "/bionic/libdl.so", "/system/lib64/libdl.so", "/apex/"
    };
    bool hijacked = false; bool suspicious = false;
    for (auto s : syms) {
        void* p = dlsym(RTLD_DEFAULT, s);
        if (!IsPtrInTrustedLib(p, trust)) hijacked = true;
        if (IsSuspiciousA64Branch(p)) suspicious = true;
    }
    if (outSuspiciousBranch) *outSuspiciousBranch = suspicious;
    return hijacked;
}

// 汇总
AntiReport RunAllDetections() {
    AntiReport r;
    r.traced           = IsTraced();
    r.badModules       = DetectBadModules();
    r.badMaps          = ScanMapsForBadStrings();
    r.fridaPort        = DetectFridaPorts();
    r.badThreads       = DetectBadThreads();
    r.dlsymHijack      = CheckDlsymHijackAndBranch(&r.suspiciousBranch);
    return r;
}

std::string ToJson(const AntiReport& rep) {
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{"
             "\"traced\":%s,"
             "\"badModules\":%s,"
             "\"badMaps\":%s,"
             "\"fridaPort\":%s,"
             "\"badThreads\":%s,"
             "\"dlsymHijack\":%s,"
             "\"suspiciousBranch\":%s"
             "}",
             rep.traced?"true":"false",
             rep.badModules?"true":"false",
             rep.badMaps?"true":"false",
             rep.fridaPort?"true":"false",
             rep.badThreads?"true":"false",
             rep.dlsymHijack?"true":"false",
             rep.suspiciousBranch?"true":"false"
    );
    return std::string(buf);
}
