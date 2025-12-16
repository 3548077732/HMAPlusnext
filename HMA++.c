// 仅保留核心头文件（内核通用+KPM必需，无版本依赖）
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <uapi/linux/limits.h>

// 模块元信息（极简必备）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.2.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("极简风险+广告拦截");

// 核心宏定义（无冗余，适配通用路径）
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif
#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH)-1)
#define MAX_PATH_LEN PATH_MAX
#define MAX_PACKAGE_LEN 2064

// 精简白名单（仅保留高频合规应用，减少匹配开销）
static const struct {
    const char *path;
    size_t len;
} legal_paths[] = {
    {"/storage/emulated/0/Android/data/com.tencent.mm/", 42},
    {"/storage/emulated/0/Android/data/com.tencent.mobileqq/", 46},
    {"/storage/emulated/0/Android/data/com.eg.android.AlipayGphone/", 50},
    {"/storage/emulated/0/Android/data/cn.wps.moffice_eng/", 47},
    {"/storage/emulated/0/Android/data/com.ss.android.ugc.aweme/", 49},
};
#define LEGAL_PATH_COUNT (sizeof(legal_paths)/sizeof(legal_paths[0]))

// 精简黑名单（核心风险关键词，无重复）
static const char *risk_keywords[] = {
    "xposed", "lsposed", "hook", "inject", "patch", "mod", "crack", "hack",
    "emulator", "virtual", "fake", "termux", "apktool", "root", "magisk", "ksu",
    "advertise", "ads", "adbanner", "adpopup", "adpush"
};
#define RISK_KEYWORD_COUNT (sizeof(risk_keywords)/sizeof(risk_keywords[0]))

// 风险后缀（通用恶意文件类型）
static const char *risk_suffixes[] = {".so", ".dex", ".apk", ".xposed", ".hook"};
#define RISK_SUFFIX_COUNT (sizeof(risk_suffixes)/sizeof(risk_suffixes[0]))

// 全局开关（极简控制，无冗余变量）
static bool hma_enabled = true;

// 1. 白名单校验（极简匹配逻辑，减少计算开销）
static bool is_legal(const char *path) {
    if (!path || strlen(path) < TARGET_PATH_LEN) return false;
    for (int i = 0; i < LEGAL_PATH_COUNT; i++) {
        if (strncmp(path, legal_paths[i].path, legal_paths[i].len) == 0) {
            return true;
        }
    }
    return false;
}

// 2. 风险检测（关键词+后缀双重校验，无冗余判断）
static bool is_risky(const char *path) {
    if (!path) return false;
    // 关键词匹配（忽略大小写）
    char lower_path[MAX_PATH_LEN];
    strncpy(lower_path, path, MAX_PATH_LEN-1);
    lower_path[MAX_PATH_LEN-1] = '\0';
    for (char *p = lower_path; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') *p += 32;
    }
    // 关键词匹配
    for (int i = 0; i < RISK_KEYWORD_COUNT; i++) {
        if (strstr(lower_path, risk_keywords[i])) {
            // 后缀二次校验，减少误判
            size_t path_len = strlen(path);
            for (int j = 0; j < RISK_SUFFIX_COUNT; j++) {
                size_t suffix_len = strlen(risk_suffixes[j]);
                if (path_len >= suffix_len && 
                    strcmp(path + path_len - suffix_len, risk_suffixes[j]) == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

// 核心挂钩逻辑（统一处理所有文件操作，精简代码）
static void hook_file_op(hook_fargs_t *args, void *udata) {
    if (!hma_enabled) return;
    
    char path[MAX_PATH_LEN] = {0};
    long len = 0;
    // 适配不同syscall的path参数位置（通用处理，无架构依赖）
    switch (args->syscall) {
        case __NR_mkdirat:
        case __NR_unlinkat:
        case __NR_openat:
            len = kp_strncpy_from_user(path, args->args[1], MAX_PATH_LEN-1);
            break;
        case __NR_rmdir:
        case __NR_chdir:
            len = kp_strncpy_from_user(path, args->args[0], MAX_PATH_LEN-1);
            break;
        case __NR_renameat: {
            // renameat需检查新旧路径，取任一风险路径即拦截
            char new_path[MAX_PATH_LEN] = {0};
            len = kp_strncpy_from_user(path, args->args[1], MAX_PATH_LEN-1);
            long len_new = kp_strncpy_from_user(new_path, args->args[3], MAX_PATH_LEN-1);
            if (len_new > 0 && is_risky(new_path)) {
                strncpy(path, new_path, MAX_PATH_LEN-1);
                len = len_new;
            }
            break;
        }
        default:
            return; // 跳过未注册的syscall，避免无效计算
    }
    
    // 路径有效性校验+白名单放行
    if (len <= 0 || is_legal(path)) return;
    path[len] = '\0';
    
    // 目标路径+风险双重校验，拦截非法操作
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_risky(path)) {
        pr_warn("[HMA++] Blocked risky op: %s (syscall: %d)\n", path, args->syscall);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// 模块初始化（极简挂钩，符合KPM规范）
static long hma_init(void *udata) {
    pr_info("[HMA++] Init (minimal kernel build)\n");
    // 统一挂钩核心文件操作syscall（KPM自动适配架构）
    hook_syscall(__NR_mkdirat, hook_file_op, NULL, NULL);
    hook_syscall(__NR_chdir, hook_file_op, NULL, NULL);
    hook_syscall(__NR_rmdir, hook_file_op, NULL, NULL);
    hook_syscall(__NR_unlinkat, hook_file_op, NULL, NULL);
    hook_syscall(__NR_openat, hook_file_op, NULL, NULL);
    hook_syscall(__NR_renameat, hook_file_op, NULL, NULL);
    return 0;
}

// 模块控制（极简开关，无冗余功能）
static long hma_ctl(const char __user *args, char __user *out, size_t out_len) {
    char buf[2] = {0};
    if (copy_from_user(buf, args, 1)) return -EFAULT;
    hma_enabled = (buf[0] == '1') ? true : false;
    const char *msg = hma_enabled ? "Enabled" : "Disabled";
    if (out_len > strlen(msg)) {
        copy_to_user(out, msg, strlen(msg)+1);
    }
    return 0;
}

// 模块退出（修复函数原型，符合KPM规范）
static long hma_exit(void *udata) {
    pr_info("[HMA++] Exit\n");
    unhook_syscall(__NR_mkdirat, hook_file_op, NULL);
    unhook_syscall(__NR_chdir, hook_file_op, NULL);
    unhook_syscall(__NR_rmdir, hook_file_op, NULL);
    unhook_syscall(__NR_unlinkat, hook_file_op, NULL);
    unhook_syscall(__NR_openat, hook_file_op, NULL);
    unhook_syscall(__NR_renameat, hook_file_op, NULL);
    return 0;
}

// KPM注册（严格遵循框架宏定义规范）
KPM_INIT(hma_init);
KPM_CTL0(hma_ctl);
KPM_EXIT(hma_exit);
