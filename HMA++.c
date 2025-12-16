#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <uapi/linux/limits.h>
#include <linux/kernel.h>

// ====================== KPM 标准元信息（仅保留5个核心宏） ======================
#define MODULE_NAME "HMA_Next"
KPM_NAME(MODULE_NAME);          // 模块名称（无特殊字符）
KPM_VERSION("1.0.19");          // 版本号
KPM_LICENSE("GPLv3");           // 许可证（KPM强制要求）
KPM_AUTHOR("NightFallsLikeRain");// 作者
KPM_DESCRIPTION("全应用风险+广告拦截（含微信/QQ/银行/系统软件白名单）");

// ====================== 极简核心宏定义（零冗余） ======================
#define MAX_PACKAGE_LEN 256       // 包名长度上限（通用值）
#define ARG_SEPARATOR ','         // 控制参数分隔符
#define PATH_SEPARATOR '/'        // 路径分隔符
#define HZ 100                    // 通用内核HZ值（兼容绝大多数内核）
#define INTERVAL 2 * 60 * HZ      // 2分钟拦截间隔（极简时间控制）
#define KPM_CTL_PATH "/proc/kpmctl/" MODULE_NAME  // 标准KPM控制路径

// ====================== 极简内核符号声明（仅核心依赖） ======================
extern unsigned long jiffies;    // 内核通用时间戳（仅显式声明核心符号）
// KPM框架标准接口声明（与KPM头文件完全一致）
extern hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
extern void unhook_syscalln(int nr, void *before, void *after);

// ====================== 全局变量（极简初始化） ======================
static bool hma_running = true;        // 总开关（默认开启）
static bool hma_ad_enabled = true;     // 广告拦截开关
static unsigned long last_blocked_time[MAX_PACKAGE_LEN] = {0};  // 静态初始化（内核兼容）

// ====================== 函数原型声明（仅必要函数） ======================
static char *get_package_name(const char *path);
static int is_whitelisted(const char *path);
static int is_blocked_path(const char *path);
static int is_ad_blocked(const char *path);
static int can_block(const char *path);
static long hma_init(const char *args, const char *event, void *__user reserved);
static long hma_control(const char *args, char *__user out_msg, int outlen);
static long hma_exit(void *__user reserved);

// ====================== 核心白名单（极简通用版） ======================
static const char *whitelist[] = {
    // 系统核心应用（通用Linux/Android系统）
    "com.android.systemui", "com.android.settings", "com.android.phone",
    "com.android.contacts", "com.android.mms", "com.android.launcher3",
    // 常用关键应用（通用兼容）
    "com.tencent.mm", "com.tencent.mobileqq", "com.eg.android.AlipayGphone",
    "com.icbc.mobilebank", "com.cmbchina", "com.unionpay",
    // KPM框架自身（避免拦截框架）
    "me.bmax.apatch", "com.bmax.apatch"
};
#define WHITELIST_SIZE (sizeof(whitelist)/sizeof(whitelist[0]))

// ====================== 黑名单（核心风险项，无冗余） ======================
static const char *deny_list[] = {
    // 风险应用核心列表（通用风险特征）
    "com.silverlab.app.deviceidchanger.free", "me.bingyue.IceCore",
    "com.modify.installer", "com.lerist.fakelocation", "lin.xposed",
    "moe.shizuku.privileged.api", "com.termux", "bin.mt.plus",
    "com.github.tianma8023.xposed.smscode", "tornaco.apps.shortx"
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

static const char *deny_folder_list[] = {
    // 风险路径核心列表（通用文件操作风险）
    "xposed_temp", "lsposed_cache", "hook_inject_data", "magisk_temp",
    "termux_data", "apktool_temp", "ad_cache", "ad_plugin"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

static const char *ad_file_keywords[] = {
    // 广告关键词核心列表（通用广告特征）
    "ad_", "_ad.", "ads_", "_ads.", "adcache", "adimg", "adpush", "adservice"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// ====================== 核心工具函数（极简实现，无冗余逻辑） ======================
static int is_whitelisted(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    const char *data_prefix = "/data/data/";
    const char *pkg_start = strstr(path, data_prefix);
    if (!pkg_start) return 0;

    pkg_start += strlen(data_prefix);
    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    // 极简白名单匹配（线性遍历，低开销）
    for (size_t j = 0; j < WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, whitelist[j]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_blocked_path(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    const char *data_prefix = "/data/data/";
    const char *android_data_prefix = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    if (strstr(path, data_prefix)) {
        pkg_start = path + strlen(data_prefix);
    } else if (strstr(path, android_data_prefix)) {
        pkg_start = path + strlen(android_data_prefix);
    } else {
        const char *last_slash = strrchr(path, PATH_SEPARATOR);
        pkg_start = last_slash ? last_slash + 1 : path;
    }

    char target_buf[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        target_buf[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    // 极简黑名单匹配
    for (size_t j = 0; j < DENY_LIST_SIZE; j++) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (size_t k = 0; k < DENY_FOLDER_SIZE; k++) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

static int is_ad_blocked(const char *path) {
    if (!hma_ad_enabled || !path) return 0;

    char lower_path[PATH_MAX];
    strncpy(lower_path, path, PATH_MAX - 1);
    lower_path[PATH_MAX - 1] = '\0';

    // 极简转小写（无额外函数调用）
    for (char *s = lower_path; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') *s += 32;
    }

    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i])) return 1;
    }
    return 0;
}

static int can_block(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    // 白名单直接放行
    if (is_whitelisted(path)) return 0;

    // 提取包名（极简逻辑复用）
    const char *data_prefix = "/data/data/";
    const char *pkg_start = strstr(path, data_prefix);
    if (!pkg_start) return 0;
    pkg_start += strlen(data_prefix);

    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    // 极简哈希（低开销）
    unsigned long hash = 0;
    for (i = 0; pkg_name[i]; i++) {
        hash = (hash * 31) + pkg_name[i];
    }

    // 极简时间控制（直接使用jiffies，无额外适配）
    unsigned long current_time = jiffies;
    unsigned long time_diff = current_time - last_blocked_time[hash % MAX_PACKAGE_LEN];
    if (time_diff >= INTERVAL) {
        last_blocked_time[hash % MAX_PACKAGE_LEN] = current_time;
        return 1;
    }
    return 0;
}

// ====================== 核心拦截钩子（极简实现，仅保留必要逻辑） ======================
static void __used before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';

    if (is_blocked_path(path) || is_ad_blocked(path)) {
        if (can_block(path)) {
            pr_warn("[%s] mkdirat deny: %s (pkg: %s)\n", MODULE_NAME, path, get_package_name(path));
            args->skip_origin = 1;
            args->ret = -EACCES;
        }
    }
}

static void __used before_chdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';

    if (is_blocked_path(path) || is_ad_blocked(path)) {
        if (can_block(path)) {
            pr_warn("[%s] chdir deny: %s (pkg: %s)\n", MODULE_NAME, path, get_package_name(path));
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

// ====================== 辅助函数（极简实现） ======================
static char *get_package_name(const char *path) {
    static char pkg_name[MAX_PACKAGE_LEN] = {0};
    memset(pkg_name, 0, sizeof(pkg_name));

    const char *data_prefix = "/data/data/";
    const char *pkg_start = strstr(path, data_prefix);
    if (!pkg_start) return pkg_name;

    pkg_start += strlen(data_prefix);
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    return pkg_name;
}

// ====================== 模块生命周期（极简KPM标准实现） ======================
static long __used hma_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[%s] init start (极简通用版)\n", MODULE_NAME);

    // 仅挂钩核心syscall（减少失败点）
    err = hook_syscalln((int)__NR_mkdirat, 3, (void *)before_mkdirat, NULL, NULL);
    if (err) {
        pr_err("[%s] hook mkdirat err: %d\n", MODULE_NAME, err);
        return -EINVAL;
    }

    err = hook_syscalln((int)__NR_chdir, 1, (void *)before_chdir, NULL, NULL);
    if (err) {
        pr_err("[%s] hook chdir err: %d\n", MODULE_NAME, err);
        unhook_syscalln((int)__NR_mkdirat, (void *)before_mkdirat, NULL);
        return -EINVAL;
    }

    pr_info("[%s] init success (global: %d, ad: %d, interval: %ds)\n",
            MODULE_NAME, hma_running, hma_ad_enabled, INTERVAL / HZ);
    return 0;
}

static long __used hma_control(const char *args, char *__user out_msg, int outlen) {
    char msg[64] = {0};
    if (!args || strlen(args) < 3 || !strchr(args, ARG_SEPARATOR)) {
        strncpy(msg, "args err: use '0/1,0/1' (global,ad)", sizeof(msg)-1);
        goto out;
    }

    char global_arg = args[0];
    char ad_arg = args[2];
    if ((global_arg != '0' && global_arg != '1') || (ad_arg != '0' && ad_arg != '1')) {
        strncpy(msg, "args err: only 0/1 allowed", sizeof(msg)-1);
        goto out;
    }

    hma_running = (global_arg == '1');
    hma_ad_enabled = (ad_arg == '1');
    snprintf(msg, sizeof(msg)-1, "%s: global=%s, ad=%s",
             MODULE_NAME, hma_running ? "on" : "off", hma_ad_enabled ? "on" : "off");

out:
    if (outlen >= strlen(msg) + 1) {
        compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

static long __used hma_exit(void *__user reserved) {
    pr_info("[%s] exit start\n", MODULE_NAME);
    unhook_syscalln((int)__NR_mkdirat, (void *)before_mkdirat, NULL);
    unhook_syscalln((int)__NR_chdir, (void *)before_chdir, NULL);
    pr_info("[%s] exit success\n", MODULE_NAME);
    return 0;
}

// ====================== KPM 标准注册（分散宏，兼容所有KPM版本） ======================
KPM_INIT(hma_init);
KPM_CTL0(hma_control);
KPM_EXIT(hma_exit);
