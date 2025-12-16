// 仅保留KPM框架与内核核心头文件（无任何冗余依赖）
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <uapi/linux/limits.h>
#include <linux/kernel.h>

// 模块元信息（KPM标准宏，不可移除）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.8");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("全应用风险+广告拦截（2分钟检测间隔+核心白名单）");

// 核心宏定义（无依赖，纯内核原生）
#define MAX_PACKAGE_LEN 256
#define ARG_SEPARATOR ','
#define PATH_SEPARATOR '/'
#define HZ 100                  // 通用内核HZ值（无需头文件定义）
#define INTERVAL 2 * 60 * HZ    // 2分钟检测间隔（12000 jiffies）

// 全局变量（静态初始化，无动态依赖）
static bool hma_running = true;
static bool hma_ad_enabled = true;
// 记录每个包最后拦截时间（包名哈希映射，无内存依赖）
static unsigned long last_blocked_time[MAX_PACKAGE_LEN] = {0};

// 核心白名单（修复语法错误：添加缺失逗号）
static const char *whitelist[] = {
    "com.tencent.mm", "com.tencent.mobileqq", "com.tencent.minihd.qq", "com.tencent.wework",
    "com.android.systemui", "com.android.settings", "com.android.phone", "com.android.contacts",
    "com.android.mms", "com.android.launcher3", "com.android.packageinstaller",
    "com.icbc.mobilebank", "com.ccb.ccbphone", "com.abchina.mobilebank", "com.cmbchina.psbc",
    "com.cmbchina", "com.bankcomm", "com.spdb.mobilebank", "com.hxb.android",
    "com.cib.mobilebank", "com.pingan.bank", "com.abcwealth.mobile", "com.eg.android.AlipayGphone",
    "com.unionpay", "com.xiaomi.misettings", "com.huawei.systemmanager", "com.oppo.launcher",
    "com.vivo.launcher", "com.samsung.android.launcher", "com.meizu.flyme.launcher",
    "me.bmax.apatch", "com.larus.nova", "com.miui.home", "com.sukisu.ultra"
};
#define WHITELIST_SIZE (sizeof(whitelist)/sizeof(whitelist[0]))

// 风险拦截黑名单
static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free", "me.bingyue.IceCore",
    "com.modify.installer", "o.dyoo", "com.zhufucdev.motion_emulator",
    "com.xiaomi.shop", "com.demo.serendipity", "me.iacn.biliroaming",
    "me.teble.xposed.autodaily", "com.example.ourom", "dialog.box",
    "tornaco.apps.shortx", "moe.fuqiuluo.portal", "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api", "lin.xposed", "com.lerist.fakelocation",
    "com.yxer.packageinstalles", "bin.mt.plus.canary", "web1n.stopapp",
    "Hook.JiuWu.Xp", "com.taobao.taobao", "com.houvven.guise",
    "com.xayah.databackup.foss", "github.tornaco.android.thanos",
    "nep.timeline.freezer", "cn.geektang.privacyspace", "com.byyoung.setting",
    "cn.myflv.noactive", "com.junge.algorithmAidePro", "bin.mt.termex",
    "tmgp.atlas.toolbox", "com.wn.app.np", "icu.nullptr.nativetest",
    "ru.maximoff.apktool", "top.bienvenido.saas.i18n", "com.syyf.quickpay",
    "tornaco.apps.shortx.ext", "com.mio.kitchen", "eu.faircode.xlua",
    "com.dna.tools", "cn.myflv.monitor.noactive", "com.yuanwofei.cardemulator.pro",
    "com.termux", "com.suqi8.oshin", "me.hd.wauxv", "have.fun",
    "miko.client", "com.kooritea.fcmfix", "com.twifucker.hachidori",
    "com.luckyzyx.luckytool", "com.padi.hook.hookqq", "cn.lyric.getter",
    "com.parallelc.micts", "me.plusne", "com.hchen.appretention",
    "com.hchen.switchfreeform", "name.monwf.customiuizer", "com.houvven.impad",
    "cn.aodlyric.xiaowine", "top.sacz.timtool", "nep.timeline.re_telegram",
    "com.fuck.android.rimet", "cn.kwaiching.hook", "cn.android.x",
    "cc.aoeiuv020.iamnotdisabled.hook", "vn.kwaiching.tao", "com.nnnen.plusne",
    "com.fkzhang.wechatxposed", "one.yufz.hmspush", "cn.fuckhome.xiaowine",
    "com.fankes.tsbattery", "com.rifsxd.ksunext", "com.rkg.IAMRKG",
    "me.gm.cleaner", "com.ddm.qute", "kk.dk.anqu", "com.qq.qcxm",
    "dknb.con", "dknb.coo8", "com.tencent.jingshi", "com.tencent.JYNB",
    "com.apocalua.run", "com.coderstory.toolkit", "com.didjdk.adbhelper",
    "io.github.Retmon403.oppotheme", "com.fankes.enforcehighrefreshrate",
    "es.chiteroman.bootloaderspoofer", "com.hchai.rescueplan",
    "io.github.chipppppppppp.lime", "dev.device.emulator",
    "com.github.dan.NoStorageRestrict", "com.android1500.androidfaker",
    "com.smartpack.kernelmanager", "ps.reso.instaeclipse", "top.ltfan.notdeveloper",
    "com.rel.languager", "not.val.cheat", "com.haobammmm", "bin.mt.plus",
    "com.tencent.tmgp.dfm"
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

// 风险文件夹黑名单
static const char *deny_folder_list[] = {
    "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp",
    "system_modify", "root_tool_data", "magisk_temp", "ksu_cache", "kernel_mod_dir",
    "privacy_steal", "data_crack", "illegal_access", "info_collect", "secret_monitor",
    "apk_modify", "pirate_apk", "illegal_install", "app_cracked", "patch_apk_dir",
    "risk_temp", "unsafe_operation", "malicious_dir", "temp_hack", "unsafe_cache",
    "termux_data", "apktool_temp", "reverse_engineer", "hack_tool_data", "crack_tool_dir",
    "emulator_data", "virtual_env", "fake_device", "emulator_cache", "virtual_device",
    "ad_plugin", "malicious_plugin", "ad_cache", "plugin_hack", "ad_inject",
    "data_modify", "crack_data", "modify_logs", "crack_cache", "data_hack",
    "tool_residue", "illegal_backup", "hack_residue", "backup_crack", "tool_cache"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 广告拦截关键词黑名单
static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat", "adtrack",
    "adservice", "adplugin", "admodule", "adlibrary", "adloader"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// 函数原型声明（无隐含声明，避免编译警告）
static int is_whitelisted(const char *path);
static int is_blocked_path(const char *path);
static int is_ad_blocked(const char *path);
static int can_block(const char *path);
static void before_mkdirat(hook_fargs4_t *args, void *udata);
static void before_chdir(hook_fargs1_t *args, void *udata);
static void before_rmdir(hook_fargs1_t *args, void *udata);
static void before_unlinkat(hook_fargs4_t *args, void *udata);
static void before_openat(hook_fargs5_t *args, void *udata);
static void before_renameat(hook_fargs4_t *args, void *udata);
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved);
static long hma_control0(const char *args, char *__user out_msg, int outlen);
static long hma_control1(void *a1, void *a2, void *a3);
static long mkdir_hook_exit(void *__user reserved);

// 1. 白名单校验（优先放行）
static int is_whitelisted(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    const char *data_prefix = "/data/data/";
    const char *android_data_prefix = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    if (strstr(path, data_prefix)) {
        pkg_start = path + strlen(data_prefix);
    } else if (strstr(path, android_data_prefix)) {
        pkg_start = path + strlen(android_data_prefix);
    } else {
        return (strstr(path, "/system/") || strstr(path, "/vendor/") || strstr(path, "/oem/")) ? 1 : 0;
    }

    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    for (size_t j = 0; j < WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, whitelist[j]) == 0) return 1;
    }
    return 0;
}

// 2. 风险路径判断
static int is_blocked_path(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    char target_buf[MAX_PACKAGE_LEN] = {0};
    const char *pkg_start = NULL;

    if (strstr(path, "/data/data/")) {
        pkg_start = path + strlen("/data/data/");
    } else if (strstr(path, "/storage/emulated/0/Android/data/")) {
        pkg_start = path + strlen("/storage/emulated/0/Android/data/");
    } else {
        const char *last_slash = strrchr(path, PATH_SEPARATOR);
        pkg_start = last_slash && *(last_slash + 1) ? last_slash + 1 : path;
    }

    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        target_buf[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    for (size_t j = 0; j < DENY_LIST_SIZE; j++) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (size_t k = 0; k < DENY_FOLDER_SIZE; k++) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// 3. 广告拦截判断
static int is_ad_blocked(const char *path) {
    if (!hma_ad_enabled || !path) return 0;

    char lower_path[PATH_MAX];
    strncpy(lower_path, path, PATH_MAX - 1);
    lower_path[PATH_MAX - 1] = '\0';

    for (char *s = lower_path; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') *s += 32;
    }

    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i])) return 1;
    }
    return 0;
}

// 核心：包级2分钟检测间隔控制（无额外依赖）
static int can_block(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    // 提取包名（复用路径解析逻辑，无冗余）
    const char *data_prefix = "/data/data/";
    const char *android_data_prefix = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    if (strstr(path, data_prefix)) {
        pkg_start = path + strlen(data_prefix);
    } else if (strstr(path, android_data_prefix)) {
        pkg_start = path + strlen(android_data_prefix);
    } else {
        return 0; // 非应用路径无需间隔控制
    }

    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    // 白名单包直接放行（跳过间隔判断）
    for (size_t j = 0; j < WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, whitelist[j]) == 0) return 0;
    }

    // 包名哈希映射（低开销，无内存依赖）
    unsigned long hash = 0;
    for (i = 0; pkg_name[i]; i++) {
        hash = (hash * 31) + pkg_name[i];
    }
    unsigned long pkg_index = hash % MAX_PACKAGE_LEN;

    // 内核原生时间戳（jiffies无额外头文件依赖）
    unsigned long current_time = jiffies;
    unsigned long time_diff = current_time - last_blocked_time[pkg_index];

    // 间隔≥2分钟则允许拦截，并更新最后拦截时间
    if (time_diff >= INTERVAL) {
        last_blocked_time[pkg_index] = current_time;
        return 1;
    }
    return 0;
}

// 核心拦截钩子（集成间隔控制）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0 || is_whitelisted(path)) return;
    path[len] = '\0';
    if ((is_blocked_path(path) || is_ad_blocked(path)) && can_block(path)) {
        pr_warn("[HMA++] mkdirat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

static void before_chdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0 || is_whitelisted(path)) return;
    path[len] = '\0';
    if ((is_blocked_path(path) || is_ad_blocked(path)) && can_block(path)) {
        pr_warn("[HMA++] chdir deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

#if defined(__NR_rmdir)
static void before_rmdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0 || is_whitelisted(path)) return;
    path[len] = '\0';
    if ((is_blocked_path(path) || is_ad_blocked(path)) && can_block(path)) {
        pr_warn("[HMA++] rmdir deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#if defined(__NR_unlinkat)
static void before_unlinkat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0 || is_whitelisted(path)) return;
    path[len] = '\0';
    if ((is_blocked_path(path) || is_ad_blocked(path)) && can_block(path)) {
        pr_warn("[HMA++] unlinkat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#ifdef __NR_openat
static void before_openat(hook_fargs5_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0 || is_whitelisted(path)) return;
    path[len] = '\0';
    if ((is_blocked_path(path) || is_ad_blocked(path)) && can_block(path)) {
        pr_warn("[HMA++] openat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#ifdef __NR_renameat
static void before_renameat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char old_path[PATH_MAX], new_path[PATH_MAX];
    long len_old = compat_strncpy_from_user(old_path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    long len_new = compat_strncpy_from_user(new_path, (void *)syscall_argn(args, 3), PATH_MAX - 1);
    if (len_old <= 0 || len_new <= 0) return;
    old_path[len_old] = '\0';
    new_path[len_new] = '\0';

    if (is_whitelisted(old_path) || is_whitelisted(new_path)) return;

    if ((is_blocked_path(old_path) || is_blocked_path(new_path) || is_ad_blocked(old_path) || is_ad_blocked(new_path)) && can_block(old_path)) {
        pr_warn("[HMA++] renameat deny: %s -> %s\n", old_path, new_path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// 模块生命周期（极简无冗余）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] init start（2分钟检测间隔）\n");

    err = hook_syscalln((int)__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++] hook mkdirat err: %d\n", err); return -EINVAL; }
    err = hook_syscalln((int)__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++] hook chdir err: %d\n", err); return -EINVAL; }
#if defined(__NR_rmdir)
    hook_syscalln((int)__NR_rmdir, 1, before_rmdir, NULL, NULL);
#endif
#if defined(__NR_unlinkat)
    hook_syscalln((int)__NR_unlinkat, 4, before_unlinkat, NULL, NULL);
#endif
#ifdef __NR_openat
    hook_syscalln((int)__NR_openat, 5, before_openat, NULL, NULL);
#endif
#ifdef __NR_renameat
    hook_syscalln((int)__NR_renameat, 4, before_renameat, NULL, NULL);
#endif

    pr_info("[HMA++] init success（global: %d, ad: %d）\n", hma_running, hma_ad_enabled);
    return 0;
}

// 双开关控制接口
static long hma_control0(const char *args, char *__user out_msg, int outlen) {
    char msg[64] = {0};
    if (!args || strlen(args) < 3 || !strchr(args, ARG_SEPARATOR)) {
        strncpy(msg, "args err: use '0/1,0/1' (global,ad)", sizeof(msg)-1);
        goto out_copy;
    }

    char global_arg = args[0];
    char ad_arg = args[2];
    if ((global_arg != '0' && global_arg != '1') || (ad_arg != '0' && ad_arg != '1')) {
        strncpy(msg, "args err: only 0/1 allowed", sizeof(msg)-1);
        goto out_copy;
    }

    hma_running = (global_arg == '1');
    hma_ad_enabled = (ad_arg == '1');
    snprintf(msg, sizeof(msg)-1, "global: %s, ad: %s",
             hma_running ? "enabled" : "disabled",
             hma_ad_enabled ? "enabled" : "disabled");

out_copy:
    if (outlen >= strlen(msg) + 1) {
        compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

// 预留控制接口
static long hma_control1(void *a1, void *a2, void *a3) {
    return 0;
}

// 模块退出（解钩干净）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++] exit start\n");
    unhook_syscalln((int)__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln((int)__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln((int)__NR_rmdir, before_rmdir, NULL);
#endif
#if defined(__NR_unlinkat)
    unhook_syscalln((int)__NR_unlinkat, before_unlinkat, NULL);
#endif
#ifdef __NR_openat
    unhook_syscalln((int)__NR_openat, before_openat, NULL);
#endif
#ifdef __NR_renameat
    unhook_syscalln((int)__NR_renameat, before_renameat, NULL);
#endif
    pr_info("[HMA++] exit success\n");
    return 0;
}

// KPM标准注册
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
