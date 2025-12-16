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

// ====================== KPM 标准元信息（仅保留框架支持的宏） ======================
#define MODULE_NAME "HMA_Next"  // 统一模块名称定义
KPM_NAME(MODULE_NAME);
KPM_VERSION("1.0.17");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("Apatch专属：全应用风险+广告拦截（含微信/QQ/银行/系统白名单）");

#define MAX_PACKAGE_LEN 256
#define ARG_SEPARATOR ','
#define PATH_SEPARATOR '/'
#define HZ 100
#define INTERVAL 2 * 60 * HZ
#define APATCH_KPM_PROC_PATH "/proc/apatch/kpm/" MODULE_NAME  // 动态拼接路径

// ====================== 内核符号声明（与头文件保持一致，修复冲突） ======================
extern unsigned long long get_jiffies_64(void);
extern unsigned long jiffies;
// 修正hook_syscalln/unhook_syscalln声明：与syscall.h头文件类型一致
extern hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
extern void unhook_syscalln(int nr, void *before, void *after);

// ====================== 全局变量 ======================
static bool hma_running = true;
static bool hma_ad_enabled = true;
static unsigned long last_blocked_time[MAX_PACKAGE_LEN] = {0};

// ====================== 函数原型声明 ======================
static char *get_package_name(const char *path);
static int is_whitelisted(const char *path);
static int is_blocked_path(const char *path);
static int is_ad_blocked(const char *path);
static int can_block(const char *path);
static long hma_apatch_init(const char *args, const char *event, void *__user reserved);
static long hma_apatch_control(const char *args, char *__user out_msg, int outlen);
static long hma_apatch_exit(void *__user reserved);

// ====================== 白名单/黑名单（保持不变） ======================
static const char *whitelist[] = {
    "me.bmax.apatch",
    "com.tencent.mm", "com.tencent.mobileqq", "com.tencent.minihd.qq", "com.tencent.wework",
    "com.android.systemui", "com.android.settings", "com.android.phone", "com.android.contacts",
    "com.android.mms", "com.android.launcher3", "com.android.packageinstaller",
    "com.android.server", "com.android.providers.settings", "com.android.providers.media",
    "com.icbc.mobilebank", "com.ccb.ccbphone", "com.abchina.mobilebank", "com.cmbchina.psbc",
    "com.cmbchina", "com.bankcomm", "com.spdb.mobilebank", "com.hxb.android",
    "com.cib.mobilebank", "com.pingan.bank", "com.abcwealth.mobile", "com.eg.android.AlipayGphone",
    "com.unionpay", "com.tencent.mobilepayment",
    "com.xiaomi.misettings", "com.huawei.systemmanager", "com.oppo.launcher", "com.vivo.launcher",
    "com.samsung.android.launcher", "com.meizu.flyme.launcher", "com.miui.home",
    "com.sukisu.ultra", "com.larus.nova", "com.oneplus.launcher", "com.realme.launcher"
};
#define WHITELIST_SIZE (sizeof(whitelist)/sizeof(whitelist[0]))

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

static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat", "adtrack",
    "adservice", "adplugin", "admodule", "adlibrary", "adloader", "ad_sdk", "adcore"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// ====================== 核心工具函数（修复get_jiffies_64警告） ======================
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
        return (strstr(path, "/system/") || strstr(path, "/vendor/") || strstr(path, "/oem/") || strstr(path, "/apex/")) ? 1 : 0;
    }

    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    for (size_t j = 0; j < WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, whitelist[j]) == 0) {
            return 1;
        }
    }
    return 0;
}

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
        if (last_slash && *(last_slash + 1)) {
            pkg_start = last_slash + 1;
        } else {
            return 0;
        }
    }

    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        target_buf[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    for (size_t j = 0; j < DENY_LIST_SIZE; j++) {
        if (strcmp(target_buf, deny_list[j]) == 0) {
            return 1;
        }
    }
    for (size_t k = 0; k < DENY_FOLDER_SIZE; k++) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_ad_blocked(const char *path) {
    if (!hma_ad_enabled || !path) return 0;

    char lower_path[PATH_MAX];
    strncpy(lower_path, path, PATH_MAX - 1);
    lower_path[PATH_MAX - 1] = '\0';

    for (char *s = lower_path; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') {
            *s += 32;
        }
    }

    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

static int can_block(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    const char *data_prefix = "/data/data/";
    const char *android_data_prefix = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    if (strstr(path, data_prefix)) {
        pkg_start = path + strlen(data_prefix);
    } else if (strstr(path, android_data_prefix)) {
        pkg_start = path + strlen(android_data_prefix);
    } else {
        return 0;
    }

    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    for (size_t j = 0; j < WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, whitelist[j]) == 0) {
            return 0;
        }
    }

    unsigned long hash = 0;
    for (i = 0; pkg_name[i]; i++) {
        hash = (hash * 31) + pkg_name[i];
    }

    // 修复警告：移除get_jiffies_64地址判断（内核函数地址非NULL），直接使用并降级
    unsigned long current_time;
#if IS_ENABLED(CONFIG_GENERIC_TIME)
    current_time = (unsigned long)get_jiffies_64();
#else
    current_time = jiffies;
#endif

    unsigned long time_diff = current_time - last_blocked_time[hash % MAX_PACKAGE_LEN];
    if (time_diff >= INTERVAL) {
        last_blocked_time[hash % MAX_PACKAGE_LEN] = current_time;
        return 1;
    }
    return 0;
}

// ====================== 核心拦截钩子（保持不变） ======================
static void __used before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';

    if (is_whitelisted(path)) return;

    int should_block = (is_blocked_path(path) || is_ad_blocked(path)) ? 1 : 0;
    if (should_block && can_block(path)) {
        pr_warn("[%s/Apatch] mkdirat deny: %s (pkg: %s)\n", MODULE_NAME, path, get_package_name(path));
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

static void __used before_chdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';

    if (is_whitelisted(path)) return;

    int should_block = (is_blocked_path(path) || is_ad_blocked(path)) ? 1 : 0;
    if (should_block && can_block(path)) {
        pr_warn("[%s/Apatch] chdir deny: %s (pkg: %s)\n", MODULE_NAME, path, get_package_name(path));
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

#if defined(__NR_openat)
static void __used before_openat(hook_fargs5_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';

    if (is_whitelisted(path)) return;

    int should_block = (is_blocked_path(path) || is_ad_blocked(path)) ? 1 : 0;
    if (should_block && can_block(path)) {
        pr_warn("[%s/Apatch] openat deny: %s (pkg: %s)\n", MODULE_NAME, path, get_package_name(path));
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#if defined(__NR_unlinkat)
static void __used before_unlinkat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';

    if (is_whitelisted(path)) return;

    int should_block = (is_blocked_path(path) || is_ad_blocked(path)) ? 1 : 0;
    if (should_block && can_block(path)) {
        pr_warn("[%s/Apatch] unlinkat deny: %s (pkg: %s)\n", MODULE_NAME, path, get_package_name(path));
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// ====================== 辅助函数（保持不变） ======================
static char *get_package_name(const char *path) {
    static char pkg_name[MAX_PACKAGE_LEN] = {0};
    memset(pkg_name, 0, sizeof(pkg_name));

    const char *data_prefix = "/data/data/";
    const char *android_data_prefix = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    if (strstr(path, data_prefix)) {
        pkg_start = path + strlen(data_prefix);
    } else if (strstr(path, android_data_prefix)) {
        pkg_start = path + strlen(android_data_prefix);
    } else {
        return pkg_name;
    }

    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    return pkg_name;
}

// ====================== 模块生命周期函数（修复syscall参数类型） ======================
static long __used hma_apatch_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[%s/Apatch] init start (Apatch >=0.5.0 compatible)\n", MODULE_NAME);

    // 修复syscall号类型：与hook_syscalln声明一致（int类型）
    if ((int)__NR_mkdirat <= 0 || (int)__NR_chdir <= 0) {
        pr_err("[%s/Apatch] invalid syscall number (Android kernel not compatible)\n", MODULE_NAME);
        return -EINVAL;
    }

    // 修复参数类型：使用void*强制转换，与头文件一致
    err = hook_syscalln((int)__NR_mkdirat, 3, (void *)before_mkdirat, NULL, NULL);
    if (err) {
        pr_err("[%s/Apatch] hook mkdirat err: %d\n", MODULE_NAME, err);
        return -EINVAL;
    }

    err = hook_syscalln((int)__NR_chdir, 1, (void *)before_chdir, NULL, NULL);
    if (err) {
        pr_err("[%s/Apatch] hook chdir err: %d\n", MODULE_NAME, err);
        unhook_syscalln((int)__NR_mkdirat, (void *)before_mkdirat, NULL);
        return -EINVAL;
    }

#if defined(__NR_openat)
    err = hook_syscalln((int)__NR_openat, 5, (void *)before_openat, NULL, NULL);
    if (err) {
        pr_err("[%s/Apatch] hook openat err: %d\n", MODULE_NAME, err);
        unhook_syscalln((int)__NR_mkdirat, (void *)before_mkdirat, NULL);
        unhook_syscalln((int)__NR_chdir, (void *)before_chdir, NULL);
        return -EINVAL;
    }
#endif

#if defined(__NR_unlinkat)
    err = hook_syscalln((int)__NR_unlinkat, 4, (void *)before_unlinkat, NULL, NULL);
    if (err) {
        pr_err("[%s/Apatch] hook unlinkat err: %d\n", MODULE_NAME, err);
        unhook_syscalln((int)__NR_mkdirat, (void *)before_mkdirat, NULL);
        unhook_syscalln((int)__NR_chdir, (void *)before_chdir, NULL);
#if defined(__NR_openat)
        unhook_syscalln((int)__NR_openat, (void *)before_openat, NULL);
#endif
        return -EINVAL;
    }
#endif

    pr_info("[%s/Apatch] init success (global: %d, ad: %d, interval: %ds)\n",
            MODULE_NAME, hma_running, hma_ad_enabled, INTERVAL / HZ);
    pr_info("[%s/Apatch] control path: %s\n", MODULE_NAME, APATCH_KPM_PROC_PATH);
    return 0;
}

static long __used hma_apatch_control(const char *args, char *__user out_msg, int outlen) {
    char msg[64] = {0};
    if (!args || strlen(args) < 3 || strchr(args, ARG_SEPARATOR) == NULL) {
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
    snprintf(msg, sizeof(msg)-1, "Apatch %s: global=%s, ad=%s",
             MODULE_NAME, hma_running ? "on" : "off",
             hma_ad_enabled ? "on" : "off");

out_copy:
    if (outlen >= strlen(msg) + 1) {
        compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

static long __used hma_apatch_exit(void *__user reserved) {
    pr_info("[%s/Apatch] exit start\n", MODULE_NAME);
    unhook_syscalln((int)__NR_mkdirat, (void *)before_mkdirat, NULL);
    unhook_syscalln((int)__NR_chdir, (void *)before_chdir, NULL);
#if defined(__NR_openat)
    unhook_syscalln((int)__NR_openat, (void *)before_openat, NULL);
#endif
#if defined(__NR_unlinkat)
    unhook_syscalln((int)__NR_unlinkat, (void *)before_unlinkat, NULL);
#endif
    pr_info("[%s/Apatch] exit success\n", MODULE_NAME);
    return 0;
}

// ====================== 模块注册 ======================
KPM_INIT(hma_apatch_init);
KPM_CTL0(hma_apatch_control);
KPM_EXIT(hma_apatch_exit);
