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

// ====================== Apatch KPM 强制元信息 ======================
KPM_NAME("HMA_Next");                  // 模块名称（无特殊字符，Apatch强制要求）
KPM_VERSION("1.0.14");                 // 版本号（Apatch版本管理要求）
KPM_LICENSE("GPLv3");                  // 许可证（Apatch兼容GPLv3）
KPM_AUTHOR("NightFallsLikeRain");      // 作者信息
KPM_DESCRIPTION("全应用风险+广告拦截（含微信/QQ/银行/系统白名单）");
KPM_PLATFORM("Android");               // 平台标识（Apatch强制指定为Android）
KPM_DEPENDS("apatch >= 0.5.0");        // 依赖Apatch版本（最低支持0.5.0，Apatch要求）
KPM_RELEASE_DATE("2025-12-16");        // 发布日期（Apatch元信息规范）

// ====================== 核心宏定义（Apatch Android适配） ======================
#define MAX_PACKAGE_LEN 256               // 适配Android包名长度（最长128字符，留冗余）
#define ARG_SEPARATOR ','
#define PATH_SEPARATOR '/'
#define HZ 100                           // Android内核默认HZ=100，无需修改
#define INTERVAL 2 * 60 * HZ             // 2分钟间隔（Apatch推荐的拦截频率）
#define APATCH_KPM_PROC_PATH "/proc/apatch/kpm/HMA_Next" // Apatch标准控制路径

// Apatch兼容的jiffies声明（Android内核专用）
extern unsigned long long get_jiffies_64(void);
extern unsigned long jiffies;

// ====================== 全局变量（Apatch内存规范） ======================
static bool hma_running = true;        // 总开关（默认开启，符合Apatch用户习惯）
static bool hma_ad_enabled = true;     // 广告拦截开关
static unsigned long last_blocked_time[MAX_PACKAGE_LEN] = {0}; // 静态数组初始化（Apatch要求）

// ====================== 函数原型声明（Apatch符号导出要求） ======================
static char *get_package_name(const char *path);
static int is_whitelisted(const char *path);
static int is_blocked_path(const char *path);
static int is_ad_blocked(const char *path);
static int can_block(const char *path);
// 显式声明Apatch导出的KPM接口（避免符号未找到）
extern hook_err_t hook_syscalln(long nr, int argc, void (*before)(void *, void *), void (*after)(void *, void *), void *udata);
extern void unhook_syscalln(long nr, void (*before)(void *, void *), void (*after)(void *, void *));

// ====================== 白名单（Apatch Android专属优化） ======================
static const char *whitelist[] = {
    "me.bmax.apatch",                    // Apatch自身（必加，避免拦截Apatch运行）
    // 微信/QQ 核心应用（Android高频应用，避免误拦）
    "com.tencent.mm", "com.tencent.mobileqq", "com.tencent.minihd.qq", "com.tencent.wework",
    // Android系统核心应用（Apatch禁止拦截系统关键进程）
    "com.android.systemui", "com.android.settings", "com.android.phone", "com.android.contacts",
    "com.android.mms", "com.android.launcher3", "com.android.packageinstaller",
    "com.android.server", "com.android.providers.settings", "com.android.providers.media",
    // 主流银行/支付应用（Android金融类应用白名单）
    "com.icbc.mobilebank", "com.ccb.ccbphone", "com.abchina.mobilebank", "com.cmbchina.psbc",
    "com.cmbchina", "com.bankcomm", "com.spdb.mobilebank", "com.hxb.android",
    "com.cib.mobilebank", "com.pingan.bank", "com.abcwealth.mobile", "com.eg.android.AlipayGphone",
    "com.unionpay", "com.tencent.mobilepayment",
    // 主流厂商系统应用（适配Android各品牌）
    "com.xiaomi.misettings", "com.huawei.systemmanager", "com.oppo.launcher", "com.vivo.launcher",
    "com.samsung.android.launcher", "com.meizu.flyme.launcher", "com.miui.home",
    "com.sukisu.ultra", "com.larus.nova", "com.oneplus.launcher", "com.realme.launcher"
};
#define WHITELIST_SIZE (sizeof(whitelist)/sizeof(whitelist[0]))

// ====================== 黑名单（Android风险应用/路径适配） ======================
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

// ====================== 核心工具函数（Apatch Android兼容优化） ======================
static int is_whitelisted(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    // Android专属路径适配（支持/data/data和/storage/emulated/0/Android/data）
    const char *data_prefix = "/data/data/";
    const char *android_data_prefix = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    if (strstr(path, data_prefix)) {
        pkg_start = path + strlen(data_prefix);
    } else if (strstr(path, android_data_prefix)) {
        pkg_start = path + strlen(android_data_prefix);
    } else {
        // Apatch要求：系统路径（/system//vendor//oem/）直接放行
        return (strstr(path, "/system/") || strstr(path, "/vendor/") || strstr(path, "/oem/") || strstr(path, "/apex/")) ? 1 : 0;
    }

    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    // 白名单匹配（Apatch推荐线性遍历，避免复杂算法占用资源）
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
    // Apatch推荐使用compat_strncpy_from_user，但此处是内核空间字符串，直接拷贝
    strncpy(lower_path, path, PATH_MAX - 1);
    lower_path[PATH_MAX - 1] = '\0';

    // 转小写（适配Android应用路径大小写不统一问题）
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

// Apatch专属jiffies访问（Android内核兼容）
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

    // 白名单应用不拦截
    for (size_t j = 0; j < WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, whitelist[j]) == 0) {
            return 0;
        }
    }

    // 包名哈希（Apatch推荐的简单哈希算法，低开销）
    unsigned long hash = 0;
    for (i = 0; pkg_name[i]; i++) {
        hash = (hash * 31) + pkg_name[i];
    }

    // Android内核优先使用get_jiffies_64（Apatch导出的安全接口）
    unsigned long current_time;
    if (get_jiffies_64) {
        current_time = (unsigned long)get_jiffies_64();
    } else {
        current_time = jiffies;
    }

    unsigned long time_diff = current_time - last_blocked_time[hash % MAX_PACKAGE_LEN];
    if (time_diff >= INTERVAL) {
        last_blocked_time[hash % MAX_PACKAGE_LEN] = current_time;
        return 1;
    }
    return 0;
}


static void __used before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    // Apatch强制使用compat_strncpy_from_user（Android用户空间数据拷贝兼容）
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';

    if (is_whitelisted(path)) return;

    int should_block = (is_blocked_path(path) || is_ad_blocked(path)) ? 1 : 0;
    if (should_block && can_block(path)) {
        pr_warn("[HMA_Next/Apatch] mkdirat deny: %s (pkg: %s)\n", path, get_package_name(path));
        args->skip_origin = 1;
        args->ret = -EACCES; // Android标准权限拒绝码（Apatch推荐）
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
        pr_warn("[HMA_Next/Apatch] chdir deny: %s (pkg: %s)\n", path, get_package_name(path));
        args->skip_origin = 1;
        args->ret = -ENOENT; // Android标准路径不存在码（避免应用崩溃）
    }
}

// 适配Android常用syscall（Apatch推荐挂钩核心文件操作）
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
        pr_warn("[HMA_Next/Apatch] openat deny: %s (pkg: %s)\n", path, get_package_name(path));
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
        pr_warn("[HMA_Next/Apatch] unlinkat deny: %s (pkg: %s)\n", path, get_package_name(path));
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// ====================== 辅助函数（Android包名提取） ======================
static char *get_package_name(const char *path) {
    static char pkg_name[MAX_PACKAGE_LEN] = {0};
    memset(pkg_name, 0, sizeof(pkg_name)); // Apatch要求静态变量每次使用前初始化

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

// ====================== Apatch KPM模块生命周期（强制规范） ======================
// 初始化函数（Apatch要求返回long，参数固定）
static long hma_apatch_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA_Next/Apatch] init start (Apatch %s compatible)\n", KPM_DEPENDS);

    // Apatch要求：挂钩前验证syscall号（Android内核syscall号有效性检查）
    if (__NR_mkdirat <= 0 || __NR_chdir <= 0) {
        pr_err("[HMA_Next/Apatch] invalid syscall number (Android kernel not compatible)\n");
        return -EINVAL;
    }

    // 挂钩核心syscall（Apatch推荐顺序：mkdirat → chdir → openat → unlinkat）
    err = hook_syscalln(__NR_mkdirat, 3, (void *)before_mkdirat, NULL, NULL);
    if (err) {
        pr_err("[HMA_Next/Apatch] hook mkdirat err: %d\n", err);
        return -EINVAL;
    }

    err = hook_syscalln(__NR_chdir, 1, (void *)before_chdir, NULL, NULL);
    if (err) {
        pr_err("[HMA_Next/Apatch] hook chdir err: %d\n", err);
        unhook_syscalln(__NR_mkdirat, (void *)before_mkdirat, NULL);
        return -EINVAL;
    }

#if defined(__NR_openat)
    err = hook_syscalln(__NR_openat, 5, (void *)before_openat, NULL, NULL);
    if (err) {
        pr_err("[HMA_Next/Apatch] hook openat err: %d\n", err);
        unhook_syscalln(__NR_mkdirat, (void *)before_mkdirat, NULL);
        unhook_syscalln(__NR_chdir, (void *)before_chdir, NULL);
        return -EINVAL;
    }
#endif

#if defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, (void *)before_unlinkat, NULL, NULL);
    if (err) {
        pr_err("[HMA_Next/Apatch] hook unlinkat err: %d\n", err);
        unhook_syscalln(__NR_mkdirat, (void *)before_mkdirat, NULL);
        unhook_syscalln(__NR_chdir, (void *)before_chdir, NULL);
#if defined(__NR_openat)
        unhook_syscalln(__NR_openat, (void *)before_openat, NULL);
#endif
        return -EINVAL;
    }
#endif

    pr_info("[HMA_Next/Apatch] init success (global: %d, ad: %d, interval: %ds)\n",
            hma_running, hma_ad_enabled, INTERVAL / HZ);
    return 0;
}

// 控制接口（Apatch procfs规范）
static long hma_apatch_control(const char *args, char *__user out_msg, int outlen) {
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
    snprintf(msg, sizeof(msg)-1, "Apatch HMA_Next: global=%s, ad=%s",
             hma_running ? "on" : "off",
             hma_ad_enabled ? "on" : "off");

out_copy:
    if (outlen >= strlen(msg) + 1) {
        // Apatch强制使用compat_copy_to_user（Android用户空间数据拷贝）
        compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

// 退出函数（Apatch要求解钩所有syscall，避免内存泄漏）
static long hma_apatch_exit(void *__user reserved) {
    pr_info("[HMA_Next/Apatch] exit start\n");
    unhook_syscalln(__NR_mkdirat, (void *)before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, (void *)before_chdir, NULL);
#if defined(__NR_openat)
    unhook_syscalln(__NR_openat, (void *)before_openat, NULL);
#endif
#if defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, (void *)before_unlinkat, NULL);
#endif
    pr_info("[HMA_Next/Apatch] exit success\n");
    return 0;
}

// ====================== Apatch KPM模块注册（强制宏） ======================
// Apatch要求使用KPM_MODULE宏统一注册，参数顺序：init → control → control1 → exit
KPM_MODULE(hma_apatch_init, hma_apatch_control, NULL, hma_apatch_exit);
