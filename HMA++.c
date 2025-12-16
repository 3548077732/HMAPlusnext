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

// 模块元信息
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.10");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("全应用风险+广告拦截（含微信/QQ/银行/系统软件白名单）");

// 核心宏定义（移除路径限制，适配所有应用）
#define MAX_PACKAGE_LEN 576
#define ARG_SEPARATOR ','
#define PATH_SEPARATOR '/'

// 全局开关（双开关设计，保持极简）
static bool hma_running = true;        // 总开关
static bool hma_ad_enabled = true;     // 广告拦截独立开关

// 核心白名单（QQ/微信/系统软件/常用银行等，白名单内应用不受风险拦截限制）
static const char *whitelist[] = {
    "com.tencent.mm", "com.tencent.mobileqq", "com.tencent.minihd.qq", "com.tencent.wework",
    // 系统基础软件
    "com.android.systemui", "com.android.settings", "com.android.phone", "com.android.contacts",
    "com.android.mms", "com.android.launcher3", "com.android.packageinstaller",
    // 常用银行软件
    "com.icbc.mobilebank", "com.ccb.ccbphone", "com.abchina.mobilebank", "com.cmbchina.psbc",
    "com.cmbchina", "com.bankcomm", "com.spdb.mobilebank", "com.hxb.android",
    "com.cib.mobilebank", "com.pingan.bank", "com.abcwealth.mobile", "com.eg.android.AlipayGphone",
    "com.unionpay",
    // 厂商系统应用
    "com.xiaomi.misettings", "com.huawei.systemmanager", "com.oppo.launcher", "com.vivo.launcher",
    "com.samsung.android.launcher", "com.meizu.flyme.launcher", "me.bmax.apatch", "com.larus.nova",
    "com.miui.home", "com.sukisu.ultra",
    // 原风险名单（用户添加的白名单，不受风险拦截）
    "com.silverlab.app.deviceidchanger.free", "me.bingyue.IceCore", "com.modify.installer", "o.dyoo",
    "com.zhufucdev.motion_emulator", "com.xiaomi.shop", "com.demo.serendipity", "me.iacn.biliroaming",
    "me.teble.xposed.autodaily", "com.example.ourom", "dialog.box", "tornaco.apps.shortx",
    "moe.fuqiuluo.portal", "com.github.tianma8023.xposed.smscode", "moe.shizuku.privileged.api",
    "lin.xposed", "com.lerist.fakelocation", "com.yxer.packageinstalles", "bin.mt.plus.canary",
    "web1n.stopapp", "Hook.JiuWu.Xp", "com.taobao.taobao", "com.houvven.guise",
    "com.xayah.databackup.foss", "github.tornaco.android.thanos", "nep.timeline.freezer",
    "cn.geektang.privacyspace", "com.byyoung.setting", "cn.myflv.noactive", "com.junge.algorithmAidePro",
    "bin.mt.termex", "tmgp.atlas.toolbox", "com.wn.app.np", "icu.nullptr.nativetest",
    "ru.maximoff.apktool", "top.bienvenido.saas.i18n", "com.syyf.quickpay", "tornaco.apps.shortx.ext",
    "com.mio.kitchen", "eu.faircode.xlua", "com.dna.tools", "cn.myflv.monitor.noactive",
    "com.yuanwofei.cardemulator.pro", "com.termux", "com.suqi8.oshin", "me.hd.wauxv", "have.fun",
    "miko.client", "com.kooritea.fcmfix", "com.twifucker.hachidori", "com.luckyzyx.luckytool",
    "com.padi.hook.hookqq", "cn.lyric.getter", "com.parallelc.micts", "me.plusne",
    "com.hchen.appretention", "com.hchen.switchfreeform", "name.monwf.customiuizer", "com.houvven.impad",
    "cn.aodlyric.xiaowine", "top.sacz.timtool", "nep.timeline.re_telegram", "com.fuck.android.rimet",
    "cn.kwaiching.hook", "cn.android.x", "cc.aoeiuv020.iamnotdisabled.hook", "vn.kwaiching.tao",
    "com.nnnen.plusne", "com.fkzhang.wechatxposed", "one.yufz.hmspush", "cn.fuckhome.xiaowine",
    "com.fankes.tsbattery", "com.rifsxd.ksunext", "com.rkg.IAMRKG", "me.gm.cleaner",
    "com.ddm.qute", "kk.dk.anqu", "com.qq.qcxm", "dknb.con", "dknb.coo8",
    "com.tencent.jingshi", "com.tencent.JYNB", "com.apocalua.run", "com.coderstory.toolkit",
    "com.didjdk.adbhelper", "io.github.Retmon403.oppotheme", "com.fankes.enforcehighrefreshrate",
    "es.chiteroman.bootloaderspoofer", "com.hchai.rescueplan", "io.github.chipppppppppp.lime",
    "dev.device.emulator", "com.github.dan.NoStorageRestrict", "com.android1500.androidfaker",
    "com.smartpack.kernelmanager", "ps.reso.instaeclipse", "top.ltfan.notdeveloper", "com.rel.languager",
    "not.val.cheat", "com.haobammmm", "bin.mt.plus", "com.tencent.tmgp.dfm",
    "com.miHoYo.hkrpg", "com.tencent.tmgp.sgame", "com.ss.android.lark.dahx258", "com.omarea.vtools"
};
#define WHITELIST_SIZE (sizeof(whitelist)/sizeof(whitelist[0]))

// 风险文件夹黑名单（仅对白名单外应用生效）
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

// 广告拦截黑名单（对所有应用生效，包括白名单内）
static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat", "adtrack",
    "adservice", "adplugin", "admodule", "adlibrary", "adloader"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// 核心工具函数（关键调整：风险拦截仅对白名单外应用生效）
// 1. 白名单校验（优先放行核心应用）
static int is_whitelisted(const char *path) {
    if (!path || *path != PATH_SEPARATOR) return 0;

    // 提取包名（适配 /data/data/包名/... 或 /storage/emulated/0/Android/data/包名/... 路径）
    const char *data_prefix = "/data/data/";
    const char *android_data_prefix = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    if (strstr(path, data_prefix)) {
        pkg_start = path + strlen(data_prefix);
    } else if (strstr(path, android_data_prefix)) {
        pkg_start = path + strlen(android_data_prefix);
    } else {
        // 系统路径直接放行（不受风险拦截）
        return (strstr(path, "/system/") || strstr(path, "/vendor/") || strstr(path, "/oem/")) ? 1 : 0;
    }

    // 提取包名字符串
    char pkg_name[MAX_PACKAGE_LEN] = {0};
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    if (i == 0) return 0;

    // 白名单匹配：命中则放行（不受风险拦截）
    for (size_t j = 0; j < WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, whitelist[j]) == 0) {
            return 1;
        }
    }
    return 0;
}

// 2. 风险路径判断（核心调整：仅对白名单外应用生效）
static int is_blocked_path(const char *path) {
    // 白名单内应用/系统路径：直接放行，不触发风险拦截
    if (is_whitelisted(path)) return 0;

    if (!path || *path != PATH_SEPARATOR) return 0;

    // 提取路径中的文件夹名（匹配风险文件夹）
    char target_buf[MAX_PACKAGE_LEN] = {0};
    const char *last_slash = strrchr(path, PATH_SEPARATOR);
    if (!last_slash || !*(last_slash + 1)) return 0;

    // 提取最后一级文件夹名（如 "/data/test/xposed_temp" → "xposed_temp"）
    const char *folder_name = last_slash + 1;
    size_t i = 0;
    while (folder_name[i] && folder_name[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        target_buf[i] = folder_name[i];
        i++;
    }
    if (i == 0) return 0;

    // 风险文件夹匹配（仅对白名单外应用生效）
    for (size_t k = 0; k < DENY_FOLDER_SIZE; k++) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) {
            return 1;
        }
    }
    return 0;
}

// 3. 广告拦截判断（对所有应用生效，保持不变）
static int is_ad_blocked(const char *path) {
    if (!hma_ad_enabled || !path) return 0;

    char lower_path[PATH_MAX];
    strncpy(lower_path, path, PATH_MAX - 1);
    lower_path[PATH_MAX - 1] = '\0';

    // 转小写匹配
    for (char *s = lower_path; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') {
            *s += 32;
        }
    }

    // 广告关键词匹配（所有应用均拦截）
    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// 核心拦截钩子（逻辑：白名单外应用+风险路径 → 拦截；所有应用+广告路径 → 拦截）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    
    // 拦截条件：白名单外应用触发风险路径，或所有应用触发广告路径
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] mkdirat deny: %s (白名单外应用风险拦截/广告拦截)\n", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

static void before_chdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] chdir deny: %s (白名单外应用风险拦截/广告拦截)\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

#if defined(__NR_rmdir)
static void before_rmdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] rmdir deny: %s (白名单外应用风险拦截/广告拦截)\n", path);
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
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] unlinkat deny: %s (白名单外应用风险拦截/广告拦截)\n", path);
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
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] openat deny: %s (白名单外应用风险拦截/广告拦截)\n", path);
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

    // 任一路径触发拦截条件即拦截
    if (is_blocked_path(old_path) || is_blocked_path(new_path) || is_ad_blocked(old_path) || is_ad_blocked(new_path)) {
        pr_warn("[HMA++] renameat deny: %s -> %s (白名单外应用风险拦截/广告拦截)\n", old_path, new_path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// 模块生命周期（保持极简）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] init start (风险拦截仅对白名单外应用生效)\n");

    // 挂钩核心文件操作syscall
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++] hook mkdirat err: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++] hook chdir err: %d\n", err); return -EINVAL; }
#if defined(__NR_rmdir)
    hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#endif
#if defined(__NR_unlinkat)
    hook_syscalln(__NR_unlinkat, 4, before_unlinkat, NULL, NULL);
#endif
#ifdef __NR_openat
    hook_syscalln(__NR_openat, 5, before_openat, NULL, NULL);
#endif
#ifdef __NR_renameat
    hook_syscalln(__NR_renameat, 4, before_renameat, NULL, NULL);
#endif

    pr_info("[HMA++] init success (global: %d, ad: %d) - 白名单内应用不受风险拦截限制\n", hma_running, hma_ad_enabled);
    return 0;
}

// 启停控制（双开关参数："总开关,广告开关" 如 "1,1"）
static long hma_control0(const char *args, char *__user out_msg, int outlen) {
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
    snprintf(msg, sizeof(msg)-1, "global: %s, ad: %s (风险仅拦截白名单外应用)",
             hma_running ? "enabled" : "disabled",
             hma_ad_enabled ? "enabled" : "disabled");

out_copy:
    if (outlen >= strlen(msg) + 1) {
        compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

// 预留控制接口（极简实现）
static long hma_control1(void *a1, void *a2, void *a3) {
    return 0;
}

// 模块退出（极简解钩）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++] exit start\n");
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#endif
#if defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_unlinkat, NULL);
#endif
#ifdef __NR_openat
    unhook_syscalln(__NR_openat, before_openat, NULL);
#endif
#ifdef __NR_renameat
    unhook_syscalln(__NR_renameat, before_renameat, NULL);
#endif
    pr_info("[HMA++] exit success\n");
    return 0;
}

// 模块注册（符合KPM规范）
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
