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

// 1. 避免头文件冲突（优先定义__user）
#ifndef __user
#define __user
#endif

// 2. 弱引用KPM核心符号（缺失不崩溃，加载时检测）
extern hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata) __attribute__((weak));
extern void unhook_syscalln(int nr, void *before, void *after) __attribute__((weak));
extern long compat_strncpy_from_user(char __user *dest, const char *src, long count) __attribute__((weak));
extern int compat_copy_to_user(void __user *to, const void *from, int n) __attribute__((weak));

// 3. 定义syscall号默认值（无此syscall时跳过挂钩）
#ifndef __NR_mkdirat
#define __NR_mkdirat -1
#endif
#ifndef __NR_chdir
#define __NR_chdir -1
#endif

// 4. 强制日志定义（所有内核可见，避免日志缺失）
#ifndef pr_info
#define pr_info(fmt, ...) printk(KERN_INFO "[HMA++] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef pr_err
#define pr_err(fmt, ...) printk(KERN_ERR "[HMA++] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef pr_warn
#define pr_warn(fmt, ...) printk(KERN_WARN "[HMA++] " fmt "\n", ##__VA_ARGS__)
#endif

// 模块元信息（与打包脚本版本严格一致）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.10");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("风险拦截仅对白名单外应用生效（强兼容加载版）");

// 核心宏定义
#define MAX_PACKAGE_LEN 256
#define ARG_SEPARATOR ','
#define PATH_SEPARATOR '/'

// 全局开关
static bool hma_running = true;
static bool hma_ad_enabled = true;

// 核心白名单（保留用户所有配置）
static const char *whitelist[] = {
    "com.tencent.mm", "com.tencent.mobileqq", "com.tencent.minihd.qq", "com.tencent.wework",
    "com.android.systemui", "com.android.settings", "com.android.phone", "com.android.contacts",
    "com.android.mms", "com.android.launcher3", "com.android.packageinstaller",
    "com.icbc.mobilebank", "com.ccb.ccbphone", "com.abchina.mobilebank", "com.cmbchina.psbc",
    "com.cmbchina", "com.bankcomm", "com.spdb.mobilebank", "com.hxb.android",
    "com.cib.mobilebank", "com.pingan.bank", "com.abcwealth.mobile", "com.eg.android.AlipayGphone",
    "com.unionpay",
    "com.xiaomi.misettings", "com.huawei.systemmanager", "com.oppo.launcher", "com.vivo.launcher",
    "com.samsung.android.launcher", "com.meizu.flyme.launcher", "me.bmax.apatch", "com.larus.nova",
    "com.miui.home", "com.sukisu.ultra",
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

// 广告拦截黑名单（对所有应用生效）
static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat", "adtrack",
    "adservice", "adplugin", "admodule", "adlibrary", "adloader", "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp",
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
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// 核心工具函数（添加符号存在性检测）
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
        if (strcmp(pkg_name, whitelist[j]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_blocked_path(const char *path) {
    if (is_whitelisted(path)) return 0;
    if (!path || *path != PATH_SEPARATOR) return 0;

    char target_buf[MAX_PACKAGE_LEN] = {0};
    const char *last_slash = strrchr(path, PATH_SEPARATOR);
    if (!last_slash || !*(last_slash + 1)) return 0;

    const char *folder_name = last_slash + 1;
    size_t i = 0;
    while (folder_name[i] && folder_name[i] != PATH_SEPARATOR && i < MAX_PACKAGE_LEN - 1) {
        target_buf[i] = folder_name[i];
        i++;
    }
    if (i == 0) return 0;

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

// 核心拦截钩子（仅保留2个核心syscall，减少冲突）
static void __used before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running || !compat_strncpy_from_user) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("mkdirat deny: %s", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

static void __used before_chdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running || !compat_strncpy_from_user) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("chdir deny: %s", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 模块初始化（核心：符号检测+仅挂钩有效syscall）
static long __used mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    pr_info("===== 初始化开始（强兼容加载版） =====");

    // 关键：检测所有依赖符号（缺失直接提示，不崩溃）
    if (!hook_syscalln) {
        pr_err("加载失败：KPM未导出hook_syscalln符号！请升级KPM到1.1.0+");
        return -EINVAL;
    }
    if (!compat_strncpy_from_user) {
        pr_err("加载失败：KPM未导出compat_strncpy_from_user符号！");
        return -EINVAL;
    }
    if (__NR_mkdirat <= 0) {
        pr_err("加载失败：内核无__NR_mkdirat系统调用！");
        return -EINVAL;
    }
    if (__NR_chdir <= 0) {
        pr_err("加载失败：内核无__NR_chdir系统调用！");
        return -EINVAL;
    }

    // 仅挂钩2个核心syscall（减少加载冲突）
    hook_err_t err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) {
        pr_err("挂钩mkdirat失败：err=%d（可能syscall号不匹配）", err);
        return -EINVAL;
    }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) {
        pr_err("挂钩chdir失败：err=%d（可能syscall号不匹配）", err);
        return -EINVAL;
    }

    pr_info("初始化成功！全局拦截：%s，广告拦截：%s",
            hma_running ? "开启" : "关闭", hma_ad_enabled ? "开启" : "关闭");
    return 0;
}

// 控制接口（添加符号存在性检测）
static long __used hma_control0(const char *args, char *__user out_msg, int outlen) {
    char msg[64] = "参数错误：使用'0/1,0/1'（全局,广告）";
    if (args && strlen(args) >= 3 && strchr(args, ARG_SEPARATOR)) {
        char global_arg = args[0];
        char ad_arg = args[2];
        if ((global_arg == '0' || global_arg == '1') && (ad_arg == '0' || ad_arg == '1')) {
            hma_running = (global_arg == '1');
            hma_ad_enabled = (ad_arg == '1');
            snprintf(msg, sizeof(msg)-1, "全局：%s，广告：%s",
                     hma_running ? "开启" : "关闭", hma_ad_enabled ? "开启" : "关闭");
        }
    }

    if (outlen >= strlen(msg) + 1 && compat_copy_to_user) {
        compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

static long __used hma_control1(void *a1, void *a2, void *a3) {
    return 0;
}

// 模块退出（安全解钩）
static long __used mkdir_hook_exit(void *__user reserved) {
    pr_info("===== 退出模块 =====");
    if (hook_syscalln && __NR_mkdirat > 0) {
        unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    }
    if (hook_syscalln && __NR_chdir > 0) {
        unhook_syscalln(__NR_chdir, before_chdir, NULL);
    }
    pr_info("退出成功");
    return 0;
}

// KPM注册（确保宏无语法错误）
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
