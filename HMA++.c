// 第一步：优先定义__user宏（解决KPM头文件冲突）
#ifndef __user
#define __user
#endif

// 仅保留KPM框架必需头文件（新增linux/ctype.h，解决tolower声明问题）
#include <kpmodule.h>
#include <syscall.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <uapi/linux/limits.h>
#include <linux/kernel.h>
#include <linux/ctype.h>  // 关键：内核空间tolower函数声明

// 显式声明KPM/内核符号（弱引用，避免符号缺失直接崩溃）
extern long kf_strncpy_from_user(char *dest, const void __user *src, long count) __attribute__((weak));
extern long kf_copy_to_user(void __user *dest, const void *src, long count) __attribute__((weak));
extern unsigned long jiffies __attribute__((weak));
extern hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata) __attribute__((weak));
extern void unhook_syscalln(int nr, void *before, void *after) __attribute__((weak));

// 强制日志定义（确保旧内核兼容，日志必现）
#ifndef pr_emerg
#define pr_emerg(fmt, ...) printk(KERN_EMERG "[HMA++] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef pr_err
#define pr_err(fmt, ...) printk(KERN_ERR "[HMA++] " fmt "\n", ##__VA_ARGS__)
#endif

// 模块元信息（KPM标准格式，确保识别）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.12");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("全应用风险+广告拦截（含微信/QQ/银行/系统软件白名单）");

// 核心宏定义
#define MAX_PACKAGE_LEN 256
#define ARG_SEPARATOR ','
#define PATH_SEPARATOR '/'
#define HZ 100
#define INTERVAL 2 * 60 * HZ

// 全局变量
static bool hma_running = true;
static bool hma_ad_enabled = true;
static unsigned long last_blocked_time[MAX_PACKAGE_LEN] = {0};

// 白名单（修复：补充缺失的逗号）
static const char *whitelist[] = {
    // 微信/QQ 核心应用
    "com.tencent.mm",          // 微信
    "com.tencent.mobileqq",    // QQ
    "com.tencent.minihd.qq",   // QQ轻量版
    "com.tencent.wework",      // 企业微信
    // 系统基础软件
    "com.android.systemui",    // 系统UI
    "com.android.settings",    // 设置
    "com.android.phone",       // 电话
    "com.android.contacts",    // 联系人
    "com.android.mms",         // 短信
    "com.android.launcher3",   // 桌面启动器（通用）
    "com.android.packageinstaller", // 应用安装器
    // 常用银行软件
    "com.icbc.mobilebank",     // 工商银行
    "com.ccb.ccbphone",        // 建设银行
    "com.abchina.mobilebank",  // 农业银行
    "com.cmbchina.psbc",       // 邮储银行
    "com.cmbchina",            // 招商银行
    "com.bankcomm",            // 交通银行
    "com.spdb.mobilebank",     // 浦发银行
    "com.hxb.android",         // 华夏银行
    "com.cib.mobilebank",      // 兴业银行
    "com.pingan.bank",         // 平安银行
    "com.abcwealth.mobile",    // 农业银行财富版
    "com.eg.android.AlipayGphone", // 支付宝（金融类）
    "com.unionpay",            // 银联
    // 厂商系统应用（兼容主流品牌）
    "com.xiaomi.misettings",   // 小米设置
    "com.huawei.systemmanager",// 华为系统管家
    "com.oppo.launcher",       // OPPO桌面
    "com.vivo.launcher",       // VIVO桌面
    "com.samsung.android.launcher", // 三星桌面
    "com.meizu.flyme.launcher",// 魅族桌面（修复：补充逗号）
    "me.bmax.apatch",          // 修复：补充逗号
    "com.larus.nova",          // 修复：补充逗号
    "com.miui.home",           // 修复：补充逗号
    "com.sukisu.ultra"
};
#define WHITELIST_SIZE (sizeof(whitelist)/sizeof(whitelist[0]))

// 风险/广告黑名单（不变）
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

// 风险文件夹黑名单（全路径匹配）（修复：注释符号改为//）
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

// 广告拦截黑名单（全路径关键词匹配）
static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat", "adtrack",
    "adservice", "adplugin", "admodule", "adlibrary", "adloader"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// 函数原型声明（严格匹配KPM）
static int is_whitelisted(const char *path);
static int is_blocked_path(const char *path);
static int is_ad_blocked(const char *path);
static int can_block(const char *path);
static void before_mkdirat(hook_fargs4_t *args, void *udata);
static void before_chdir(hook_fargs1_t *args, void *udata);
static long mkdir_hook_init(const char *args, const char *event, void *reserved);
static long hma_control0(const char *ctl_args, char *__user out_msg, int outlen);
static long hma_control1(void *a1, void *a2, void *a3);
static long mkdir_hook_exit(void *reserved);

// 辅助函数（修复：is_blocked_path添加deny_folder_list匹配）
static int is_whitelisted(const char *path) {
    if (!path) return 0;
    for (size_t i = 0; i < WHITELIST_SIZE; i++) {
        if (strstr(path, whitelist[i])) return 1;
    }
    return (strstr(path, "/system/") || strstr(path, "/vendor/") || strstr(path, "/oem/")) ? 1 : 0;
}
static int is_blocked_path(const char *path) {
    if (!path) return 0;
    // 匹配风险应用包名
    for (size_t i = 0; i < DENY_LIST_SIZE; i++) {
        if (strstr(path, deny_list[i])) return 1;
    }
    // 匹配风险文件夹（新增：之前遗漏的文件夹黑名单匹配）
    for (size_t i = 0; i < DENY_FOLDER_SIZE; i++) {
        if (strstr(path, deny_folder_list[i])) return 1;
    }
    return 0;
}
static int is_ad_blocked(const char *path) {
    if (!hma_ad_enabled || !path) return 0;
    char lower[PATH_MAX];
    strncpy(lower, path, PATH_MAX-1);
    lower[PATH_MAX-1] = '\0'; // 修复：添加字符串结束符，避免越界
    for (char *s = lower; *s; s++) *s = tolower(*s);
    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower, ad_file_keywords[i])) return 1;
    }
    return 0;
}
static int can_block(const char *path) {
    if (!path || !jiffies) return 0;
    const char *pkg_start = strstr(path, "/data/data/") ? path+10 : strstr(path, "/Android/data/") ? path+13 : NULL;
    if (!pkg_start) return 0;
    char pkg[MAX_PACKAGE_LEN] = {0};
    // 修复：处理path中无 '/' 的情况，避免strchr返回NULL
    char *pkg_end = strchr(pkg_start, '/');
    if (pkg_end) {
        strncpy(pkg, pkg_start, pkg_end - pkg_start);
    } else {
        strncpy(pkg, pkg_start, MAX_PACKAGE_LEN-1);
    }
    // 白名单应用直接放行
    for (size_t i = 0; i < WHITELIST_SIZE; i++) {
        if (!strcmp(pkg, whitelist[i])) return 0;
    }
    // 包名哈希去重，2分钟内仅拦截一次
    unsigned long hash = 0;
    for (size_t i = 0; pkg[i]; i++) hash = hash*31 + pkg[i];
    unsigned long idx = hash % MAX_PACKAGE_LEN;
    if (jiffies - last_blocked_time[idx] >= INTERVAL) {
        last_blocked_time[idx] = jiffies;
        return 1;
    }
    return 0;
}

// 核心拦截钩子（添加符号检查）
static void __used before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running || !kf_strncpy_from_user) return;
    char path[PATH_MAX];
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX-1);
    if (len <= 0 || is_whitelisted(path)) return;
    path[len] = '\0';
    if ((is_blocked_path(path) || is_ad_blocked(path)) && can_block(path)) {
        pr_emerg("拦截mkdirat: %s", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}
static void __used before_chdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running || !kf_strncpy_from_user) return;
    char path[PATH_MAX];
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX-1);
    if (len <= 0 || is_whitelisted(path)) return;
    path[len] = '\0';
    if ((is_blocked_path(path) || is_ad_blocked(path)) && can_block(path)) {
        pr_emerg("拦截chdir: %s", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 模块初始化（核心修复：添加KPM符号检测+强制日志）
static long __used mkdir_hook_init(const char *args, const char *event, void *reserved) {
    pr_emerg("===== 开始初始化（KPM加载修复版） =====");
    
    // 关键：检测KPM核心符号是否存在（避免加载失败无日志）
    if (!hook_syscalln) {
        pr_emerg("ERROR: KPM框架未导出hook_syscalln符号！");
        return -EINVAL;
    }
    if (!kf_strncpy_from_user) {
        pr_emerg("ERROR: KPM兼容层未导出kf_strncpy_from_user符号！");
        return -EINVAL;
    }
    if (!jiffies) {
        pr_emerg("ERROR: 内核未导出jiffies符号！");
        return -EINVAL;
    }

    // 挂钩系统调用（简化逻辑，确保成功）
    hook_err_t err = hook_syscalln((int)__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) {
        pr_emerg("ERROR: 挂钩mkdirat失败！err=%d", err);
        return -EINVAL;
    }
    err = hook_syscalln((int)__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) {
        pr_emerg("ERROR: 挂钩chdir失败！err=%d", err);
        return -EINVAL;
    }

    pr_emerg("===== 初始化成功！全局拦截：%s，广告拦截：%s =====", 
             hma_running ? "开启" : "关闭", hma_ad_enabled ? "开启" : "关闭");
    return 0;
}

// 控制接口（严格匹配KPM）
static long __used hma_control0(const char *ctl_args, char *__user out_msg, int outlen) {
    char msg[64] = "参数格式：0/1,0/1（全局拦截,广告拦截）";
    if (ctl_args && strlen(ctl_args)>=3) {
        hma_running = (ctl_args[0] == '1');
        hma_ad_enabled = (ctl_args[2] == '1');
        snprintf(msg, 63, "全局：%s，广告：%s", hma_running?"开启":"关闭", hma_ad_enabled?"开启":"关闭");
    }
    if (outlen >= strlen(msg)+1 && kf_copy_to_user) {
        kf_copy_to_user(out_msg, msg, strlen(msg)+1);
    }
    return 0;
}
static long __used hma_control1(void *a1, void *a2, void *a3) { return 0; }

// 模块退出（添加日志）
static long __used mkdir_hook_exit(void *reserved) {
    pr_emerg("===== 退出模块 =====");
    if (hook_syscalln) {
        unhook_syscalln((int)__NR_mkdirat, before_mkdirat, NULL);
        unhook_syscalln((int)__NR_chdir, before_chdir, NULL);
    }
    return 0;
}

// KPM注册（确保宏展开无错误）
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
