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
KPM_VERSION("1.0.8");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("全应用风险+广告拦截（非白名单拦截，核心应用放行）");

// 核心宏定义（移除路径限制，适配所有应用）
#define MAX_PACKAGE_LEN 576
#define ARG_SEPARATOR ','
#define PATH_SEPARATOR '/'

// 全局开关（双开关设计，保持极简）
static bool hma_running = true;        // 总开关
static bool hma_ad_enabled = true;     // 广告拦截独立开关

// ========== 核心白名单：仅放行以下应用的所有文件操作 ==========
// 原业务白名单 + 新增风险白名单合并，非此列表应用默认拦截风险操作
static const char *app_whitelist[] = {
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
    "com.cib.mobilebank",      // 招商银行
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
    "com.meizu.flyme.launcher",// 魅族桌面
    "me.bmax.apatch",
    "com.larus.nova",
    "com.miui.home",
    "com.sukisu.ultra",
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
    "com.tencent.tmgp.dfm","com.miHoYo.hkrpg","com.tencent.tmgp.sgame","com.ss.android.lark.dahx258","com.omarea.vtools"
};
#define APP_WHITELIST_SIZE (sizeof(app_whitelist)/sizeof(app_whitelist[0]))

// ========== 广告拦截黑名单（全路径关键词匹配，保持不变） ==========
static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat", "adtrack",
    "adservice", "adplugin", "admodule", "adlibrary", "adloader"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// ========== 核心工具函数（逻辑反转：非白名单默认拦截） ==========
// 1. 应用白名单校验：白名单内应用直接放行所有操作
static int is_app_whitelisted(const char *path) {
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
        // 系统路径直接放行（系统目录无风险）
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

    // 白名单匹配：命中则放行
    for (size_t j = 0; j < APP_WHITELIST_SIZE; j++) {
        if (strcmp(pkg_name, app_whitelist[j]) == 0) {
            return 1;
        }
    }
    return 0;
}

// 2. 风险操作判断：非白名单应用默认拦截所有文件操作
static int is_risk_operation(const char *path) {
    // 白名单应用/系统路径：无风险
    if (is_app_whitelisted(path)) return 0;
    // 非白名单应用：所有文件操作均判定为风险
    return 1;
}

// 3. 广告拦截判断（全应用生效，保持不变）
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

    // 广告关键词匹配
    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// ========== 核心拦截钩子（逻辑：风险操作+广告操作 双重拦截） ==========
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    
    // 非白名单风险操作 或 广告操作 → 拦截
    if (is_risk_operation(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] mkdirat deny: %s\n", path);
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
    
    if (is_risk_operation(path) || is_ad_blocked(path)) {
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
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_risk_operation(path) || is_ad_blocked(path)) {
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
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_risk_operation(path) || is_ad_blocked(path)) {
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
    if (len <= 0) return;
    path[len] = '\0';
    
    if (is_risk_operation(path) || is_ad_blocked(path)) {
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

    // 任一路径命中风险/广告 → 拦截
    if (is_risk_operation(old_path) || is_risk_operation(new_path) || is_ad_blocked(old_path) || is_ad_blocked(new_path)) {
        pr_warn("[HMA++] renameat deny: %s -> %s\n", old_path, new_path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// ========== 模块生命周期（极简无冗余） ==========
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] init start (非白名单拦截+核心应用放行)\n");

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

    pr_info("[HMA++] init success (global: %d, ad: %d)\n", hma_running, hma_ad_enabled);
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
    snprintf(msg, sizeof(msg)-1, "global: %s, ad: %s",
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
