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
KPM_VERSION("1.1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("广告拦截（含原风险包名白名单+核心应用白名单）");

// 核心宏定义（极简适配）
#define MAX_PACKAGE_LEN 576
#define PATH_SEPARATOR '/'

// 全局开关（精简为双开关）
static bool hma_running = true;        // 总开关（默认开启）
static bool hma_ad_enabled = true;     // 广告拦截开关（2开3关）

// 1. 核心白名单（原核心应用白名单，完全放行）
static const char *core_whitelist[] = {
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
#define CORE_WL_SIZE (sizeof(core_whitelist)/sizeof(core_whitelist[0]))

// 2. 广告拦截白名单（合并原风险拦截黑名单的包名，不拦截这些应用的广告）
static const char *ad_whitelist[] = {
    // 原风险拦截黑名单中的所有包名
    "com.silverlab.app.deviceidchanger.free", "me.bingyue.IceCore", "com.modify.installer",
    "o.dyoo", "com.zhufucdev.motion_emulator", "com.xiaomi.shop", "com.demo.serendipity",
    "me.iacn.biliroaming", "me.teble.xposed.autodaily", "com.example.ourom", "dialog.box",
    "tornaco.apps.shortx", "moe.fuqiuluo.portal", "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api", "lin.xposed", "com.lerist.fakelocation", "com.yxer.packageinstalles",
    "bin.mt.plus.canary", "web1n.stopapp", "Hook.JiuWu.Xp", "com.taobao.taobao", "com.houvven.guise",
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
    "com.fankes.tsbattery", "com.rifsxd.ksunext", "com.rkg.IAMRKG", "me.gm.cleaner", "com.ddm.qute",
    "kk.dk.anqu", "com.qq.qcxm", "dknb.con", "dknb.coo8", "com.tencent.jingshi", "com.tencent.JYNB",
    "com.apocalua.run", "com.coderstory.toolkit", "com.didjdk.adbhelper", "io.github.Retmon403.oppotheme",
    "com.fankes.enforcehighrefreshrate", "es.chiteroman.bootloaderspoofer", "com.hchai.rescueplan",
    "io.github.chipppppppppp.lime", "dev.device.emulator", "com.github.dan.NoStorageRestrict",
    "com.android1500.androidfaker", "com.smartpack.kernelmanager", "ps.reso.instaeclipse",
    "top.ltfan.notdeveloper", "com.rel.languager", "not.val.cheat", "com.haobammmm", "bin.mt.plus",
    "com.tencent.tmgp.dfm"
};
#define AD_WL_SIZE (sizeof(ad_whitelist)/sizeof(ad_whitelist[0]))

// 广告拦截关键词（保持不变）
static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat", "adtrack",
    "adservice", "adplugin", "admodule", "adlibrary", "adloader"
};
#define AD_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// 公共工具函数：统一提取路径中的包名
static int get_package_from_path(const char *path, char *pkg_name, size_t max_len) {
    if (!path || *path != PATH_SEPARATOR || !pkg_name || max_len == 0) return -1;

    const char *prefix1 = "/data/data/";
    const char *prefix2 = "/storage/emulated/0/Android/data/";
    const char *pkg_start = NULL;

    // 匹配应用数据路径，提取包名
    if (strstr(path, prefix1)) {
        pkg_start = path + strlen(prefix1);
    } else if (strstr(path, prefix2)) {
        pkg_start = path + strlen(prefix2);
    } else {
        // 非应用数据路径，无法提取包名（返回失败，不拦截）
        return -1;
    }

    // 复制包名（截止到下一个路径分隔符）
    size_t i = 0;
    while (pkg_start[i] && pkg_start[i] != PATH_SEPARATOR && i < max_len - 1) {
        pkg_name[i] = pkg_start[i];
        i++;
    }
    pkg_name[i] = '\0';
    return i > 0 ? 0 : -1;
}

// 1. 核心白名单校验（完全放行）
static bool is_in_core_whitelist(const char *path) {
    char pkg_name[MAX_PACKAGE_LEN] = {0};
    if (get_package_from_path(path, pkg_name, MAX_PACKAGE_LEN) != 0) {
        // 无法提取包名的系统路径直接放行
        return strstr(path, "/system/") || strstr(path, "/vendor/") || strstr(path, "/oem/");
    }

    for (size_t i = 0; i < CORE_WL_SIZE; i++) {
        if (strcmp(pkg_name, core_whitelist[i]) == 0) return true;
    }
    return false;
}

// 2. 广告拦截白名单校验（这些应用不拦截广告）
static bool is_in_ad_whitelist(const char *path) {
    char pkg_name[MAX_PACKAGE_LEN] = {0};
    if (get_package_from_path(path, pkg_name, MAX_PACKAGE_LEN) != 0) return false;

    for (size_t i = 0; i < AD_WL_SIZE; i++) {
        if (strcmp(pkg_name, ad_whitelist[i]) == 0) return true;
    }
    return false;
}

// 3. 广告拦截判断（核心逻辑：核心白名单→广告白名单→关键词匹配）
static bool should_block_ad(const char *path) {
    if (!hma_ad_enabled) return false;
    // 核心白名单内 → 不拦截
    if (is_in_core_whitelist(path)) return false;
    // 广告白名单内 → 不拦截
    if (is_in_ad_whitelist(path)) return false;

    // 关键词匹配 → 拦截
    char lower_path[PATH_MAX] = {0};
    strncpy(lower_path, path, PATH_MAX - 1);
    for (char *s = lower_path; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') *s += 32;
    }

    for (size_t i = 0; i < AD_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i])) return true;
    }
    return false;
}

// 核心拦截钩子（仅保留广告拦截逻辑）
static void before_file_op(hook_fargs_t *args, int syscall_num) {
    if (!hma_running) return;

    // 提取路径参数（适配不同syscall）
    char path[PATH_MAX] = {0};
    char new_path[PATH_MAX] = {0};
    long len = -1;
    bool has_new_path = false;

    switch (syscall_num) {
        case __NR_mkdirat:
        case __NR_unlinkat:
            len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
            break;
        case __NR_chdir:
        case __NR_rmdir:
        case __NR_openat:
            len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
            break;
        case __NR_renameat:
            len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
            if (len > 0) {
                long len_new = compat_strncpy_from_user(new_path, (void *)syscall_argn(args, 3), PATH_MAX - 1);
                has_new_path = (len_new > 0);
                new_path[len_new > 0 ? len_new : 0] = '\0';
            }
            break;
        default:
            return;
    }

    // 路径无效或核心白名单应用 → 放行
    if (len <= 0 || is_in_core_whitelist(path) || (has_new_path && is_in_core_whitelist(new_path))) return;
    path[len] = '\0';

    // 广告拦截判断（任一路径命中即拦截）
    bool blocked = should_block_ad(path);
    if (has_new_path) blocked |= should_block_ad(new_path);

    if (blocked) {
        const char *syscall_name = syscall_num == __NR_mkdirat ? "mkdirat" :
                                  syscall_num == __NR_chdir ? "chdir" :
                                  syscall_num == __NR_rmdir ? "rmdir" :
                                  syscall_num == __NR_unlinkat ? "unlinkat" :
                                  syscall_num == __NR_openat ? "openat" : "renameat";
        pr_warn("[HMA++] 广告拦截: %s%s%s\n", path, has_new_path ? " -> " : "", has_new_path ? new_path : "");
        args->skip_origin = 1;
        args->ret = (syscall_num == __NR_chdir || syscall_num == __NR_rmdir) ? -ENOENT : -EACCES;
    }
}

// 钩子包装器（统一入口）
static void before_mkdirat(hook_fargs4_t *args, void *udata) { before_file_op((hook_fargs_t *)args, __NR_mkdirat); }
static void before_chdir(hook_fargs1_t *args, void *udata) { before_file_op((hook_fargs_t *)args, __NR_chdir); }
static void before_rmdir(hook_fargs1_t *args, void *udata) { before_file_op((hook_fargs_t *)args, __NR_rmdir); }
static void before_unlinkat(hook_fargs4_t *args, void *udata) { before_file_op((hook_fargs_t *)args, __NR_unlinkat); }
static void before_openat(hook_fargs5_t *args, void *udata) { before_file_op((hook_fargs_t *)args, __NR_openat); }
static void before_renameat(hook_fargs4_t *args, void *udata) { before_file_op((hook_fargs_t *)args, __NR_renameat); }

// 模块初始化
static long module_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] 初始化启动（广告拦截模式）\n");

    // 挂钩核心文件操作syscall
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++] 挂钩mkdirat失败: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++] 挂钩chdir失败: %d\n", err); return -EINVAL; }
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

    pr_info("[HMA++] 初始化成功（广告拦截: %d）\n", hma_ad_enabled);
    return 0;
}

// 控制接口（保持原参数：2=广告开启，3=广告关闭）
static long module_control(const char *args, char *__user out_msg, int outlen) {
    char msg[64] = {0};
    if (!args || strlen(args) != 1) {
        strncpy(msg, "参数错误：仅支持2(广告开启)/3(广告关闭)", sizeof(msg)-1);
        goto out;
    }

    switch (args[0]) {
        case '2': hma_ad_enabled = true; break;
        case '3': hma_ad_enabled = false; break;
        default:
            strncpy(msg, "无效参数：仅支持2或3", sizeof(msg)-1);
            goto out;
    }

    snprintf(msg, sizeof(msg)-1, "广告拦截状态: %s", hma_ad_enabled ? "开启" : "关闭");

out:
    if (outlen >= strlen(msg) + 1) {
        compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

// 模块退出
static long module_exit(void *__user reserved) {
    pr_info("[HMA++] 退出启动\n");
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
    pr_info("[HMA++] 退出成功\n");
    return 0;
}

// KPM模块注册
KPM_INIT(module_init);
KPM_CTL0(module_control);
KPM_CTL1(NULL);
KPM_EXIT(module_exit);
