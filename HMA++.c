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

// 模块元信息（极简核心标识）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.5");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("核心风险拦截测试+广告拦截测试");

// 核心宏定义（精简适配）
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif
#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH)-1)
#define MAX_PACKAGE_LEN 256

// 全局核心开关（唯一全局变量）
static bool hma_running = true;

// 1.风险拦截黑名单（无空项，精简高效）
static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free",
    "me.bingyue.IceCore",
    "com.modify.installer",
    "o.dyoo",
    "com.zhufucdev.motion_emulator",
    "com.xiaomi.shop",
    "com.demo.serendipity",
    "me.iacn.biliroaming",
    "me.teble.xposed.autodaily",
    "com.example.ourom",
    "dialog.box",
    "tornaco.apps.shortx",
    "moe.fuqiuluo.portal",
    "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api",
    "lin.xposed",
    "com.lerist.fakelocation",
    "com.yxer.packageinstalles",
    "bin.mt.plus.canary",
    "web1n.stopapp",
    "Hook.JiuWu.Xp",
    "com.taobao.taobao",
    "com.houvven.guise",
    "com.xayah.databackup.foss",
    "github.tornaco.android.thanos",
    "nep.timeline.freezer",
    "cn.geektang.privacyspace",
    "com.byyoung.setting",
    "cn.myflv.noactive",
    "com.junge.algorithmAidePro",
    "bin.mt.termex",
    "tmgp.atlas.toolbox",
    "com.wn.app.np",
    "icu.nullptr.nativetest",
    "ru.maximoff.apktool",
    "top.bienvenido.saas.i18n",
    "com.syyf.quickpay",
    "tornaco.apps.shortx.ext",
    "com.mio.kitchen",
    "eu.faircode.xlua",
    "com.dna.tools",
    "cn.myflv.monitor.noactive",
    "com.yuanwofei.cardemulator.pro",
    "com.termux",
    "com.suqi8.oshin",
    "me.hd.wauxv",
    "have.fun",
    "miko.client",
    "com.kooritea.fcmfix",
    "com.twifucker.hachidori",
    "com.luckyzyx.luckytool",
    "com.padi.hook.hookqq",
    "cn.lyric.getter",
    "com.parallelc.micts",
    "me.plusne",
    "com.hchen.appretention",
    "com.hchen.switchfreeform",
    "name.monwf.customiuizer",
    "com.houvven.impad",
    "cn.aodlyric.xiaowine",
    "top.sacz.timtool",
    "nep.timeline.re_telegram",
    "com.fuck.android.rimet",
    "cn.kwaiching.hook",
    "cn.android.x",
    "cc.aoeiuv020.iamnotdisabled.hook",
    "vn.kwaiching.tao",
    "com.nnnen.plusne",
    "com.fkzhang.wechatxposed",
    "one.yufz.hmspush",
    "cn.fuckhome.xiaowine",
    "com.fankes.tsbattery",
    "com.rifsxd.ksunext",
    "com.rkg.IAMRKG",
    "me.gm.cleaner",
    "com.ddm.qute",
    "kk.dk.anqu",
    "com.qq.qcxm",
    "dknb.con",
    "dknb.coo8",
    "com.tencent.jingshi",
    "com.tencent.JYNB",
    "com.apocalua.run",
    "com.coderstory.toolkit",
    "com.didjdk.adbhelper",
    "io.github.Retmon403.oppotheme",
    "com.fankes.enforcehighrefreshrate",
    "es.chiteroman.bootloaderspoofer",
    "com.hchai.rescueplan",
    "io.github.chipppppppppp.lime",
    "dev.device.emulator",
    "com.github.dan.NoStorageRestrict",
    "com.android1500.androidfaker",
    "com.smartpack.kernelmanager",
    "ps.reso.instaeclipse",
    "top.ltfan.notdeveloper",
    "com.rel.languager",
    "not.val.cheat",
    "com.haobammmm",
    "bin.mt.plus",
    "com.tencent.tmgp.dfm"
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

static const char *deny_folder_list[] = {
    // Hook/注入类
    "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp",
    // 系统篡改类
    "system_modify", "root_tool_data", "magisk_temp", "ksu_cache", "kernel_mod_dir",
    // 隐私窃取类
    "privacy_steal", "data_crack", "illegal_access", "info_collect", "secret_monitor",
    // 违规安装类
    "apk_modify", "pirate_apk", "illegal_install", "app_cracked", "patch_apk_dir",
    // 风险临时类
    "risk_temp", "unsafe_operation", "malicious_dir", "temp_hack", "unsafe_cache",
    // 终端脚本类
    "termux_data", "apktool_temp", "reverse_engineer", "hack_tool_data", "crack_tool_dir",
    // 模拟器类
    "emulator_data", "virtual_env", "fake_device", "emulator_cache", "virtual_device",
    // 广告插件类
    "ad_plugin", "malicious_plugin", "ad_cache", "plugin_hack", "ad_inject",
    // 数据篡改类
    "data_modify", "crack_data", "modify_logs", "crack_cache", "data_hack",
    // 残留备份类
    "tool_residue", "illegal_backup", "hack_residue", "backup_crack", "tool_cache",
    "MiShopSkyTreeBundleProvider", "release"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 2.广告拦截黑名单（仅文件关键词，无进程依赖）
static const char *ad_file_keywords[] = {
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo",
    "adbanner", "adpopup", "adpush", "adconfig", "adlog", "adstat"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// 核心判断函数（无任何结构体依赖）
// 风险路径判断
static int is_blocked_path(const char *path) {
    // 仅拦截绝对目标路径
    if (*path != '/' || strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0)
        return 0;
    
    char target_buf[MAX_PACKAGE_LEN] = {0};
    const char *p = path + TARGET_PATH_LEN;
    size_t i = 0;
    // 提取目标前缀后首个目录名
    while (*p && *p != '/' && i < MAX_PACKAGE_LEN - 1) {
        target_buf[i++] = *p++;
    }
    if (i == 0) return 0;

    // 风险包名校验
    for (size_t j = 0; j < DENY_LIST_SIZE; j++) {
        if (strcmp(target_buf, deny_list[j]) == 0)
            return 1;
    }
    // 风险文件夹校验
    for (size_t k = 0; k < DENY_FOLDER_SIZE; k++) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0)
            return 1;
    }
    return 0;
}

// 广告拦截判断（仅文件关键词，无进程/网络依赖）
static int is_ad_blocked(const char *path) {
    if (!path) return 0;
    char lower_path[PATH_MAX];
    // 路径拷贝+防越界
    strncpy(lower_path, path, PATH_MAX - 1);
    lower_path[PATH_MAX - 1] = '\0';
    // 转小写（极简实现，无辅助函数）
    for (char *s = lower_path; *s; s++) {
        if (*s >= 'A' && *s <= 'Z')
            *s += 32;
    }
    // 广告文件关键词匹配
    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i]) != NULL)
            return 1;
    }
    return 0;
}

// 极简文件操作钩子（核心拦截逻辑）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path)) {
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
    if (is_blocked_path(path) || is_ad_blocked(path)) {
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
    if (is_blocked_path(path) || is_ad_blocked(path)) {
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
    if (is_blocked_path(path) || is_ad_blocked(path)) {
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
    if (is_blocked_path(path) || is_ad_blocked(path)) {
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
    if (is_blocked_path(old_path) || is_blocked_path(new_path) || is_ad_blocked(old_path) || is_ad_blocked(new_path)) {
        pr_warn("[HMA++] renameat deny: %s -> %s\n", old_path, new_path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// 模块生命周期（极简无冗余）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] init start\n");

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

    pr_info("[HMA++] init success\n");
    return 0;
}

// 启停控制（极简逻辑）
static long hma_control0(const char *args, char *__user out_msg, int outlen) {
    char msg[32] = {0};
    // 参数校验
    if (!args || strlen(args) != 1) {
        strncpy(msg, "args err: only 0/1", sizeof(msg)-1);
        goto out_copy;
    }
    // 开关控制
    hma_running = (*args == '1') ? true : false;
    strncpy(msg, hma_running ? "interception enabled" : "interception disabled", sizeof(msg)-1);

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
    // 解钩所有挂钩的syscall
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

// 模块注册（符合规范）
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
