#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <accctl.h>
#include <uapi/linux/limits.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>

// 适配不同内核 hook 结构体定义（优化宏判断，避免重复定义冲突）
#ifndef hook_fargs0_t
typedef struct {
    unsigned long args[0];
    long ret;
    bool skip_origin;
} hook_fargs0_t;
#endif

#ifndef hook_fargs1_t
typedef struct {
    unsigned long args[1];
    long ret;
    bool skip_origin;
} hook_fargs1_t;
#endif

#ifndef hook_fargs2_t
typedef struct {
    unsigned long args[2];
    long ret;
    bool skip_origin;
} hook_fargs2_t;
#endif

#ifndef hook_fargs4_t
typedef struct {
    unsigned long args[4];
    long ret;
    bool skip_origin;
} hook_fargs4_t;
#endif

// 兼容不同内核 syscall_argn 宏定义（优化参数取值逻辑，避免宏展开错误）
#ifndef syscall_argn
#define syscall_argn(args, idx) ((args)->args[idx])
#endif

// 核心宏定义（避免与内核内置宏冲突）
#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN ((unsigned int)sizeof(TARGET_PATH) - 1)
#define STATUS_QUERY_MAGIC 0x12345678

// 模块基础信息（规范定义，避免宏展开歧义）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("测试更新（新增自定义路径隐藏+工作状态显示）");

// 内置 deny list（修正语法错误，补充缺失逗号）
static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free",
    "me.bingyue.IceCore",
    "com.modify.installer",
    "o.dyoo",
    "com.zhufucdev.motion_emulator",
    "me.simpleHook",
    "com.cshlolss.vipkill",
    "io.github.a13e300.ksuwebui",
    "com.demo.serendipity",
    "me.iacn.biliroaming",
    "me.teble.xposed.autodaily",
    "com.example.ourom",
    "dialog.box",
    "top.hookvip.pro",
    "tornaco.apps.shortx",
    "moe.fuqiuluo.portal",
    "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api",
    "lin.xposed",
    "com.lerist.fakelocation",
    "com.yxer.packageinstalles",
    "xzr.hkf",
    "web1n.stopapp",
    "Hook.JiuWu.Xp",
    "io.github.qauxv",
    "com.houvven.guise",
    "xzr.konabess",
    "com.xayah.databackup.foss",
    "com.sevtinge.hyperceiler",
    "github.tornaco.android.thanos",
    "nep.timeline.freezer",
    "cn.geektang.privacyspace",
    "org.lsposed.lspatch",
    "zako.zako.zako",
    "com.topmiaohan.hidebllist",
    "com.tsng.hidemyapplist",
    "com.tsng.pzyhrx.hma",
    "com.rifsxd.ksunext",
    "com.byyoung.setting",
    "com.omarea.vtools",
    "cn.myflv.noactive",
    "io.github.vvb2060.magisk",
    "com.bug.hookvip",
    "com.junge.algorithmAidePro",
    "bin.mt.termex",
    "tmgp.atlas.toolbox",
    "com.wn.app.np",
    "com.sukisu.ultra",
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
    "com.rkg.IAMRKG",
    "me.gm.cleaner",
    "moe.shizuku.redirectstorage",
    "com.ddm.qute",
    "kk.dk.anqu",
    "com.qq.qcxm",
    "com.wei.vip",
    "dknb.con",
    "dknb.coo8",
    "com.tencent.jingshi",
    "com.tencent.JYNB",
    "com.apocalua.run",
    "com.coderstory.toolkit",
    "com.didjdk.adbhelper",
    "org.lsposed.manager",
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
    "com.reveny.nativecheck",
    "chunqiu.safe.detector",
};
#define DENY_LIST_SIZE ((unsigned int)sizeof(deny_list)/sizeof(deny_list[0]))

// 核心拦截文件夹列表
static const char *deny_folder_list[] = {
    "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp", "hook_framework",
    "magisk_temp", "ksu_cache", "system_modify", "root_tool_data", "kernel_mod_dir",
    "privacy_steal", "data_crack", "info_collect", "secret_monitor", "data_leak_dir",
    "apk_modify", "pirate_apk", "app_cracked", "patch_apk_dir", "illegal_install",
    "termux_data", "apktool_temp", "reverse_engineer", "hack_tool_data", "shell_script",
    "emulator_data", "virtual_env", "fake_device", "emulator_cache",
    "ad_plugin", "malicious_plugin", "plugin_hack", "ad_inject",
    "risk_temp", "malicious_dir", "temp_hack", "unsafe_cache"
};
#define DENY_FOLDER_SIZE ((unsigned int)sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 原有路径判断函数（无修改，适配无types.h环境）
static int is_blocked_path(const char *path) {
    unsigned int prefix_len = strlen(TARGET_PATH);
    if (strncmp(path, TARGET_PATH, prefix_len) != 0) return 0;
    
    const char *target_part = path + prefix_len;
    char target_buf[128];
    unsigned int i = 0;
    while (*target_part && *target_part != '/' && *target_part != '\\' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *target_part++;
    }
    target_buf[i] = '\0';
    
    for (unsigned int j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (unsigned int k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// -------------------------- 新增功能代码（修复宏展开兼容问题）--------------------------
static int g_module_running = 0;
static unsigned long g_intercept_count[6] = {0};
static spinlock_t g_count_lock;
static const char *op_name_map[] = {
    "mkdirat(创建)", "chdir(进入)", "unlinkat(删除)", "fstatat(查询)", "openat(打开)", "access(访问)"
};

// 新增路径隐藏判断函数（适配无types.h环境）
static int is_hide_target(const char *path) {
    if (!path || strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    const char *path_after_root = path + TARGET_PATH_LEN;
    if (*path_after_root == '\0') return 0;

    char target_buf[128];
    unsigned int i = 0;
    while (*path_after_root && *path_after_root != '/' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *path_after_root++;
    }
    target_buf[i] = '\0';

    for (unsigned int j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (unsigned int k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// 新增计数更新函数（无修改）
static void update_intercept_count(int op_idx) {
    spin_lock(&g_count_lock);
    g_intercept_count[op_idx]++;
    spin_unlock(&g_count_lock);
}

// 新增状态打印函数（无特殊字符，避免宏展开歧义）
static void print_work_status(const char *trigger) {
    pr_info("[HMA++]===== 工作状态报告（触发：%s）=====\n", trigger);
    pr_info("[HMA++]模块运行状态：%s\n", g_module_running ? "正常运行" : "已停止");
    pr_info("[HMA++]监控根目录：%s\n", TARGET_PATH);
    pr_info("[HMA++]拦截目标总数：包名%d个 + 文件夹%d个 = %d个\n", 
            DENY_LIST_SIZE, DENY_FOLDER_SIZE, DENY_LIST_SIZE + DENY_FOLDER_SIZE);
    pr_info("[HMA++]累计拦截统计：\n");
    for (int i = 0; i < 6; ++i) {
        pr_info("[HMA++]  - %s：%lu 次\n", op_name_map[i], g_intercept_count[i]);
    }
    pr_info("[HMA++]================================\n");
}

// 新增getpid钩子（优化参数逻辑，避免宏展开错误）
static void before_getpid(hook_fargs0_t *args, void *udata) {
    unsigned long magic = syscall_argn(args, 0);
    if (magic == STATUS_QUERY_MAGIC) {
        print_work_status("手动查询");
        args->ret = 0;
        args->skip_origin = 1;
    }
}

// 新增openat钩子（优化字符串拷贝，避免宏相关警告）
static void before_openat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(4);
        pr_warn("[HMA++]openat: Denied hide target (file open) %s（累计：%lu次）\n", filename_kernel, g_intercept_count[4]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 新增access钩子（优化字符串拷贝，避免宏相关警告）
static void before_access(hook_fargs2_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(5);
        pr_warn("[HMA++]access: Denied hide target (path access) %s（累计：%lu次）\n", filename_kernel, g_intercept_count[5]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
// -------------------------- 新增功能代码结束 --------------------------

// 原有mkdirat钩子（优化宏参数，避免展开错误）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(0);
        pr_warn("[HMA++]mkdirat: Denied by block rule to create %s（累计：%lu次）\n", filename_kernel, g_intercept_count[0]);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// 原有chdir钩子（优化宏参数，避免展开错误）
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(1);
        pr_warn("[HMA++]chdir: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[1]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有rmdir钩子（优化宏参数，避免展开错误）
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(2);
        pr_warn("[HMA++]rmdir/unlinkat: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[2]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有fstatat钩子（优化宏参数，避免展开错误）
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(3);
        pr_warn("[HMA++]fstatat/stat: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[3]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有初始化函数（优化宏使用，避免展开冲突）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    spin_lock_init(&g_count_lock);
    memset(g_intercept_count, 0, sizeof(g_intercept_count));
    g_module_running = 1;

    pr_info("[HMA++]HMA++ init. Hooking core syscalls...\n");
    
    // 原有syscall挂钩
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook mkdirat failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook chdir failed: %d\n", err); return -EINVAL; }
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
#else
#   error "No suitable syscall for rmdir"
#endif
    if (err) { pr_err("[HMA++]Hook rmdir/unlinkat failed: %d\n", err); return -EINVAL; }
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
#else
#   error "No suitable syscall for fstatat"
#endif
    if (err) { pr_err("[HMA++]Hook fstatat failed: %d\n", err); return -EINVAL; }
    
    // 新增syscall挂钩
    err = hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook openat failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_access, 2, before_access, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook access failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_getpid, 0, before_getpid, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook getpid (status query) failed: %d\n", err); return -EINVAL; }
    
    pr_info("[HMA++]All core syscalls hooked successfully.\n");
    print_work_status("模块加载完成");
    return 0;
}

// 原有退出函数（优化宏使用，避免展开冲突）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++]HMA++ exit. Unhooking syscalls...\n");
    g_module_running = 0;

    // 原有syscall解绑
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#elif defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_rmdir, NULL);
#endif
#ifdef __NR_newfstatat
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#endif
    
    // 新增syscall解绑
    unhook_syscalln(__NR_openat, before_openat, NULL);
    unhook_syscalln(__NR_access, before_access, NULL);
    unhook_syscalln(__NR_getpid, before_getpid, NULL);

    pr_info("[HMA++]All syscalls unhooked successfully.\n");
    print_work_status("模块卸载前");
    return 0;
}

// 修正模块入口出口宏，避免展开错误
KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
    unsigned long args[2];
    long ret;
    bool skip_origin;
} hook_fargs2_t;
#endif

#if !defined(hook_fargs4_t)
typedef struct {
    unsigned long args[4];
    long ret;
    bool skip_origin;
} hook_fargs4_t;
#endif

// 兼容不同内核 syscall_argn 宏定义（解决函数未定义报错）
#if !defined(syscall_argn)
#define syscall_argn(args, idx) ((args)->args[idx])
#endif

KPM_NAME("HMA++ Next");
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("测试更新（新增自定义路径隐藏+工作状态显示）");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

// 内置 deny list（修正语法错误：补充缺失逗号）
static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free",
    "me.bingyue.IceCore",
    "com.modify.installer",
    "o.dyoo",
    "com.zhufucdev.motion_emulator",
    "me.simpleHook",
    "com.cshlolss.vipkill",
    "io.github.a13e300.ksuwebui",
    "com.demo.serendipity",
    "me.iacn.biliroaming",
    "me.teble.xposed.autodaily",
    "com.example.ourom",
    "dialog.box",
    "top.hookvip.pro",
    "tornaco.apps.shortx",
    "moe.fuqiuluo.portal",
    "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api",
    "lin.xposed",
    "com.lerist.fakelocation",
    "com.yxer.packageinstalles",
    "xzr.hkf",
    "web1n.stopapp",
    "Hook.JiuWu.Xp",
    "io.github.qauxv",
    "com.houvven.guise",
    "xzr.konabess",
    "com.xayah.databackup.foss",
    "com.sevtinge.hyperceiler",
    "github.tornaco.android.thanos",
    "nep.timeline.freezer",
    "cn.geektang.privacyspace",
    "org.lsposed.lspatch",
    "zako.zako.zako",
    "com.topmiaohan.hidebllist",
    "com.tsng.hidemyapplist",
    "com.tsng.pzyhrx.hma",
    "com.rifsxd.ksunext",
    "com.byyoung.setting",
    "com.omarea.vtools",
    "cn.myflv.noactive",
    "io.github.vvb2060.magisk",
    "com.bug.hookvip",
    "com.junge.algorithmAidePro",
    "bin.mt.termex",
    "tmgp.atlas.toolbox",
    "com.wn.app.np",
    "com.sukisu.ultra",
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
    "com.rkg.IAMRKG",
    "me.gm.cleaner",
    "moe.shizuku.redirectstorage",
    "com.ddm.qute",
    "kk.dk.anqu",
    "com.qq.qcxm",
    "com.wei.vip",
    "dknb.con",
    "dknb.coo8",
    "com.tencent.jingshi",
    "com.tencent.JYNB",
    "com.apocalua.run",
    "com.coderstory.toolkit",
    "com.didjdk.adbhelper",
    "org.lsposed.manager",
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
    "bin.mt.plus", // 修复：补充缺失逗号
    "com.reveny.nativecheck",
    "chunqiu.safe.detector",
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

// 核心拦截文件夹列表
static const char *deny_folder_list[] = {
    "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp", "hook_framework",
    "magisk_temp", "ksu_cache", "system_modify", "root_tool_data", "kernel_mod_dir",
    "privacy_steal", "data_crack", "info_collect", "secret_monitor", "data_leak_dir",
    "apk_modify", "pirate_apk", "app_cracked", "patch_apk_dir", "illegal_install",
    "termux_data", "apktool_temp", "reverse_engineer", "hack_tool_data", "shell_script",
    "emulator_data", "virtual_env", "fake_device", "emulator_cache",
    "ad_plugin", "malicious_plugin", "plugin_hack", "ad_inject",
    "risk_temp", "malicious_dir", "temp_hack", "unsafe_cache"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 原有路径判断函数（无修改）
static int is_blocked_path(const char *path) {
    unsigned int prefix_len = strlen(TARGET_PATH); // 修复：用unsigned int替代size_t，适配无types.h环境
    if (strncmp(path, TARGET_PATH, prefix_len) != 0) return 0;
    
    const char *target_part = path + prefix_len;
    char target_buf[128];
    unsigned int i = 0; // 修复：unsigned int替代size_t
    while (*target_part && *target_part != '/' && *target_part != '\\' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *target_part++;
    }
    target_buf[i] = '\0';
    
    for (unsigned int j = 0; j < DENY_LIST_SIZE; ++j) { // 修复：unsigned int替代size_t
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (unsigned int k = 0; k < DENY_FOLDER_SIZE; ++k) { // 修复：unsigned int替代size_t
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// -------------------------- 新增功能代码（适配无types.h环境）--------------------------
#define STATUS_QUERY_MAGIC 0x12345678
static int g_module_running = 0;
static unsigned long g_intercept_count[6] = {0};
static spinlock_t g_count_lock;
static const char *op_name_map[] = {
    "mkdirat(创建)", "chdir(进入)", "unlinkat(删除)", "fstatat(查询)", "openat(打开)", "access(访问)"
};

// 新增路径隐藏判断函数（适配无types.h环境）
static int is_hide_target(const char *path) {
    if (!path || strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    const char *path_after_root = path + TARGET_PATH_LEN;
    if (*path_after_root == '\0') return 0;

    char target_buf[128];
    unsigned int i = 0; // 修复：unsigned int替代size_t
    while (*path_after_root && *path_after_root != '/' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *path_after_root++;
    }
    target_buf[i] = '\0';

    for (unsigned int j = 0; j < DENY_LIST_SIZE; ++j) { // 修复：unsigned int替代size_t
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (unsigned int k = 0; k < DENY_FOLDER_SIZE; ++k) { // 修复：unsigned int替代size_t
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// 新增计数更新函数（无修改）
static void update_intercept_count(int op_idx) {
    spin_lock(&g_count_lock);
    g_intercept_count[op_idx]++;
    spin_unlock(&g_count_lock);
}

// 新增状态打印函数（无特殊字符，适配所有编译器）
static void print_work_status(const char *trigger) {
    pr_info("[HMA++]===== 工作状态报告（触发：%s）=====\n", trigger);
    pr_info("[HMA++]模块运行状态：%s\n", g_module_running ? "正常运行" : "已停止");
    pr_info("[HMA++]监控根目录：%s\n", TARGET_PATH);
    pr_info("[HMA++]拦截目标总数：包名%d个 + 文件夹%d个 = %d个\n", 
            DENY_LIST_SIZE, DENY_FOLDER_SIZE, DENY_LIST_SIZE + DENY_FOLDER_SIZE);
    pr_info("[HMA++]累计拦截统计：\n");
    for (int i = 0; i < 6; ++i) {
        pr_info("[HMA++]  - %s：%lu 次\n", op_name_map[i], g_intercept_count[i]);
    }
    pr_info("[HMA++]================================\n");
}

// 新增getpid钩子（参数类型匹配）
static void before_getpid(hook_fargs0_t *args, void *udata) {
    unsigned long magic = syscall_argn(args, 0);
    if (magic == STATUS_QUERY_MAGIC) {
        print_work_status("手动查询");
        args->ret = 0;
        args->skip_origin = 1;
    }
}

// 新增openat钩子（字符串拷贝长度优化）
static void before_openat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(4);
        pr_warn("[HMA++]openat: Denied hide target (file open) %s（累计：%lu次）\n", filename_kernel, g_intercept_count[4]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 新增access钩子（字符串拷贝长度优化）
static void before_access(hook_fargs2_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(5);
        pr_warn("[HMA++]access: Denied hide target (path access) %s（累计：%lu次）\n", filename_kernel, g_intercept_count[5]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
// -------------------------- 新增功能代码结束 --------------------------

// 原有mkdirat钩子（字符串拷贝优化+新增计数）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(0);
        pr_warn("[HMA++]mkdirat: Denied by block rule to create %s（累计：%lu次）\n", filename_kernel, g_intercept_count[0]);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// 原有chdir钩子（字符串拷贝优化+新增计数）
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(1);
        pr_warn("[HMA++]chdir: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[1]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有rmdir钩子（字符串拷贝优化+新增计数）
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(2);
        pr_warn("[HMA++]rmdir/unlinkat: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[2]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有fstatat钩子（字符串拷贝优化+新增计数）
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(3);
        pr_warn("[HMA++]fstatat/stat: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[3]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有初始化函数（完善钩子绑定）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    spin_lock_init(&g_count_lock);
    memset(g_intercept_count, 0, sizeof(g_intercept_count));
    g_module_running = 1;

    pr_info("[HMA++]HMA++ init. Hooking core syscalls...\n");
    
    // 原有syscall挂钩
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook mkdirat failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook chdir failed: %d\n", err); return -EINVAL; }
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
#else
#   error "No suitable syscall for rmdir"
#endif
    if (err) { pr_err("[HMA++]Hook rmdir/unlinkat failed: %d\n", err); return -EINVAL; }
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
#else
#   error "No suitable syscall for fstatat"
#endif
    if (err) { pr_err("[HMA++]Hook fstatat failed: %d\n", err); return -EINVAL; }
    
    // 新增syscall挂钩
    err = hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook openat failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_access, 2, before_access, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook access failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_getpid, 0, before_getpid, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook getpid (status query) failed: %d\n", err); return -EINVAL; }
    
    pr_info("[HMA++]All core syscalls hooked successfully.\n");
    print_work_status("模块加载完成");
    return 0;
}

// 原有退出函数（完善钩子解绑）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++]HMA++ exit. Unhooking syscalls...\n");
    g_module_running = 0;

    // 原有syscall解绑
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#elif defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_rmdir, NULL);
#endif
#ifdef __NR_newfstatat
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#endif
    
    // 新增syscall解绑
    unhook_syscalln(__NR_openat, before_openat, NULL);
    unhook_syscalln(__NR_access, before_access, NULL);
    unhook_syscalln(__NR_getpid, before_getpid, NULL);

    pr_info("[HMA++]All syscalls unhooked successfully.\n");
    print_work_status("模块卸载前");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
#if !defined(hook_fargs2_t)
typedef struct {
    unsigned long args[2];
    long ret;
    bool skip_origin;
} hook_fargs2_t;
#endif

#if !defined(hook_fargs4_t)
typedef struct {
    unsigned long args[4];
    long ret;
    bool skip_origin;
} hook_fargs4_t;
#endif

// 新增：兼容不同内核 syscall_argn 宏定义（解决函数未定义报错）
#if !defined(syscall_argn)
#define syscall_argn(args, idx) ((args)->args[idx])
#endif

KPM_NAME("HMA++ Next");
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("测试更新（新增自定义路径隐藏+工作状态显示）");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

// 内置 deny list
static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free",
    "me.bingyue.IceCore",
    "com.modify.installer",
    "o.dyoo",
    "com.zhufucdev.motion_emulator",
    "me.simpleHook",
    "com.cshlolss.vipkill",
    "io.github.a13e300.ksuwebui",
    "com.demo.serendipity",
    "me.iacn.biliroaming",
    "me.teble.xposed.autodaily",
    "com.example.ourom",
    "dialog.box",
    "top.hookvip.pro",
    "tornaco.apps.shortx",
    "moe.fuqiuluo.portal",
    "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api",
    "lin.xposed",
    "com.lerist.fakelocation",
    "com.yxer.packageinstalles",
    "xzr.hkf",
    "web1n.stopapp",
    "Hook.JiuWu.Xp",
    "io.github.qauxv",
    "com.houvven.guise",
    "xzr.konabess",
    "com.xayah.databackup.foss",
    "com.sevtinge.hyperceiler",
    "github.tornaco.android.thanos",
    "nep.timeline.freezer",
    "cn.geektang.privacyspace",
    "org.lsposed.lspatch",
    "zako.zako.zako",
    "com.topmiaohan.hidebllist",
    "com.tsng.hidemyapplist",
    "com.tsng.pzyhrx.hma",
    "com.rifsxd.ksunext",
    "com.byyoung.setting",
    "com.omarea.vtools",
    "cn.myflv.noactive",
    "io.github.vvb2060.magisk",
    "com.bug.hookvip",
    "com.junge.algorithmAidePro",
    "bin.mt.termex",
    "tmgp.atlas.toolbox",
    "com.wn.app.np",
    "com.sukisu.ultra",
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
    "com.rkg.IAMRKG",
    "me.gm.cleaner",
    "moe.shizuku.redirectstorage",
    "com.ddm.qute",
    "kk.dk.anqu",
    "com.qq.qcxm",
    "com.wei.vip",
    "dknb.con",
    "dknb.coo8",
    "com.tencent.jingshi",
    "com.tencent.JYNB",
    "com.apocalua.run",
    "com.coderstory.toolkit",
    "com.didjdk.adbhelper",
    "org.lsposed.manager",
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
    "com.reveny.nativecheck",
    "chunqiu.safe.detector",
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

// 核心拦截文件夹列表
static const char *deny_folder_list[] = {
    "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp", "hook_framework",
    "magisk_temp", "ksu_cache", "system_modify", "root_tool_data", "kernel_mod_dir",
    "privacy_steal", "data_crack", "info_collect", "secret_monitor", "data_leak_dir",
    "apk_modify", "pirate_apk", "app_cracked", "patch_apk_dir", "illegal_install",
    "termux_data", "apktool_temp", "reverse_engineer", "hack_tool_data", "shell_script",
    "emulator_data", "virtual_env", "fake_device", "emulator_cache",
    "ad_plugin", "malicious_plugin", "plugin_hack", "ad_inject",
    "risk_temp", "malicious_dir", "temp_hack", "unsafe_cache"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 原有路径判断函数（无修改）
static int is_blocked_path(const char *path) {
    size_t prefix_len = strlen(TARGET_PATH);
    if (strncmp(path, TARGET_PATH, prefix_len) != 0) return 0;
    
    const char *target_part = path + prefix_len;
    char target_buf[128];
    size_t i = 0;
    while (*target_part && *target_part != '/' && *target_part != '\\' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *target_part++;
    }
    target_buf[i] = '\0';
    
    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (size_t k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// -------------------------- 新增功能代码（修复报错后版本）--------------------------
#define STATUS_QUERY_MAGIC 0x12345678
static int g_module_running = 0;
static unsigned long g_intercept_count[6] = {0};
static spinlock_t g_count_lock;
static const char *op_name_map[] = {
    "mkdirat(创建)", "chdir(进入)", "unlinkat(删除)", "fstatat(查询)", "openat(打开)", "access(访问)"
};

// 新增路径隐藏判断函数（无修改，适配头文件后可正常编译）
static int is_hide_target(const char *path) {
    if (!path || strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    const char *path_after_root = path + TARGET_PATH_LEN;
    if (*path_after_root == '\0') return 0;

    char target_buf[128];
    size_t i = 0;
    while (*path_after_root && *path_after_root != '/' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *path_after_root++;
    }
    target_buf[i] = '\0';

    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (size_t k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// 新增计数更新函数（无修改）
static void update_intercept_count(int op_idx) {
    spin_lock(&g_count_lock);
    g_intercept_count[op_idx]++;
    spin_unlock(&g_count_lock);
}

// 新增状态打印函数（修复：移除特殊字符，兼容老旧编译器）
static void print_work_status(const char *trigger) {
    pr_info("[HMA++]===== 工作状态报告（触发：%s）=====\n", trigger);
    pr_info("[HMA++]模块运行状态：%s\n", g_module_running ? "正常运行" : "已停止");
    pr_info("[HMA++]监控根目录：%s\n", TARGET_PATH);
    pr_info("[HMA++]拦截目标总数：包名%d个 + 文件夹%d个 = %d个\n", 
            DENY_LIST_SIZE, DENY_FOLDER_SIZE, DENY_LIST_SIZE + DENY_FOLDER_SIZE);
    pr_info("[HMA++]累计拦截统计：\n");
    for (int i = 0; i < 6; ++i) {
        pr_info("[HMA++]  - %s：%lu 次\n", op_name_map[i], g_intercept_count[i]);
    }
    pr_info("[HMA++]================================\n");
}

// 新增getpid钩子（修复：参数类型匹配，适配hook结构体）
static void before_getpid(hook_fargs0_t *args, void *udata) {
    // 修复：getpid无参数，魔术值通过args[0]传递（兼容内核调用规范）
    unsigned long magic = syscall_argn(args, 0);
    if (magic == STATUS_QUERY_MAGIC) {
        print_work_status("手动查询");
        args->ret = 0;
        args->skip_origin = 1;
    }
}

// 新增openat钩子（修复：参数类型匹配，字符串拷贝长度处理）
static void before_openat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    // 修复：strncpy_from_user返回值处理，避免越界
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(4);
        pr_warn("[HMA++]openat: Denied hide target (file open) %s（累计：%lu次）\n", filename_kernel, g_intercept_count[4]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 新增access钩子（修复：参数类型匹配，字符串拷贝长度处理）
static void before_access(hook_fargs2_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(5);
        pr_warn("[HMA++]access: Denied hide target (path access) %s（累计：%lu次）\n", filename_kernel, g_intercept_count[5]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
// -------------------------- 新增功能代码结束 --------------------------

// 原有mkdirat钩子（修复：新增计数，字符串拷贝长度处理）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(0);
        pr_warn("[HMA++]mkdirat: Denied by block rule to create %s（累计：%lu次）\n", filename_kernel, g_intercept_count[0]);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// 原有chdir钩子（修复：新增计数，字符串拷贝长度处理）
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(1);
        pr_warn("[HMA++]chdir: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[1]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有rmdir钩子（修复：新增计数，字符串拷贝长度处理）
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(2);
        pr_warn("[HMA++]rmdir/unlinkat: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[2]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有fstatat钩子（修复：新增计数，字符串拷贝长度处理）
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        update_intercept_count(3);
        pr_warn("[HMA++]fstatat/stat: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[3]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 原有初始化函数（修复：新增钩子绑定，初始化逻辑完善）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    spin_lock_init(&g_count_lock);
    memset(g_intercept_count, 0, sizeof(g_intercept_count));
    g_module_running = 1;

    pr_info("[HMA++]HMA++ init. Hooking core syscalls...\n");
    
    // 原有syscall挂钩
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook mkdirat failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook chdir failed: %d\n", err); return -EINVAL; }
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
#else
#   error "No suitable syscall for rmdir"
#endif
    if (err) { pr_err("[HMA++]Hook rmdir/unlinkat failed: %d\n", err); return -EINVAL; }
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
#else
#   error "No suitable syscall for fstatat"
#endif
    if (err) { pr_err("[HMA++]Hook fstatat failed: %d\n", err); return -EINVAL; }
    
    // 新增syscall挂钩
    err = hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook openat failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_access, 2, before_access, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook access failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_getpid, 0, before_getpid, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook getpid (status query) failed: %d\n", err); return -EINVAL; }
    
    pr_info("[HMA++]All core syscalls hooked successfully.\n");
    print_work_status("模块加载完成");
    return 0;
}

// 原有退出函数（修复：新增钩子解绑）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++]HMA++ exit. Unhooking syscalls...\n");
    g_module_running = 0;

    // 原有syscall解绑
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#elif defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_rmdir, NULL);
#endif
#ifdef __NR_newfstatat
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#endif
    
    // 新增syscall解绑
    unhook_syscalln(__NR_openat, before_openat, NULL);
    unhook_syscalln(__NR_access, before_access, NULL);
    unhook_syscalln(__NR_getpid, before_getpid, NULL);

    pr_info("[HMA++]All syscalls unhooked successfully.\n");
    print_work_status("模块卸载前");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
