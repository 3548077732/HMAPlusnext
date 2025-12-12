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

// -------------------------- 模块基础信息 --------------------------
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("自定义路径隐藏+工作状态监控（稳定加载版）");

// -------------------------- 核心宏定义 --------------------------
#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN ((unsigned int)sizeof(TARGET_PATH) - 1)
#define STATUS_QUERY_MAGIC 0x12345678
#define MAX_TARGET_NAME_LEN 127

// -------------------------- 拦截列表 --------------------------
static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free", "me.bingyue.IceCore", "com.modify.installer",
    "o.dyoo", "com.zhufucdev.motion_emulator", "me.simpleHook", "com.cshlolss.vipkill",
    "io.github.a13e300.ksuwebui", "com.demo.serendipity", "me.iacn.biliroaming",
    "me.teble.xposed.autodaily", "com.example.ourom", "dialog.box", "top.hookvip.pro",
    "tornaco.apps.shortx", "moe.fuqiuluo.portal", "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api", "lin.xposed", "com.lerist.fakelocation", "com.yxer.packageinstalles",
    "xzr.hkf", "web1n.stopapp", "Hook.JiuWu.Xp", "io.github.qauxv", "com.houvven.guise",
    "xzr.konabess", "com.xayah.databackup.foss", "com.sevtinge.hyperceiler",
    "github.tornaco.android.thanos", "nep.timeline.freezer", "cn.geektang.privacyspace",
    "org.lsposed.lspatch", "zako.zako.zako", "com.topmiaohan.hidebllist", "com.tsng.hidemyapplist",
    "com.tsng.pzyhrx.hma", "com.rifsxd.ksunext", "com.byyoung.setting", "com.omarea.vtools",
    "cn.myflv.noactive", "io.github.vvb2060.magisk", "com.bug.hookvip", "com.junge.algorithmAidePro",
    "bin.mt.termex", "tmgp.atlas.toolbox", "com.wn.app.np", "com.sukisu.ultra", "ru.maximoff.apktool",
    "top.bienvenido.saas.i18n", "com.syyf.quickpay", "tornaco.apps.shortx.ext", "com.mio.kitchen",
    "eu.faircode.xlua", "com.dna.tools", "cn.myflv.monitor.noactive", "com.yuanwofei.cardemulator.pro",
    "com.termux", "com.suqi8.oshin", "me.hd.wauxv", "have.fun", "miko.client", "com.kooritea.fcmfix",
    "com.twifucker.hachidori", "com.luckyzyx.luckytool", "com.padi.hook.hookqq", "cn.lyric.getter",
    "com.parallelc.micts", "me.plusne", "com.hchen.appretention", "com.hchen.switchfreeform",
    "name.monwf.customiuizer", "com.houvven.impad", "cn.aodlyric.xiaowine", "top.sacz.timtool",
    "nep.timeline.re_telegram", "com.fuck.android.rimet", "cn.kwaiching.hook", "cn.android.x",
    "cc.aoeiuv020.iamnotdisabled.hook", "vn.kwaiching.tao", "com.nnnen.plusne", "com.fkzhang.wechatxposed",
    "one.yufz.hmspush", "cn.fuckhome.xiaowine", "com.fankes.tsbattery", "com.rkg.IAMRKG",
    "me.gm.cleaner", "moe.shizuku.redirectstorage", "com.ddm.qute", "kk.dk.anqu", "com.qq.qcxm",
    "com.wei.vip", "dknb.con", "dknb.coo8", "com.tencent.jingshi", "com.tencent.JYNB",
    "com.apocalua.run", "com.coderstory.toolkit", "com.didjdk.adbhelper", "org.lsposed.manager",
    "io.github.Retmon403.oppotheme", "com.fankes.enforcehighrefreshrate", "es.chiteroman.bootloaderspoofer",
    "com.hchai.rescueplan", "io.github.chipppppppppp.lime", "dev.device.emulator",
    "com.github.dan.NoStorageRestrict", "com.android1500.androidfaker", "com.smartpack.kernelmanager",
    "ps.reso.instaeclipse", "top.ltfan.notdeveloper", "com.rel.languager", "not.val.cheat",
    "com.haobammmm", "bin.mt.plus", "com.reveny.nativecheck", "chunqiu.safe.detector"
};
#define DENY_LIST_SIZE ((unsigned int)sizeof(deny_list)/sizeof(deny_list[0]))

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

// -------------------------- 全局变量 --------------------------
static int g_module_running = 0;
static unsigned long g_intercept_count[6] = {0};
static spinlock_t g_count_lock;
static const char *op_name_map[] = {
    "mkdirat(创建)", "chdir(进入)", "unlinkat(删除)", "fstatat(查询)", "openat(打开)", "access(访问)"
};

// -------------------------- 函数原型声明 --------------------------
static int is_blocked_path(const char *path);
static int is_hide_target(const char *path);
static void update_intercept_count(int op_idx);
static void print_work_status(const char *trigger);
static void before_getpid(hook_fargs0_t *args, void *udata);
static void before_openat(hook_fargs4_t *args, void *udata);
static void before_access(hook_fargs4_t *args, void *udata);
static void before_mkdirat(hook_fargs4_t *args, void *udata);
static void before_chdir(hook_fargs4_t *args, void *udata);
static void before_rmdir(hook_fargs4_t *args, void *udata);
static void before_fstatat(hook_fargs4_t *args, void *udata);
static long mkdir_hook_init(const char *args, const char *event, void *reserved);
static long mkdir_hook_exit(void *reserved);
static void unhook_all_hooked_syscall(void);

// -------------------------- 核心工具函数 --------------------------
static int is_blocked_path(const char *path) {
    if (!path) return 0;
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    
    const char *target_part = path + TARGET_PATH_LEN;
    if (*target_part == '\0') return 0;
    
    char target_buf[MAX_TARGET_NAME_LEN + 1] = {0};
    unsigned int i = 0;
    while (*target_part && *target_part != '/' && *target_part != '\\' && i < MAX_TARGET_NAME_LEN) {
        target_buf[i++] = *target_part++;
    }
    
    for (unsigned int j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (unsigned int k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

static int is_hide_target(const char *path) {
    if (!path) return 0;
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    
    const char *target_part = path + TARGET_PATH_LEN;
    if (*target_part == '\0') return 0;
    
    char target_buf[MAX_TARGET_NAME_LEN + 1] = {0};
    unsigned int i = 0;
    while (*target_part && *target_part != '/' && i < MAX_TARGET_NAME_LEN) {
        target_buf[i++] = *target_part++;
    }
    
    for (unsigned int j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (unsigned int k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// 关键修复：适配当前环境spin_lock_irqsave单参数接口
static void update_intercept_count(int op_idx) {
    if (op_idx < 0 || op_idx >= 6) return; // 边界校验
    spin_lock_irqsave(&g_count_lock); // 匹配头文件单参数声明，自动保存中断状态
    g_intercept_count[op_idx]++;
    spin_unlock_irqrestore(&g_count_lock); // 对应解锁接口，自动恢复中断状态
}

static void print_work_status(const char *trigger) {
    pr_info("[HMA++]===== 模块工作状态（触发：%s）=====\n", trigger);
    pr_info("[HMA++]▶ 运行状态：%s\n", g_module_running ? "✅ 正常运行" : "❌ 已停止");
    pr_info("[HMA++]▶ 监控目录：%s\n", TARGET_PATH);
    pr_info("[HMA++]▶ 拦截目标：包名%d个 + 文件夹%d个 = %d个\n", 
            DENY_LIST_SIZE, DENY_FOLDER_SIZE, DENY_LIST_SIZE + DENY_FOLDER_SIZE);
    pr_info("[HMA++]▶ 累计拦截：\n");
    for (int i = 0; i < 6; ++i) {
        pr_info("[HMA++]    - %s：%lu 次\n", op_name_map[i], g_intercept_count[i]);
    }
    pr_info("[HMA++]====================================\n");
}

// -------------------------- Syscall钩子函数 --------------------------
static void before_getpid(hook_fargs0_t *args, void *udata) {
    if (!g_module_running) return;
    unsigned long magic = syscall_argn(args, 0);
    if (magic == STATUS_QUERY_MAGIC) {
        print_work_status("手动查询");
        args->ret = 0;
        args->skip_origin = 1;
    }
}

static void before_openat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX] = {0};
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0 || len >= (long)(sizeof(filename_kernel) - 1)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(4);
        pr_warn("[HMA++]拦截openat操作：%s（累计%lu次）\n", filename_kernel, g_intercept_count[4]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

static void before_access(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX] = {0};
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0 || len >= (long)(sizeof(filename_kernel) - 1)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(5);
        pr_warn("[HMA++]拦截access操作：%s（累计%lu次）\n", filename_kernel, g_intercept_count[5]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX] = {0};
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0 || len >= (long)(sizeof(filename_kernel) - 1)) return;
    filename_kernel[len] = '\0';
    
    if (is_blocked_path(filename_kernel)) {
        update_intercept_count(0);
        pr_warn("[HMA++]拦截mkdirat操作：%s（累计%lu次）\n", filename_kernel, g_intercept_count[0]);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

static void before_chdir(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX] = {0};
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0 || len >= (long)(sizeof(filename_kernel) - 1)) return;
    filename_kernel[len] = '\0';
    
    if (is_blocked_path(filename_kernel)) {
        update_intercept_count(1);
        pr_warn("[HMA++]拦截chdir操作：%s（累计%lu次）\n", filename_kernel, g_intercept_count[1]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

static void before_rmdir(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX] = {0};
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0 || len >= (long)(sizeof(filename_kernel) - 1)) return;
    filename_kernel[len] = '\0';
    
    if ((flags & 0x200) && is_blocked_path(filename_kernel)) {
        update_intercept_count(2);
        pr_warn("[HMA++]拦截rmdir操作：%s（累计%lu次）\n", filename_kernel, g_intercept_count[2]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

static void before_fstatat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX] = {0};
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
    if (len < 0 || len >= (long)(sizeof(filename_kernel) - 1)) return;
    filename_kernel[len] = '\0';
    
    if (is_blocked_path(filename_kernel)) {
        update_intercept_count(3);
        pr_warn("[HMA++]拦截fstatat操作：%s（累计%lu次）\n", filename_kernel, g_intercept_count[3]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// -------------------------- 模块加载/卸载核心逻辑 --------------------------
static void unhook_all_hooked_syscall(void) {
    // 核心syscall解绑
    unhook_syscalln(__NR_getpid, before_getpid, NULL);
    unhook_syscalln(__NR_openat, before_openat, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#elif defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_rmdir, NULL);
#endif
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);

    // 非核心syscall解绑
#ifdef __NR_fstatat
    unhook_syscalln(__NR_fstatat, before_fstatat, NULL);
#elif defined(__NR_newfstatat)
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#elif defined(__NR_compat_fstatat64)
    unhook_syscalln(__NR_compat_fstatat64, before_fstatat, NULL);
#elif defined(__NR_compat_newfstatat)
    unhook_syscalln(__NR_compat_newfstatat, before_fstatat, NULL);
#endif

#ifdef __NR_access
    unhook_syscalln(__NR_access, before_access, NULL);
#elif defined(__NR_compat_access)
    unhook_syscalln(__NR_compat_access, before_access, NULL);
#elif defined(__NR_faccessat)
    unhook_syscalln(__NR_faccessat, before_access, NULL);
#elif defined(__NR_compat_faccessat)
    unhook_syscalln(__NR_compat_faccessat, before_access, NULL);
#endif
    pr_info("[HMA++]已回滚所有已挂钩syscall，无内核残留\n");
}

static long mkdir_hook_init(const char *args, const char *event, void *reserved) {
    hook_err_t err;
    spin_lock_init(&g_count_lock);
    memset(g_intercept_count, 0, sizeof(g_intercept_count));
    g_module_running = 0;

    pr_info("[HMA++]开始加载模块，初始化核心资源...\n");
    
    // 核心syscall挂钩
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { 
        pr_err("[HMA++]核心syscall mkdirat挂钩失败：%d，加载中断\n", err);
        return -EINVAL; 
    }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { 
        pr_err("[HMA++]核心syscall chdir挂钩失败：%d，开始回滚\n", err);
        unhook_all_hooked_syscall();
        return -EINVAL; 
    }
    err = -1;
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
#else
    pr_err("[HMA++]无核心删除syscall，加载中断\n");
    unhook_all_hooked_syscall();
    return -EINVAL;
#endif
    if (err) { 
        pr_err("[HMA++]核心syscall rmdir挂钩失败：%d，开始回滚\n", err);
        unhook_all_hooked_syscall();
        return -EINVAL; 
    }
    err = hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) { 
        pr_err("[HMA++]核心syscall openat挂钩失败：%d，开始回滚\n", err);
        unhook_all_hooked_syscall();
        return -EINVAL; 
    }
    err = hook_syscalln(__NR_getpid, 0, before_getpid, NULL, NULL);
    if (err) { 
        pr_err("[HMA++]核心syscall getpid挂钩失败：%d，开始回滚\n", err);
        unhook_all_hooked_syscall();
        return -EINVAL; 
    }

    // 非核心syscall挂钩
    err = -1;
#ifdef __NR_fstatat
    err = hook_syscalln(__NR_fstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_newfstatat)
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_compat_fstatat64)
    err = hook_syscalln(__NR_compat_fstatat64, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_compat_newfstatat)
    err = hook_syscalln(__NR_compat_newfstatat, 4, before_fstatat, NULL, NULL);
#endif
    if (err) pr_warn("[HMA++]非核心syscall fstatat挂钩失败：%d，不影响核心功能\n", err);

    err = -1;
#ifdef __NR_access
    err = hook_syscalln(__NR_access, 2, before_access, NULL, NULL);
#elif defined(__NR_compat_access)
    err = hook_syscalln(__NR_compat_access, 2, before_access, NULL, NULL);
#elif defined(__NR_faccessat)
    err = hook_syscalln(__NR_faccessat, 4, before_access, NULL, NULL);
#elif defined(__NR_compat_faccessat)
    err = hook_syscalln(__NR_compat_faccessat, 4, before_access, NULL, NULL);
#endif
    if (err) pr_warn("[HMA++]非核心syscall access挂钩失败：%d，不影响核心功能\n", err);

    g_module_running = 1;
    pr_info("[HMA++]模块加载成功！核心功能已就绪\n");
    print_work_status("模块加载完成");
    return 0;
}

static long mkdir_hook_exit(void *reserved) {
    pr_info("[HMA++]开始卸载模块，清理资源...\n");
    g_module_running = 0;

    unhook_all_hooked_syscall();

    print_work_status("模块卸载前");
    pr_info("[HMA++]模块卸载完成！无内核资源残留\n");
    return 0;
}

// -------------------------- 模块入口出口 --------------------------
KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
