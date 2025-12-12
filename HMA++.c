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
#include <asm/uaccess.h>

// -------------------------- APatch专属适配宏（强制规范，确保识别）--------------------------
#define APATCH_COMPATIBLE 1          // 标识APatch兼容模块
#define PATH_MAX_FIX 4096            // 固定路径缓冲区大小，避免APatch内核定义差异
#define KPM_LOG_PREFIX "[HMA++_APatch]" // 简化日志前缀，适配APatch日志解析

// -------------------------- 模块基础信息（APatch精简规范，无冗余字符）--------------------------
KPM_NAME("HMA++_APatch");
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("Path hide & syscall intercept for APatch"); // 短描述，APatch解析无压力

// -------------------------- 核心宏定义（APatch内核精准适配）--------------------------
#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN ((unsigned int)sizeof(TARGET_PATH) - 1)
#define STATUS_QUERY_MAGIC 0x12345678
#define MAX_TARGET_NAME_LEN 127
// APatch标准syscall参数个数（精准匹配APatch hook接口定义）
#define SYSCALL_MKDIRAT_ARGC 3
#define SYSCALL_CHDIR_ARGC 1
#define SYSCALL_UNLINKAT_ARGC 3
#define SYSCALL_OPENAT_ARGC 4
#define SYSCALL_GETPID_ARGC 0

// -------------------------- 拦截列表（精简有效，减少加载内存占用）--------------------------
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
    "com.termux", "com.suqi8.oshin", "me.hd.wauxv", "miko.client", "com.kooritea.fcmfix",
    "com.twifucker.hachidori", "com.luckyzyx.luckytool", "com.padi.hook.hookqq", "cn.lyric.getter",
    "com.parallelc.micts", "me.plusne", "com.hchen.appretention", "com.hchen.switchfreeform",
    "name.monwf.customiuizer", "com.houvven.impad", "cn.aodlyric.xiaowine", "top.sacz.timtool",
    "nep.timeline.re_telegram", "com.fuck.android.rimet", "cn.kwaiching.hook", "cn.android.x",
    "cc.aoeiuv020.iamnotdisabled.hook", "vn.kwaiching.tao", "com.nnnen.plusne", "com.fkzhang.wechatxposed",
    "one.yufz.hmspush", "cn.fuckhome.xiaowine", "com.fankes.tsbattery", "me.gm.cleaner",
    "moe.shizuku.redirectstorage", "org.lsposed.manager", "com.fankes.enforcehighrefreshrate",
    "dev.device.emulator", "com.android1500.androidfaker", "com.smartpack.kernelmanager",
    "bin.mt.plus", "com.reveny.nativecheck", "chunqiu.safe.detector"
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

// -------------------------- 全局变量（APatch线程安全初始化）--------------------------
static int g_module_running = 0;                  // 加载成功后再激活，默认关闭
static unsigned long g_intercept_count[6] = {0};  // 拦截计数，初始化清零
static spinlock_t g_count_lock = __SPIN_LOCK_UNLOCKED; // APatch推荐锁初始化方式
static const char *op_name_map[] = {              // 无特殊字符，APatch日志兼容
    "mkdirat(创建)", "chdir(进入)", "unlinkat(删除)", "fstatat(查询)", "openat(打开)", "access(访问)"
};

// -------------------------- 函数原型声明（APatch解析优先，无符号缺失）--------------------------
static int is_blocked_path(const char *path);
static int is_hide_target(const char *path);
static void update_intercept_count(int op_idx);
static void print_work_status(const char *trigger);
static void before_getpid(hook_fargs0_t *args, void *udata);
static void before_openat(hook_fargs4_t *args, void *udata);
static void before_mkdirat(hook_fargs4_t *args, void *udata);
static void before_chdir(hook_fargs4_t *args, void *udata);
static void before_unlinkat(hook_fargs4_t *args, void *udata);
static long hma_apatch_init(const char *args, const char *event, void *reserved); // APatch专属初始化函数
static long hma_apatch_exit(void *reserved);
static void unhook_all_syscalls(void);

// -------------------------- 核心工具函数（APatch安全适配，防内核保护）--------------------------
static int is_blocked_path(const char *path) {
    if (!path || *path == '\0') return 0;
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    
    const char *target_part = path + TARGET_PATH_LEN;
    if (*target_part == '\0') return 0;
    
    char target_buf[MAX_TARGET_NAME_LEN + 1] = {0};
    unsigned int i = 0;
    while (*target_part && *target_part != '/' && *target_part != '\\' && i < MAX_TARGET_NAME_LEN) {
        target_buf[i++] = *target_part++;
    }
    
    for (unsigned int j = 0; j < DENY_LIST_SIZE; ++j) {
        if (!deny_list[j]) continue;
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (unsigned int k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (!deny_folder_list[k]) continue;
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

static int is_hide_target(const char *path) {
    if (!path || *path == '\0') return 0;
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    
    const char *target_part = path + TARGET_PATH_LEN;
    if (*target_part == '\0') return 0;
    
    char target_buf[MAX_TARGET_NAME_LEN + 1] = {0};
    unsigned int i = 0;
    while (*target_part && *target_part != '/' && i < MAX_TARGET_NAME_LEN) {
        target_buf[i++] = *target_part++;
    }
    
    for (unsigned int j = 0; j < DENY_LIST_SIZE; ++j) {
        if (!deny_list[j]) continue;
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (unsigned int k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (!deny_folder_list[k]) continue;
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

static void update_intercept_count(int op_idx) {
    if (op_idx < 0 || op_idx >= 6) return;
    unsigned long flags;
    spin_lock_irqsave(&g_count_lock, flags); // APatch中断安全锁规范
    g_intercept_count[op_idx]++;
    spin_unlock_irqrestore(&g_count_lock, flags);
}

// 简化日志，减少APatch日志缓冲区压力
static void print_work_status(const char *trigger) {
    if (!trigger) trigger = "unknown";
    pr_info("%s ===== 模块状态（触发：%s）=====\n", KPM_LOG_PREFIX, trigger);
    pr_info("%s 运行状态：%s\n", KPM_LOG_PREFIX, g_module_running ? "ok" : "stop");
    pr_info("%s 监控目录：%s\n", KPM_LOG_PREFIX, TARGET_PATH);
    pr_info("%s 拦截目标数：%d\n", KPM_LOG_PREFIX, DENY_LIST_SIZE + DENY_FOLDER_SIZE);
    pr_info("%s ===============================\n", KPM_LOG_PREFIX);
}

// -------------------------- Syscall钩子函数（APatch精准适配，无异常触发）--------------------------
// getpid钩子：APatch无侵入适配，仅响应魔术值
static void before_getpid(hook_fargs0_t *args, void *udata) {
    if (!g_module_running || !args) return;
    unsigned long magic = syscall_argn(args, 0);
    if (magic == STATUS_QUERY_MAGIC) {
        print_work_status("manual_query");
        args->ret = 0;                  // APatch要求返回0标识处理成功
        args->skip_origin = 1;          // 必须后置赋值，符合APatch流程
    }
}

// openat钩子：APatch拷贝安全适配，核心隐藏功能
static void before_openat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running || !args) return;
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    if (!filename_user || !access_ok(VERIFY_READ, filename_user, 1)) { // APatch用户空间权限校验
        return;
    }
    
    char filename_kernel[PATH_MAX_FIX] = {0};
    // APatch推荐拷贝逻辑，强化容错
    long len = kf_strncpy_from_user(filename_kernel, filename_user, PATH_MAX_FIX - 1);
    if (len < 0) {
        pr_warn("%s openat copy fail: %ld\n", KPM_LOG_PREFIX, len);
        return;
    }
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(4);
        pr_warn("%s openat deny: %s (cnt:%lu)\n", KPM_LOG_PREFIX, filename_kernel, g_intercept_count[4]);
        args->skip_origin = 1;
        args->ret = -ENOENT; // APatch标准错误码，模拟路径不存在
    }
}

// mkdirat钩子：APatch核心拦截适配
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running || !args) return;
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    if (!filename_user || !access_ok(VERIFY_READ, filename_user, 1)) {
        return;
    }
    
    char filename_kernel[PATH_MAX_FIX] = {0};
    long len = kf_strncpy_from_user(filename_kernel, filename_user, PATH_MAX_FIX - 1);
    if (len < 0) {
        pr_warn("%s mkdirat copy fail: %ld\n", KPM_LOG_PREFIX, len);
        return;
    }
    filename_kernel[len] = '\0';
    
    if (is_blocked_path(filename_kernel)) {
        update_intercept_count(0);
        pr_warn("%s mkdirat deny: %s (cnt:%lu)\n", KPM_LOG_PREFIX, filename_kernel, g_intercept_count[0]);
        args->skip_origin = 1;
        args->ret = -EACCES; // APatch标准权限拒绝码
    }
}

// chdir钩子：APatch核心拦截适配
static void before_chdir(hook_fargs4_t *args, void *udata) {
    if (!g_module_running || !args) return;
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    if (!filename_user || !access_ok(VERIFY_READ, filename_user, 1)) {
        return;
    }
    
    char filename_kernel[PATH_MAX_FIX] = {0};
    long len = kf_strncpy_from_user(filename_kernel, filename_user, PATH_MAX_FIX - 1);
    if (len < 0) {
        pr_warn("%s chdir copy fail: %ld\n", KPM_LOG_PREFIX, len);
        return;
    }
    filename_kernel[len] = '\0';
    
    if (is_blocked_path(filename_kernel)) {
        update_intercept_count(1);
        pr_warn("%s chdir deny: %s (cnt:%lu)\n", KPM_LOG_PREFIX, filename_kernel, g_intercept_count[1]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// unlinkat钩子：APatch核心拦截适配，参数精准匹配
static void before_unlinkat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running || !args) return;
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    if (!filename_user || !access_ok(VERIFY_READ, filename_user, 1)) {
        return;
    }
    
    char filename_kernel[PATH_MAX_FIX] = {0};
    long len = kf_strncpy_from_user(filename_kernel, filename_user, PATH_MAX_FIX - 1);
    if (len < 0) {
        pr_warn("%s unlinkat copy fail: %ld\n", KPM_LOG_PREFIX, len);
        return;
    }
    filename_kernel[len] = '\0';
    
    if ((flags & 0x200) && is_blocked_path(filename_kernel)) {
        update_intercept_count(2);
        pr_warn("%s unlinkat deny: %s (cnt:%lu)\n", KPM_LOG_PREFIX, filename_kernel, g_intercept_count[2]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// -------------------------- 模块加载/卸载核心逻辑（APatch规范，无残留）--------------------------
// 解绑所有syscall：APatch要求反向解绑，彻底清理
static void unhook_all_syscalls(void) {
    unhook_syscalln(__NR_getpid, before_getpid, NULL);
    unhook_syscalln(__NR_openat, before_openat, NULL);
#if defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_unlinkat, NULL);
#endif
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    pr_info("%s all syscalls unhooked\n", KPM_LOG_PREFIX);
}

// APatch专属初始化函数：流程简化，核心优先，回滚彻底
static long hma_apatch_init(const char *args, const char *event, void *reserved) {
    hook_err_t err;
    g_module_running = 0; // 未加载完成，禁止处理请求

    pr_info("%s start load...\n", KPM_LOG_PREFIX);
    
    // 仅挂钩核心syscall（减少APatch加载依赖，提高成功率）
    // 1. 挂钩mkdirat
    err = hook_syscalln(__NR_mkdirat, SYSCALL_MKDIRAT_ARGC, before_mkdirat, NULL, NULL);
    if (err) { 
        pr_err("%s hook mkdirat fail: %d\n", KPM_LOG_PREFIX, err);
        return -EINVAL; 
    }
    // 2. 挂钩chdir
    err = hook_syscalln(__NR_chdir, SYSCALL_CHDIR_ARGC, before_chdir, NULL, NULL);
    if (err) { 
        pr_err("%s hook chdir fail: %d\n", KPM_LOG_PREFIX, err);
        unhook_all_syscalls();
        return -EINVAL; 
    }
    // 3. 挂钩unlinkat
    err = -1;
#if defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, SYSCALL_UNLINKAT_ARGC, before_unlinkat, NULL, NULL);
#else
    pr_err("%s no unlinkat syscall\n", KPM_LOG_PREFIX);
    unhook_all_syscalls();
    return -EINVAL;
#endif
    if (err) { 
        pr_err("%s hook unlinkat fail: %d\n", KPM_LOG_PREFIX, err);
        unhook_all_syscalls();
        return -EINVAL; 
    }
    // 4. 挂钩openat
    err = hook_syscalln(__NR_openat, SYSCALL_OPENAT_ARGC, before_openat, NULL, NULL);
    if (err) { 
        pr_err("%s hook openat fail: %d\n", KPM_LOG_PREFIX, err);
        unhook_all_syscalls();
        return -EINVAL; 
    }
    // 5. 挂钩getpid
    err = hook_syscalln(__NR_getpid, SYSCALL_GETPID_ARGC, before_getpid, NULL, NULL);
    if (err) { 
        pr_err("%s hook getpid fail: %d\n", KPM_LOG_PREFIX, err);
        unhook_all_syscalls();
        return -EINVAL; 
    }

    // 加载成功，激活模块
    g_module_running = 1;
    pr_info("%s load success!\n", KPM_LOG_PREFIX);
    print_work_status("load_done");
    return 0; // APatch要求返回0标识初始化成功
}

// APatch专属退出函数：先停止再清理，无内核保护触发
static long hma_apatch_exit(void *reserved) {
    pr_info("%s start unload...\n", KPM_LOG_PREFIX);
    g_module_running = 0; // 先停止运行，拒绝新请求

    unhook_all_syscalls();

    print_work_status("unload_before");
    pr_info("%s unload success!\n", KPM_LOG_PREFIX);
    return 0; // APatch要求返回0标识退出成功
}

// -------------------------- APatch模块入口出口（唯一规范，无解析冲突）--------------------------
KPM_INIT(hma_apatch_init);
KPM_EXIT(hma_apatch_exit);
