#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h> // For __NR_mkdirat
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/errno.h>    // For EACCES and EPERM
#include <accctl.h>         // For set_priv_sel_allow and related functions
#include <uapi/linux/limits.h>   // For PATH_MAX
#include <linux/kernel.h>   // For snprintf
#include <linux/spinlock.h> // 新增：线程安全计数所需头文件

KPM_NAME("HMA++ Next");
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("测试更新（新增自定义路径隐藏+工作状态显示）");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

// 内置 deny list（包名，保留原有全部核心配置，修正语法错误：补充缺失逗号）
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
    "bin.mt.plus", // 修正：补充缺失逗号，避免语法错误
    "com.reveny.nativecheck",
    "chunqiu.safe.detector",
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

// 核心拦截文件夹列表（8大类高频风险，剔除冗余低概率项，精准防护）
static const char *deny_folder_list[] = {
    // 1.Hook/注入核心风险（最常用违规场景）
    "xposed_temp",
    "lsposed_cache",
    "hook_inject_data",
    "xp_module_cache",
    "lspatch_temp",
    "hook_framework",
    // 2.ROOT/系统篡改（高权限违规）
    "magisk_temp",
    "ksu_cache",
    "system_modify",
    "root_tool_data",
    "kernel_mod_dir",
    // 3.隐私窃取/数据泄露（核心安全风险）
    "privacy_steal",
    "data_crack",
    "info_collect",
    "secret_monitor",
    "data_leak_dir",
    // 4.违规应用安装/篡改（应用安全核心）
    "apk_modify",
    "pirate_apk",
    "app_cracked",
    "patch_apk_dir",
    "illegal_install",
    // 5.终端/脚本运行（命令执行风险）
    "termux_data",
    "apktool_temp",
    "reverse_engineer",
    "hack_tool_data",
    "shell_script",
    // 6.模拟器/虚拟环境（环境欺骗违规）
    "emulator_data",
    "virtual_env",
    "fake_device",
    "emulator_cache",
    // 7.恶意插件/广告（骚扰+安全风险）
    "ad_plugin",
    "malicious_plugin",
    "plugin_hack",
    "ad_inject",
    // 8.风险临时操作（动态违规拦截）
    "risk_temp",
    "malicious_dir",
    "temp_hack",
    "unsafe_cache"
    "com.tsng.hidemyapplist",
    "com.termux",
    "lsposed_cache",
    "magisk_temp",
    "privacy_steal",
    "apk_modify",
    "emulator_data",
    "ad_plugin",
    "risk_temp",
    "hook_inject_data"
    "modules",
    "ap",
    "ksu",
    "zygisksu",
    "tricky_store",
    "agh",
    "apd",
    "susfs4ksu",
    "lsp",
    
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 整合包名+文件夹拦截逻辑，精准判断是否命中规则（原有逻辑不变）
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
    
    // 包名校验
    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    // 文件夹校验
    for (size_t k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// -------------------------- 新增：自定义路径隐藏+工作状态相关代码 --------------------------
// 1. 工作状态核心配置与变量（线程安全）
#define STATUS_QUERY_MAGIC 0x12345678 // 手动查询触发魔术值（唯一标识）
static int g_module_running = 0; // 模块运行状态：0=未运行，1=正常运行
// 拦截计数：0=mkdirat,1=chdir,2=rmdir/unlinkat,3=fstatat,4=openat（文件打开）,5=access（路径访问）
static unsigned long g_intercept_count[6] = {0};
static spinlock_t g_count_lock; // 自旋锁：保证多线程计数准确
static const char *op_name_map[] = { // 操作名称映射（日志显示用）
    "mkdirat(创建)", "chdir(进入)", "unlinkat(删除)", "fstatat(查询)", "openat(打开)", "access(访问)"
};

// 2. 新增：路径隐藏核心判断（含文件夹及内部所有文件/子目录）
static int is_hide_target(const char *path) {
    if (!path || strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    const char *path_after_root = path + TARGET_PATH_LEN;
    if (*path_after_root == '\0') return 0;

    // 提取根目录下一级目录名（判断是否在拦截列表）
    char target_buf[128];
    size_t i = 0;
    while (*path_after_root && *path_after_root != '/' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *path_after_root++;
    }
    target_buf[i] = '\0';

    // 校验是否命中包名列表或文件夹列表（命中则该目录及内部所有内容均隐藏）
    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    for (size_t k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// 3. 新增：线程安全更新拦截计数
static void update_intercept_count(int op_idx) {
    spin_lock(&g_count_lock);
    g_intercept_count[op_idx]++;
    spin_unlock(&g_count_lock);
}

// 4. 新增：工作状态打印函数（加载/退出/手动查询触发）
static void print_work_status(const char *trigger) {
    pr_info("[HMA++]===== 工作状态报告（触发：%s）=====\n", trigger);
    pr_info("[HMA++]模块运行状态：%s\n", g_module_running ? "✅ 正常运行" : "❌ 已停止");
    pr_info("[HMA++]监控根目录：%s\n", TARGET_PATH);
    pr_info("[HMA++]拦截目标总数：包名%d个 + 文件夹%d个 = %d个\n", 
            DENY_LIST_SIZE, DENY_FOLDER_SIZE, DENY_LIST_SIZE + DENY_FOLDER_SIZE);
    pr_info("[HMA++]累计拦截统计：\n");
    for (int i = 0; i < 6; ++i) {
        pr_info("[HMA++]  - %s：%lu 次\n", op_name_map[i], g_intercept_count[i]);
    }
    pr_info("[HMA++]================================\n");
}

// 5. 新增：手动触发状态查询钩子（挂钩getpid，无侵入性）
static void before_getpid(hook_fargs0_t *args, void *udata) {
    // 触发条件：调用getpid时传递魔术值 STATUS_QUERY_MAGIC
    unsigned long magic = (unsigned long)syscall_argn(args, 0);
    if (magic == STATUS_QUERY_MAGIC) {
        print_work_status("手动查询");
        args->ret = 0; // 返回0表示查询成功（区别于正常getpid返回进程号）
        args->skip_origin = 1; // 跳过原getpid调用，避免干扰
    }
}

// 6. 新增：openat钩子（拦截隐藏文件夹内文件打开，实现文件级隐藏）
static void before_openat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(4);
        pr_warn("[HMA++]openat: Denied hide target (file open) %s（累计：%lu次）\n", filename_kernel, g_intercept_count[4]);
        args->skip_origin = 1;
        args->ret = -ENOENT; // 返回不存在，模拟隐藏效果
    }
}

// 7. 新增：access钩子（拦截隐藏路径访问，增强隐藏稳定性）
static void before_access(hook_fargs2_t *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(5);
        pr_warn("[HMA++]access: Denied hide target (path access) %s（累计：%lu次）\n", filename_kernel, g_intercept_count[5]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
// -------------------------- 新增代码结束 --------------------------

// mkdirat钩子：拦截违规文件夹创建（原有逻辑不变）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        // 新增：更新拦截计数
        update_intercept_count(0);
        pr_warn("[HMA++]mkdirat: Denied by block rule to create %s（累计：%lu次）\n", filename_kernel, g_intercept_count[0]);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// chdir钩子：拦截违规文件夹访问（原有逻辑不变，新增计数）
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        // 新增：更新拦截计数
        update_intercept_count(1);
        pr_warn("[HMA++]chdir: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[1]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// rmdir/unlinkat钩子：拦截违规文件夹删除（原有逻辑不变，新增计数）
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        // 新增：更新拦截计数
        update_intercept_count(2);
        pr_warn("[HMA++]rmdir/unlinkat: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[2]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// fstatat钩子：拦截违规文件夹状态查询（原有逻辑不变，新增计数）
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        // 新增：更新拦截计数
        update_intercept_count(3);
        pr_warn("[HMA++]fstatat/stat: Denied by block rule to %s（累计：%lu次）\n", filename_kernel, g_intercept_count[3]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 模块初始化：挂钩目标syscall（原有逻辑不变，新增挂钩新增syscall）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    // 新增：初始化自旋锁+计数清零
    spin_lock_init(&g_count_lock);
    memset(g_intercept_count, 0, sizeof(g_intercept_count));
    g_module_running = 1; // 标记模块正常运行

    pr_info("[HMA++]HMA++ init. Hooking core syscalls...\n");
    
    // 挂钩原有syscall（逻辑不变）
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
#endif
    if (err) { pr_err("[HMA++]Hook fstatat failed: %d\n", err); return -EINVAL; }
    
    // 新增：挂钩新增syscall（openat/access/getpid）
    err = hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook openat failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_access, 2, before_access, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook access failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_getpid, 0, before_getpid, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook getpid (status query) failed: %d\n", err); return -EINVAL; }
    
    pr_info("[HMA++]All core syscalls hooked successfully.\n");
    // 新增：打印初始化完成状态
    print_work_status("模块加载完成");
    return 0;
}

// 模块退出：解绑syscall（原有逻辑不变，新增解绑新增syscall）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++]HMA++ exit. Unhooking syscalls...\n");
    g_module_running = 0; // 标记模块停止运行

    // 解绑原有syscall（逻辑不变）
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
    
    // 新增：解绑新增syscall
    unhook_syscalln(__NR_openat, before_openat, NULL);
    unhook_syscalln(__NR_access, before_access, NULL);
    unhook_syscalln(__NR_getpid, before_getpid, NULL);

    pr_info("[HMA++]All syscalls unhooked successfully.\n");
    // 新增：打印退出前状态
    print_work_status("模块卸载前");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
