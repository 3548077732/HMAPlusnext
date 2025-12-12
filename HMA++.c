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
#include <linux/types.h>

// 全版本兼容宏定义（适配新旧内核，避免版本敏感API冲突）
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define COMPAT_SYS_CALL_ARG(args, idx) syscall_argn(args, idx)
#else
#define COMPAT_SYS_CALL_ARG(args, idx) ((args)->args[idx])
#endif

#if !defined(__NR_newfstatat) && defined(__NR_fstatat64)
#define __NR_newfstatat __NR_fstatat64
#endif

#if !defined(SYS_getpid)
#define SYS_getpid __NR_getpid
#endif

KPM_NAME("CustomPathHide");
KPM_VERSION("0.0.6");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("lshwjgpt and NightFallsLikeRain");
KPM_DESCRIPTION("自定义路径隐藏（全版本兼容+状态显示+手动查询）");

// 1. 核心配置（可直接修改适配需求）
#define ROOT_HIDE_PATH "/data/adb/"
#define ROOT_PATH_LEN (sizeof(ROOT_HIDE_PATH) - 1)

// 2. 配置：需隐藏的文件夹列表（仅对这些文件夹及内部所有内容生效）
static const char *hide_folder_list[] = {
    // 可自行增删修改，支持包名格式/普通文件夹名
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
#define HIDE_LIST_SIZE (sizeof(hide_folder_list)/sizeof(hide_folder_list[0]))

// 2. 手动查询配置（自定义触发标识，避免冲突）
#define STATUS_QUERY_MAGIC 0x12345678 // 触发魔术值，唯一标识查询请求

// 3. 工作状态核心变量（自旋锁保证多线程安全，全版本兼容）
static int g_module_running = 0; // 0=未加载，1=正常运行
static unsigned long g_intercept_count[5] = {0}; // 0=mkdirat,1=chdir,2=unlinkat,3=fstatat,4=openat
static spinlock_t g_count_lock; // 统计计数锁（内核基础组件，全版本支持）

// 操作名称映射（日志显示用）
static const char *op_name_map[] = {
    "mkdirat(创建)",
    "chdir(进入)",
    "unlinkat(删除)",
    "fstatat(查询)",
    "openat(打开)"
};

// 4. 核心判断：路径是否属于需隐藏目标（含文件夹及内部所有内容，无版本依赖）
static int is_hide_target(const char *path) {
    if (!path || strncmp(path, ROOT_HIDE_PATH, ROOT_PATH_LEN) != 0) {
        return 0;
    }
    const char *path_after_root = path + ROOT_PATH_LEN;
    if (*path_after_root == '\0') {
        return 0;
    }

    for (size_t i = 0; i < HIDE_LIST_SIZE; i++) {
        size_t hide_len = strlen(hide_folder_list[i]);
        if (strncmp(path_after_root, hide_folder_list[i], hide_len) == 0) {
            char next_char = path_after_root[hide_len];
            if (next_char == '\0' || next_char == '/') {
                return 1;
            }
        }
    }
    return 0;
}

// 5. 辅助函数：更新拦截计数（线程安全，全版本兼容）
static void update_intercept_count(int op_idx) {
    spin_lock(&g_count_lock);
    g_intercept_count[op_idx]++;
    spin_unlock(&g_count_lock);
}

// 6. 核心：工作状态打印函数（无版本敏感API，日志格式兼容所有终端）
static void print_work_status(const char *trigger) {
    pr_info("[PathHide]===== 工作状态报告（触发：%s）=====\n", trigger);
    pr_info("[PathHide]模块运行状态：%s\n", g_module_running ? "正常运行" : "已停止");
    pr_info("[PathHide]监控根目录：%s\n", ROOT_HIDE_PATH);
    pr_info("[PathHide]隐藏文件夹总数：%zu 个\n", HIDE_LIST_SIZE);
    pr_info("[PathHide]隐藏文件夹列表：\n");
    for (size_t i = 0; i < HIDE_LIST_SIZE; i++) {
        pr_info("[PathHide]    %zu. %s\n", i + 1, hide_folder_list[i]);
    }
    pr_info("[PathHide]累计拦截统计：\n");
    for (int i = 0; i < 5; i++) {
        pr_info("[PathHide]    %s：%lu 次\n", op_name_map[i], g_intercept_count[i]);
    }
    pr_info("[PathHide]================================\n");
}

// 7. 手动触发状态查询（挂钩getpid，全版本兼容参数传递）
static void before_getpid(void *args, void *udata) {
    // 兼容新旧内核参数获取方式
    unsigned long magic = (unsigned long)COMPAT_SYS_CALL_ARG(args, 0);
    if (magic == STATUS_QUERY_MAGIC) {
        print_work_status("手动查询（getpid触发）");
        // 兼容新旧内核返回值设置
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        ((struct hook_args *)args)->ret = 0;
        ((struct hook_args *)args)->skip_origin = 1;
#else
        ((struct syscall_hook_args *)args)->ret = 0;
        ((struct syscall_hook_args *)args)->skip = 1;
#endif
    }
}

// -------------------------- 系统调用钩子（全版本兼容适配）--------------------------
// 拦截创建操作（mkdirat）
static void before_mkdirat(void *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)COMPAT_SYS_CALL_ARG(args, 1);
    char filename_kernel[PATH_MAX];
    long len = 0;

    // 兼容不同内核copy_from_user逻辑
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    len = strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#else
    len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#endif
    if (len < 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';

    if (is_hide_target(filename_kernel)) {
        update_intercept_count(0);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[0], filename_kernel, g_intercept_count[0]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        ((struct hook_args *)args)->ret = -ENOENT;
        ((struct hook_args *)args)->skip_origin = 1;
#else
        ((struct syscall_hook_args *)args)->ret = -ENOENT;
        ((struct syscall_hook_args *)args)->skip = 1;
#endif
    }
}

// 拦截进入操作（chdir）
static void before_chdir(void *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)COMPAT_SYS_CALL_ARG(args, 0);
    char filename_kernel[PATH_MAX];
    long len = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    len = strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#else
    len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#endif
    if (len < 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';

    if (is_hide_target(filename_kernel)) {
        update_intercept_count(1);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[1], filename_kernel, g_intercept_count[1]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        ((struct hook_args *)args)->ret = -ENOENT;
        ((struct hook_args *)args)->skip_origin = 1;
#else
        ((struct syscall_hook_args *)args)->ret = -ENOENT;
        ((struct syscall_hook_args *)args)->skip = 1;
#endif
    }
}

// 拦截删除操作（unlinkat/rmdir）
static void before_unlinkat(void *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)COMPAT_SYS_CALL_ARG(args, 1);
    char filename_kernel[PATH_MAX];
    long len = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    len = strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#else
    len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#endif
    if (len < 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';

    if (is_hide_target(filename_kernel)) {
        update_intercept_count(2);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[2], filename_kernel, g_intercept_count[2]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        ((struct hook_args *)args)->ret = -ENOENT;
        ((struct hook_args *)args)->skip_origin = 1;
#else
        ((struct syscall_hook_args *)args)->ret = -ENOENT;
        ((struct syscall_hook_args *)args)->skip = 1;
#endif
    }
}

// 拦截查询操作（fstatat/stat）
static void before_fstatat(void *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)COMPAT_SYS_CALL_ARG(args, 1);
    char filename_kernel[PATH_MAX];
    long len = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    len = strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#else
    len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#endif
    if (len < 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';

    if (is_hide_target(filename_kernel)) {
        update_intercept_count(3);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[3], filename_kernel, g_intercept_count[3]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        ((struct hook_args *)args)->ret = -ENOENT;
        ((struct hook_args *)args)->skip_origin = 1;
#else
        ((struct syscall_hook_args *)args)->ret = -ENOENT;
        ((struct syscall_hook_args *)args)->skip = 1;
#endif
    }
}

// 拦截打开操作（openat）
static void before_openat(void *args, void *udata) {
    if (!g_module_running) return;

    const char __user *filename_user = (const char __user *)COMPAT_SYS_CALL_ARG(args, 1);
    char filename_kernel[PATH_MAX];
    long len = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    len = strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#else
    len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel) - 1);
#endif
    if (len < 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';

    if (is_hide_target(filename_kernel)) {
        update_intercept_count(4);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[4], filename_kernel, g_intercept_count[4]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        ((struct hook_args *)args)->ret = -ENOENT;
        ((struct hook_args *)args)->skip_origin = 1;
#else
        ((struct syscall_hook_args *)args)->ret = -ENOENT;
        ((struct syscall_hook_args *)args)->skip = 1;
#endif
    }
}

// -------------------------- 模块初始化/退出（全版本兼容）--------------------------
static long path_hide_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    spin_lock_init(&g_count_lock); // 自旋锁初始化（全版本支持）
    memset(g_intercept_count, 0, sizeof(g_intercept_count));

    pr_info("[PathHide]开始加载模块...\n");
    // 挂钩核心隐藏相关syscall（兼容不同内核钩子注册）
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 mkdirat 失败：%d\n", err); return -EINVAL; }

    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 chdir 失败：%d\n", err); return -EINVAL; }

    err = hook_syscalln(__NR_unlinkat, 4, before_unlinkat, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 unlinkat 失败：%d\n", err); return -EINVAL; }

    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 fstatat 失败：%d\n", err); return -EINVAL; }

    err = hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 openat 失败：%d\n", err); return -EINVAL; }

    // 挂钩getpid（手动查询触发）
    err = hook_syscalln(SYS_getpid, 0, before_getpid, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 getpid（状态查询）失败：%d\n", err); return -EINVAL; }

    g_module_running = 1;
    pr_info("[PathHide]模块加载完成，已启动隐藏功能！\n");
    print_work_status("模块加载完成");
    return 0;
}

static long path_hide_exit(void *__user reserved) {
    pr_info("[PathHide]开始卸载模块...\n");
    g_module_running = 0;

    // 解绑所有syscall（兼容不同内核钩子解绑）
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
    unhook_syscalln(__NR_unlinkat, before_unlinkat, NULL);
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
    unhook_syscalln(__NR_openat, before_openat, NULL);
    unhook_syscalln(SYS_getpid, before_getpid, NULL);

    print_work_status("模块卸载前");
    pr_info("[PathHide]模块卸载完成，所有功能已停止！\n");
    return 0;
}

KPM_INIT(path_hide_init);
KPM_EXIT(path_hide_exit);
