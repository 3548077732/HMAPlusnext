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
#include <linux/spinlock.h> // 自旋锁，保证统计线程安全

KPM_NAME("CustomPathHide");
KPM_VERSION("0.0.6");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("自定义路径隐藏（隐藏指定文件夹及内部所有文件）");

// 1. 配置：目标根目录（仅隐藏此目录下的列表内文件夹）
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

// 2. 工作状态核心变量（自旋锁保证多线程安全）
static int g_module_running = 0; // 模块运行状态：0=未加载，1=正常运行
static unsigned long g_intercept_count[5] = {0}; // 各类操作拦截次数：0=mkdirat,1=chdir,2=unlinkat,3=fstatat,4=openat
static spinlock_t g_count_lock; // 统计计数锁

// 操作名称映射（日志显示用）
static const char *op_name_map[] = {
    "mkdirat(创建)",
    "chdir(进入)",
    "unlinkat(删除)",
    "fstatat(查询)",
    "openat(打开)"
};

// 3. 核心判断：路径是否属于需隐藏目标（含文件夹及内部所有内容）
static int is_hide_target(const char *path) {
    if (strncmp(path, ROOT_HIDE_PATH, ROOT_PATH_LEN) != 0) return 0;
    const char *path_after_root = path + ROOT_PATH_LEN;
    
    for (size_t i = 0; i < HIDE_LIST_SIZE; i++) {
        size_t hide_len = strlen(hide_folder_list[i]);
        if (strncmp(path_after_root, hide_folder_list[i], hide_len) == 0) {
            char next = path_after_root[hide_len];
            if (next == '\0' || next == '/') return 1;
        }
    }
    return 0;
}

// 4. 辅助函数：更新拦截计数（线程安全）
static void update_intercept_count(int op_idx) {
    spin_lock(&g_count_lock);
    g_intercept_count[op_idx]++;
    spin_unlock(&g_count_lock);
}

// 5. 辅助函数：打印当前工作状态（加载/退出时自动调用，也可手动触发）
static void print_work_status(const char *trigger) {
    pr_info("[PathHide]===== 工作状态报告（触发：%s）=====\n", trigger);
    pr_info("[PathHide]模块运行状态：%s\n", g_module_running ? "✅ 正常运行" : "❌ 已停止");
    pr_info("[PathHide]监控根目录：%s\n", ROOT_HIDE_PATH);
    pr_info("[PathHide]隐藏文件夹数量：%zu\n", HIDE_LIST_SIZE);
    pr_info("[PathHide]累计拦截统计：\n");
    for (int i = 0; i < 5; i++) {
        pr_info("[PathHide]  - %s：%lu 次\n", op_name_map[i], g_intercept_count[i]);
    }
    pr_info("[PathHide]================================\n");
}

// -------------------------- 系统调用钩子（含计数更新）--------------------------
// 拦截创建操作（mkdirat）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return; // 模块未运行，放行
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(0);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[0], filename_kernel, g_intercept_count[0]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 拦截进入操作（chdir）
static void before_chdir(hook_fargs1_t *args, void *udata) {
    if (!g_module_running) return;
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(1);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[1], filename_kernel, g_intercept_count[1]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 拦截删除操作（unlinkat/rmdir）
static void before_unlinkat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(2);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[2], filename_kernel, g_intercept_count[2]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 拦截查询操作（fstatat/stat）
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(3);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[3], filename_kernel, g_intercept_count[3]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 拦截打开操作（openat）
static void before_openat(hook_fargs4_t *args, void *udata) {
    if (!g_module_running) return;
    
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (is_hide_target(filename_kernel)) {
        update_intercept_count(4);
        pr_warn("[PathHide]拦截 %s 操作：%s（累计：%lu次）\n", op_name_map[4], filename_kernel, g_intercept_count[4]);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// -------------------------- 模块初始化/退出（含状态管理）--------------------------
static long path_hide_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    spin_lock_init(&g_count_lock); // 初始化计数锁
    memset(g_intercept_count, 0, sizeof(g_intercept_count)); // 计数清零
    
    pr_info("[PathHide]开始加载模块...\n");
    // 挂钩核心系统调用
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 mkdirat 失败：%d\n", err); return -EINVAL; }
    
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 chdir 失败：%d\n", err); return -EINVAL; }
    
    err = hook_syscalln(__NR_unlinkat, 4, before_unlinkat, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 unlinkat 失败：%d\n", err); return -EINVAL; }
    
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
#endif
    if (err) { pr_err("[PathHide]挂钩 fstatat 失败：%d\n", err); return -EINVAL; }
    
    err = hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) { pr_err("[PathHide]挂钩 openat 失败：%d\n", err); return -EINVAL; }
    
    g_module_running = 1; // 标记模块正常运行
    pr_info("[PathHide]模块加载完成，已启动隐藏功能！\n");
    print_work_status("模块加载完成"); // 打印初始状态
    return 0;
}

static long path_hide_exit(void *__user reserved) {
    pr_info("[PathHide]开始卸载模块...\n");
    g_module_running = 0; // 标记模块停止运行
    
    // 解绑所有系统调用
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
    unhook_syscalln(__NR_unlinkat, before_unlinkat, NULL);
#ifdef __NR_newfstatat
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#endif
    unhook_syscalln(__NR_openat, before_openat, NULL);
    
    print_work_status("模块卸载前"); // 打印最终运行统计
    pr_info("[PathHide]模块卸载完成，所有功能已停止！\n");
    return 0;
}

KPM_INIT(path_hide_init);
KPM_EXIT(path_hide_exit);
