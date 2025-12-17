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

// 模块元信息（单开关控制）
KPM_NAME("HMA++ Mini");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("单开关控制+最小可加载（0=关闭，1=开启）");

// 全局唯一开关（统一控制整个模块）
static bool hma_global_enabled = true;

// 适配 arm64 内核 syscall 号（根据实际内核调整，x86 改为 295）
#ifndef __NR_openat
#define __NR_openat 56
#endif

// 简化挂钩逻辑：开关控制是否打印日志
static void before_openat(hook_fargs5_t *args, void *udata) {
    if (!hma_global_enabled) return;

    char path[PATH_MAX] = {0};
    if (syscall_argn(args, 1) == NULL) return;

    // 仅保留框架兼容的读取函数，避免其他依赖
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len > 0) {
        path[len] = '\0';
        pr_info("[HMA++] 触发 openat：%s\n", path);
    }
}

// 模块初始化（仅挂钩 openat，简化逻辑）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] 初始化开始（单开关模式）\n");

    // 检查框架核心函数是否存在
    if (!hook_syscalln) {
        pr_err("[HMA++] 错误：KernelPatch 框架未安装！\n");
        return -ENOENT;
    }

    // 仅挂钩 openat，减少干扰
    err = hook_syscalln(__NR_openat, 5, before_openat, NULL, NULL);
    if (err) {
        pr_err("[HMA++] 挂钩 openat 失败：%d\n", err);
        return -EINVAL;
    }

    pr_info("[HMA++] 初始化成功（当前状态：开启）\n");
    return 0;
}

// 单接口控制：0=关闭，1=开启（无用户空间写入，避免编译报错）
static long hma_control0(const char *args, char *__user out_msg, int outlen) {
    if (!args || strlen(args) != 1) {
        pr_warn("[HMA++] 控制参数错误：仅支持 0（关闭）或 1（开启）\n");
        return 0;
    }

    switch (args[0]) {
        case '0':
            hma_global_enabled = false;
            pr_info("[HMA++] 模块已关闭\n");
            break;
        case '1':
            hma_global_enabled = true;
            pr_info("[HMA++] 模块已开启\n");
            break;
        default:
            pr_warn("[HMA++] 无效参数：%c\n", args[0]);
            break;
    }
    return 0;
}

// 模块退出（仅解钩 openat）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++] 退出模块\n");
    unhook_syscalln(__NR_openat, before_openat, NULL);
    return 0;
}

// 仅注册一个控制接口（删除 KPM_CTL1）
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_EXIT(mkdir_hook_exit);
