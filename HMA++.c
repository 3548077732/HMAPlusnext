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

// 模块元信息（极简，符合KPM规范）
KPM_NAME("HMA++ Mini");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("最小可加载版本（仅验证挂钩+加载）");

// 全局开关（简化为单个开关，减少变量干扰）
static bool hma_enabled = true;

// 适配 arm64 内核 syscall 号（根据实际内核调整，此处为通用值）
#ifndef __NR_openat
#define __NR_openat 56  // arm64 通用 syscall 号，x86 需改为 295
#endif

// 简化挂钩逻辑：仅打印日志，不做任何拦截（验证挂钩是否生效）
static void before_openat(hook_fargs5_t *args, void *udata) {
    if (!hma_enabled) return;

    char path[PATH_MAX] = {0};
    // 安全读取用户空间路径（使用 KernelPatch 兼容函数 kf_strncpy_from_user）
    if (syscall_argn(args, 1) == NULL) {
        pr_warn("[HMA++] openat: 空路径\n");
        return;
    }

    // 替换 strncpy_from_user → kf_strncpy_from_user（框架兼容函数）
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) {
        pr_warn("[HMA++] openat: 路径读取失败\n");
        return;
    }
    path[len] = '\0';

    // 仅打印触发的路径，不拦截（验证挂钩生效）
    pr_info("[HMA++] openat triggered: %s\n", path);
}

// 模块初始化（仅挂钩 openat，简化逻辑）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] 最小版本 init 开始\n");

    // 检查 hook_syscalln 符号（避免框架未安装）
    if (!hook_syscalln) {
        pr_err("[HMA++] 错误：未找到 hook_syscalln，KernelPatch 框架未安装？\n");
        return -ENOENT;
    }

    // 仅挂钩 openat（减少其他挂钩点干扰）
    err = hook_syscalln(__NR_openat, 5, before_openat, NULL, NULL);
    if (err) {
        pr_err("[HMA++] 挂钩 openat 失败：%d\n", err);
        return -EINVAL;
    }

    pr_info("[HMA++] 最小版本 init 成功（仅挂钩 openat）\n");
    return 0;
}

// 风险拦截控制（简化参数处理）
static long hma_control0(const char *args, char *__user out_msg, int outlen) {
    char msg[64] = {0};
    if (!args || strlen(args) != 1) {
        strncpy(msg, "参数：0=关闭，1=开启", sizeof(msg)-1);
        goto out;
    }

    hma_enabled = (args[0] == '1');
    snprintf(msg, sizeof(msg)-1, "HMA状态：%s", hma_enabled ? "开启" : "关闭");

out:
    if (out_msg && outlen >= strlen(msg) + 1) {
        // 替换 strncpy_to_user → kf_strncpy_to_user（框架兼容函数）
        kf_strncpy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

// 广告拦截控制（适配 KPM_CTL1 接口，仅占位）
static long hma_control1(void *a1, void *a2, void *a3) {
    char *__user out_msg = (char *__user)a2;
    int outlen = (int)(unsigned long)a3;
    char msg[] = "广告控制暂未启用（最小版本）";

    if (out_msg && outlen >= sizeof(msg)) {
        // 替换 strncpy_to_user → kf_strncpy_to_user（框架兼容函数）
        kf_strncpy_to_user(out_msg, msg, sizeof(msg));
    }
    return 0;
}

// 模块退出（仅解钩 openat）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++] 最小版本 exit 开始\n");
    unhook_syscalln(__NR_openat, before_openat, NULL);
    pr_info("[HMA++] 最小版本 exit 成功\n");
    return 0;
}

// 模块注册（符合KPM规范）
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
