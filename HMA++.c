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

KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.4");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("全场景风险拦截测试");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)
#define MAX_PACKAGE_LEN 1024

// 内置 deny list（包名，保留原有全部配置）
static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free",
    "me.bingyue.IceCore",
    "com.modify.installer",
    "o.dyoo",
    "com.zhufucdev.motion_emulator",
    "com.xiaomi.shop",
    "",
    "",
    "com.demo.serendipity",
    "me.iacn.biliroaming",
    "me.teble.xposed.autodaily",
    "com.example.ourom",
    "dialog.box",
    "",
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
    "",
    "com.xayah.databackup.foss",
    "",
    "github.tornaco.android.thanos",
    "nep.timeline.freezer",
    "cn.geektang.privacyspace",
    "",
    "",
    "",
    "",
    "com.byyoung.setting",
    "",
    "cn.myflv.noactive",
    "",
    "",
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
    "",
    "com.ddm.qute",
    "",
    "kk.dk.anqu",
    "com.qq.qcxm",
    "",
    "dknb.con",
    "dknb.coo8",
    "com.tencent.jingshi",
    "com.tencent.JYNB",
    "com.apocalua.run",
    "com.coderstory.toolkit",
    "com.didjdk.adbhelper",
    "",
    "io.github.Retmon403.oppotheme",
    "com.fankes.enforcehighrefreshrate",
    "es.chiteroman.bootloaderspoofer",
    "com.hchai.rescueplan",
    "io.github.chipppppppppp.lime",
    "dev.device.emulator",
    "com.github.dan.NoStorageRestrict",
    "com.android1500.androidfaker",
    "com.smartpack.kernelmanager",
    "",
    "ps.reso.instaeclipse",
    "top.ltfan.notdeveloper",
    "com.rel.languager",
    "not.val.cheat",
    "com.haobammmm",
    "bin.mt.plus",
    "com.tencent.tmgp.dfm"
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

// 新增：拦截的目标文件夹列表（10大类全场景覆盖，高频风险无遗漏）
static const char *deny_folder_list[] = {
    // 1.Hook/注入/框架类（核心风险拦截）
    "xposed_temp",
    "lsposed_cache",
    "hook_inject_data",
    "xp_module_cache",
    "lspatch_temp",
    "inject_tool_dir",
    "hook_framework",
    "xposed_module_data",
    "lsposed_module",
    "hook_libs",
    "inject_resources",
    "xp_plugin_cache",
    "lspatch_plugin",
    "hook_runner",
    "inject_framework",
    // 2.系统篡改/ROOT工具类（权限违规拦截）
    "system_modify",
    "root_tool_data",
    "magisk_temp",
    "ksu_cache",
    "kernel_mod_dir",
    "system_patch",
    "privilege_tool",
    "magisk_module",
    "ksu_module",
    "root_script",
    "system_hack",
    "privilege_cache",
    "magisk_hide",
    "ksu_hide",
    "root_utils",
    // 3.隐私窃取/数据泄露类（信息安全拦截）
    "privacy_steal",
    "data_crack",
    "illegal_access",
    "info_collect",
    "secret_monitor",
    "data_leak_dir",
    "privacy_dump",
    "info_sniff",
    "data_steal_cache",
    "monitor_logs",
    "privacy_scan",
    "info_extract",
    "data_copy",
    "secret_dump",
    "privacy_hack",
    // 4.违规安装/篡改应用类（应用安全拦截）
    "apk_modify",
    "pirate_apk",
    "illegal_install",
    "app_cracked",
    "patch_apk_dir",
    "modify_apk_cache",
    "cracked_apps",
    "apk_patch",
    "modify_install",
    "pirate_cache",
    "apk_hack",
    "modified_apk",
    "illegal_apk",
    "app_patch_dir",
    "crack_tool_apk",
    // 5.临时风险操作/缓存类（动态风险拦截）
    "risk_temp",
    "unsafe_operation",
    "malicious_dir",
    "temp_hack",
    "unsafe_cache",
    "danger_operation",
    "risk_cache",
    "unsafe_temp",
    "malicious_cache",
    "hack_temp",
    "danger_cache",
    "risk_runner",
    "unsafe_data",
    "malicious_temp",
    "hack_cache",
    // 6.终端/脚本运行类（命令执行拦截）
    "termux_data",
    "apktool_temp",
    "reverse_engineer",
    "hack_tool_data",
    "crack_tool_dir",
    "modify_tool_cache",
    "terminal_cache",
    "script_runner",
    "shell_script",
    "reverse_data",
    "crack_utils",
    "tool_script",
    "terminal_data",
    "script_cache",
    "reverse_cache",
    // 7.模拟器/虚拟环境类（环境欺骗拦截）
    "emulator_data",
    "virtual_env",
    "fake_device",
    "emulator_cache",
    "virtual_device",
    "fake_env",
    "emulator_run",
    "virtual_cache",
    "fake_system",
    "emulator_libs",
    "virtual_runner",
    "fake_cache",
    "emulator_temp",
    "virtual_data",
    "fake_run",
    // 8.广告/恶意插件类（骚扰拦截）
    "ad_plugin",
    "malicious_plugin",
    "ad_cache",
    "plugin_hack",
    "ad_inject",
    "malicious_addon",
    "ad_script",
    "plugin_cache",
    "ad_utils",
    "malicious_script",
    "ad_temp",
    "plugin_runner",
    "ad_data",
    "malicious_cache",
    "ad_hack",
    // 9.数据篡改/破解类（完整性拦截）
    "data_modify",
    "crack_data",
    "modify_logs",
    "crack_cache",
    "data_hack",
    "modify_utils",
    "crack_runner",
    "data_patch",
    "modify_cache",
    "crack_script",
    "data_temp",
    "modify_run",
    "crack_data_dir",
    "data_utils",
    "modify_hack",
    // 10.违规工具残留/备份类（残留风险拦截）
    "tool_residue",
    "illegal_backup",
    "hack_residue",
    "backup_crack",
    "tool_cache",
    "illegal_dump",
    "hack_backup",
    "residue_data",
    "tool_temp",
    "illegal_cache",
    "hack_residue_dir",
    "backup_hack",
    "tool_data",
    "illegal_run",
    "hack_temp_backup",
    "MiShopSkyTreeBundleProvider",
    "release"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 核心拦截逻辑：适配低依赖环境，仅校验绝对路径，返回1表示命中拦截
static int is_blocked_path(const char *path) {
    size_t prefix_len = TARGET_PATH_LEN;
    const char *check_path = path;

    // 仅拦截绝对路径（低依赖环境妥协，不影响主流绝对路径风险拦截）
    if (*check_path != '/') {
        return 0;
    }

    // 非目标路径（/storage/emulated/0/Android/data/）直接放行
    if (strncmp(check_path, TARGET_PATH, prefix_len) != 0) {
        return 0;
    }
    
    const char *target_part = check_path + prefix_len;
    char target_buf[MAX_PACKAGE_LEN];
    size_t i = 0;

    // 提取路径中目标前缀后的第一个目录名（遇分隔符/长度上限停止）
    while (*target_part && *target_part != '/' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *target_part++;
    }
    target_buf[i] = '\0';  // 强制字符串终止，防越界

    // 过滤空目录名，直接放行
    if (i == 0) {
        return 0;
    }

    // 1. 包名拦截校验（过滤空串，提升性能）
    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (deny_list[j][0] == '\0') {
            continue;
        }
        if (strcmp(target_buf, deny_list[j]) == 0) {
            return 1;
        }
    }
    
    // 2. 文件夹名称拦截校验（过滤空串）
    for (size_t k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (deny_folder_list[k][0] == '\0') {
            continue;
        }
        if (strcmp(target_buf, deny_folder_list[k]) == 0) {
            return 1;
        }
    }
    
    // 未命中任何拦截规则，放行
    return 0;
}

// mkdirat钩子：拦截目标路径下命中规则的文件夹创建
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    // 拷贝失败/路径超长，交给原系统调用处理（加错误日志）
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        pr_warn("[HMA++ Next]mkdirat: Invalid path copy (len: %ld)\n", len);
        return;
    }
    filename_kernel[len] = '\0';

    if (is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++ Next]mkdirat: Denied [PID:%d, UID:%u] create %s\n", 
                current->pid, __kuid_val(current_uid()), filename_kernel);
        args->skip_origin = 1;
        args->ret = -EACCES;  // 创建拦截：权限不足
    }
}

// chdir钩子：拦截目标路径下命中规则的文件夹访问
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        pr_warn("[HMA++ Next]chdir: Invalid path copy (len: %ld)\n", len);
        return;
    }
    filename_kernel[len] = '\0';

    if (is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++ Next]chdir: Denied [PID:%d, UID:%u] access %s\n", 
                current->pid, __kuid_val(current_uid()), filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;  // 访问拦截：路径不存在
    }
}

// 仅当定义__NR_rmdir时，才定义before_rmdir（避免未使用警告）
#if defined(__NR_rmdir)
// rmdir钩子（单独处理1参数syscall，避免内存越界）
static void before_rmdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        pr_warn("[HMA++ Next]rmdir: Invalid path copy (len: %ld)\n", len);
        return;
    }
    filename_kernel[len] = '\0';

    if (is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++ Next]rmdir: Denied [PID:%d, UID:%u] delete %s\n", 
                current->pid, __kuid_val(current_uid()), filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;  // 删除拦截：路径不存在
    }
}
#endif

// 新增：unlinkat钩子（单独处理4参数syscall，区分文件/文件夹删除）
static void before_unlinkat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        pr_warn("[HMA++ Next]unlinkat: Invalid path copy (len: %ld)\n", len);
        return;
    }
    filename_kernel[len] = '\0';

    // 拦截文件夹删除（AT_REMOVEDIR）或文件删除（无标志）
    if (is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++ Next]unlinkat: Denied [PID:%d, UID:%u] %s %s\n", 
                current->pid, __kuid_val(current_uid()), 
                (flags & AT_REMOVEDIR) ? "delete dir" : "delete file", filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 仅当定义__NR_newfstatat或__NR_fstatat64时，才定义before_fstatat（避免未使用警告）
#if defined(__NR_newfstatat) || defined(__NR_fstatat64)
// fstatat钩子：拦截目标路径下命中规则的文件夹状态查询
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        pr_warn("[HMA++ Next]fstatat: Invalid path copy (len: %ld)\n", len);
        return;
    }
    filename_kernel[len] = '\0';

    if (is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++ Next]fstatat: Denied [PID:%d, UID:%u] stat %s\n", 
                current->pid, __kuid_val(current_uid()), filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// 新增：openat钩子（拦截黑名单路径下文件创建/打开）
static void before_openat(hook_fargs5_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        pr_warn("[HMA++ Next]openat: Invalid path copy (len: %ld)\n", len);
        return;
    }
    filename_kernel[len] = '\0';

    // 拦截创建文件（O_CREAT）或打开文件
    if (is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++ Next]openat: Denied [PID:%d, UID:%u] %s %s\n", 
                current->pid, __kuid_val(current_uid()), 
                (flags & O_CREAT) ? "create file" : "open file", filename_kernel);
        args->skip_origin = 1;
        args->ret = (flags & O_CREAT) ? -EACCES : -ENOENT;
    }
}

// 新增：renameat钩子（拦截进出黑名单路径的移动/重命名）
static void before_renameat(hook_fargs4_t *args, void *udata) {
    const char __user *oldpath_user = (const char __user *)syscall_argn(args, 1);
    const char __user *newpath_user = (const char __user *)syscall_argn(args, 3);
    char oldpath_kernel[PATH_MAX], newpath_kernel[PATH_MAX];
    long len_old = compat_strncpy_from_user(oldpath_kernel, oldpath_user, sizeof(oldpath_kernel));
    long len_new = compat_strncpy_from_user(newpath_kernel, newpath_user, sizeof(newpath_kernel));

    if (len_old <= 0 || len_old >= sizeof(oldpath_kernel) || 
        len_new <= 0 || len_new >= sizeof(newpath_kernel)) {
        pr_warn("[HMA++ Next]renameat: Invalid path copy (old len: %ld, new len: %ld)\n", len_old, len_new);
        return;
    }
    oldpath_kernel[len_old] = '\0';
    newpath_kernel[len_new] = '\0';

    // 旧路径在黑名单 或 新路径在黑名单，均拦截
    if (is_blocked_path(oldpath_kernel) || is_blocked_path(newpath_kernel)) {
        pr_warn("[HMA++ Next]renameat: Denied [PID:%d, UID:%u] rename %s -> %s\n", 
                current->pid, __kuid_val(current_uid()), oldpath_kernel, newpath_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 新增：linkat钩子（拦截创建指向黑名单路径的硬链接）
static void before_linkat(hook_fargs4_t *args, void *udata) {
    const char __user *oldpath_user = (const char __user *)syscall_argn(args, 1);
    const char __user *newpath_user = (const char __user *)syscall_argn(args, 3);
    char oldpath_kernel[PATH_MAX], newpath_kernel[PATH_MAX];
    long len_old = compat_strncpy_from_user(oldpath_kernel, oldpath_user, sizeof(oldpath_kernel));
    long len_new = compat_strncpy_from_user(newpath_kernel, newpath_user, sizeof(newpath_kernel));

    if (len_old <= 0 || len_old >= sizeof(oldpath_kernel) || 
        len_new <= 0 || len_new >= sizeof(newpath_kernel)) {
        pr_warn("[HMA++ Next]linkat: Invalid path copy (old len: %ld, new len: %ld)\n", len_old, len_new);
        return;
    }
    oldpath_kernel[len_old] = '\0';
    newpath_kernel[len_new] = '\0';

    if (is_blocked_path(oldpath_kernel) || is_blocked_path(newpath_kernel)) {
        pr_warn("[HMA++ Next]linkat: Denied [PID:%d, UID:%u] link %s -> %s\n", 
                current->pid, __kuid_val(current_uid()), oldpath_kernel, newpath_kernel);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// 新增：symlinkat钩子（拦截创建指向黑名单路径的软链接）
static void before_symlinkat(hook_fargs4_t *args, void *udata) {
    const char __user *oldpath_user = (const char __user *)syscall_argn(args, 1);
    const char __user *newpath_user = (const char __user *)syscall_argn(args, 3);
    char oldpath_kernel[PATH_MAX], newpath_kernel[PATH_MAX];
    long len_old = compat_strncpy_from_user(oldpath_kernel, oldpath_user, sizeof(oldpath_kernel));
    long len_new = compat_strncpy_from_user(newpath_kernel, newpath_user, sizeof(newpath_kernel));

    if (len_old <= 0 || len_old >= sizeof(oldpath_kernel) || 
        len_new <= 0 || len_new >= sizeof(newpath_kernel)) {
        pr_warn("[HMA++ Next]symlinkat: Invalid path copy (old len: %ld, new len: %ld)\n", len_old, len_new);
        return;
    }
    oldpath_kernel[len_old] = '\0';
    newpath_kernel[len_new] = '\0';

    if (is_blocked_path(oldpath_kernel) || is_blocked_path(newpath_kernel)) {
        pr_warn("[HMA++ Next]symlinkat: Denied [PID:%d, UID:%u] symlink %s -> %s\n", 
                current->pid, __kuid_val(current_uid()), oldpath_kernel, newpath_kernel);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// 仅当定义__NR_chmodat时，才定义before_chmodat（避免未使用警告）
#if defined(__NR_chmodat)
// chmodat钩子（拦截修改黑名单路径下权限）
static void before_chmodat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        pr_warn("[HMA++ Next]chmodat: Invalid path copy (len: %ld)\n", len);
        return;
    }
    filename_kernel[len] = '\0';

    if (is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++ Next]chmodat: Denied [PID:%d, UID:%u] chmod %s\n", 
                current->pid, __kuid_val(current_uid()), filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// 模块初始化：挂钩所有目标系统调用（与函数定义强绑定）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++ Next]HMA++ init. Hooking all risk syscalls...\n");

    // 原有syscall挂钩
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook mkdirat failed: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook chdir failed: %d\n", err); return -EINVAL; }
    // 分开挂钩rmdir和unlinkat（与函数定义强绑定）
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook rmdir failed: %d\n", err); return -EINVAL; }
#endif
#if defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_unlinkat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook unlinkat failed: %d\n", err); return -EINVAL; }
#endif
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook newfstatat failed: %d\n", err); return -EINVAL; }
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook fstatat64 failed: %d\n", err); return -EINVAL; }
#endif

    // 新增syscall挂钩（与函数定义强绑定）
#ifdef __NR_openat
    err = hook_syscalln(__NR_openat, 5, before_openat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook openat failed: %d\n", err); return -EINVAL; }
#endif
#ifdef __NR_renameat
    err = hook_syscalln(__NR_renameat, 4, before_renameat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook renameat failed: %d\n", err); return -EINVAL; }
#endif
#ifdef __NR_linkat
    err = hook_syscalln(__NR_linkat, 4, before_linkat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook linkat failed: %d\n", err); return -EINVAL; }
#endif
#ifdef __NR_symlinkat
    err = hook_syscalln(__NR_symlinkat, 4, before_symlinkat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook symlinkat failed: %d\n", err); return -EINVAL; }
#endif
#ifdef __NR_chmodat
    err = hook_syscalln(__NR_chmodat, 4, before_chmodat, NULL, NULL);
    if (err) { pr_err("[HMA++ Next]Hook chmodat failed: %d\n", err); return -EINVAL; }
#endif

    pr_info("[HMA++ Next]All risk syscalls hooked successfully.\n");
    return 0;
}

static long hma_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm hello control0, args: %s\n", args);
    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    // 补全：判断输出缓冲区长度，防越界拷贝
    if (outlen < sizeof(echo)) {
        pr_warn("[HMA++ Next]hma_control0: out_msg len too small (%d < %zu)\n", outlen, sizeof(echo));
        return -EINVAL;
    }
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static long hma_control1(void *a1, void *a2, void *a3)
{
    pr_info("kpm hello control1, a1: %llx, a2: %llx, a3: %llx\n", a1, a2, a3);
    return 0;
}

// 模块退出：解绑所有挂钩的系统调用（与初始化挂钩强绑定）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++ Next]HMA++ exit. Unhooking all syscalls...\n");

    // 原有syscall解绑
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#endif
#if defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_unlinkat, NULL);
#endif
#ifdef __NR_newfstatat
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#endif

    // 新增syscall解绑
#ifdef __NR_openat
    unhook_syscalln(__NR_openat, before_openat, NULL);
#endif
#ifdef __NR_renameat
    unhook_syscalln(__NR_renameat, before_renameat, NULL);
#endif
#ifdef __NR_linkat
    unhook_syscalln(__NR_linkat, before_linkat, NULL);
#endif
#ifdef __NR_symlinkat
    unhook_syscalln(__NR_symlinkat, before_symlinkat, NULL);
#endif
#ifdef __NR_chmodat
    unhook_syscalln(__NR_chmodat, before_chmodat, NULL);
#endif

    pr_info("[HMA++ Next]All syscalls unhooked successfully.\n");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
