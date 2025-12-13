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

KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("测试更新");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

// 内置 deny list（包名，保留原有全部配置）
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
    "com.rifsxd.ksunext",
    "com.rkg.IAMRKG",
    "me.gm.cleaner",
    "moe.shizuku.redirectstorage",
    "com.ddm.qute",
    "io.github.vvb2060.magisk",
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
    "com.sevtinge.hyperceiler",
    "ps.reso.instaeclipse",
    "top.ltfan.notdeveloper",
    "com.rel.languager",
    "not.val.cheat",
    "com.haobammmm",
    "bin.mt.plus",
    "com.tencent.tmgp.dfm",
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
    "hack_temp_backup"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 优化：整合包名拦截+文件夹拦截，返回1表示命中拦截规则，逻辑统一且减少冗余
static int is_blocked_path(const char *path) {
    size_t prefix_len = strlen(TARGET_PATH);
    // 非目标路径（/storage/emulated/0/Android/data/）直接放行
    if (strncmp(path, TARGET_PATH, prefix_len) != 0) return 0;
    
    const char *target_part = path + prefix_len;
    char target_buf[128];
    size_t i = 0;
    // 提取路径中目标前缀后的第一个目录名（包名/文件夹名，遇分隔符或长度上限停止）
    while (*target_part && *target_part != '/' && *target_part != '\\' && i < sizeof(target_buf) - 1) {
        target_buf[i++] = *target_part++;
    }
    target_buf[i] = '\0'; // 确保字符串终止符，避免内存越界
    
    // 1. 原有包名拦截校验
    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    
    // 2. 新增文件夹名称拦截校验
    for (size_t k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    
    // 未命中任何拦截规则，放行
    return 0;
}

// mkdirat钩子：拦截目标路径下命中规则的文件夹创建
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);

    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return; // 无效路径/超长路径，交给原系统调用处理
    }
    filename_kernel[len] = '\0';

    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_blocked_path(filename_kernel)) {
            pr_warn("[HMA++ Next]mkdirat: Denied by block rule to create %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -EACCES;
        }
        return;
    }
}

// chdir钩子：拦截目标路径下命中规则的文件夹访问
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_blocked_path(filename_kernel)) {
            pr_warn("[HMA++ Next]chdir: Denied by block rule to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

// rmdir/unlinkat钩子：拦截目标路径下命中规则的文件夹删除
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    // 仅拦截文件夹删除操作（AT_REMOVEDIR标识）
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_blocked_path(filename_kernel)) {
            pr_warn("[HMA++ Next]rmdir/unlinkat: Denied by block rule to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

// fstatat钩子：拦截目标路径下命中规则的文件夹状态查询
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_blocked_path(filename_kernel)) {
            pr_warn("[HMA++ Next]fstatat/stat: Denied by block rule to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

// 模块初始化：挂钩所有目标系统调用
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++ Next]HMA++ init. Hooking mkdirat, chdir, rmdir, fstatat...\n");
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) {
        pr_err("[HMA++ Next]Failed to hook mkdirat: %d\n", err);
        return -EINVAL;
    }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++ Next]Failed to hook chdir: %d\n", err);
        return -EINVAL;
    }
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++ Next]Failed to hook rmdir: %d\n", err);
        return -EINVAL;
    }
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++ Next]Failed to hook unlinkat (for rmdir): %d\n", err);
        return -EINVAL;
    }
#else
#   error "No suitable syscall number for rmdir/unlinkat"
#endif
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
    if (err) {
        pr_err("[HMA++ Next]Failed to hook newfstatat: %d\n", err);
        return -EINVAL;
    }
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
    if (err) {
        pr_err("[HMA++ Next]Failed to hook fstatat64: %d\n", err);
        return -EINVAL;
    }
#endif
    pr_info("[HMA++ Next]Successfully hooked mkdirat, chdir, rmdir, fstatat.\n");
    return 0;
}

// 模块退出：解绑所有挂钩的系统调用
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++ Next]HMA++ Next exit. Unhooking mkdirat, chdir, rmdir, fstatat...\n");
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
    pr_info("[HMA++ Next]Successfully unhooked all syscalls.\n");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
