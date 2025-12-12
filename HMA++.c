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
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("测试更新");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

// 内置 deny list（包名，保留原有全部核心配置，剔除空字符串冗余）
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
    "bin.mt.plus"
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
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 整合包名+文件夹拦截逻辑，精准判断是否命中规则
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

// mkdirat钩子：拦截违规文件夹创建
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++]mkdirat: Denied by block rule to create %s\n", filename_kernel);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

// chdir钩子：拦截违规文件夹访问
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++]chdir: Denied by block rule to %s\n", filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// rmdir/unlinkat钩子：拦截违规文件夹删除
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++]rmdir/unlinkat: Denied by block rule to %s\n", filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// fstatat钩子：拦截违规文件夹状态查询
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    
    if (len <= 0 || len >= sizeof(filename_kernel)) return;
    filename_kernel[len] = '\0';
    
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0 && is_blocked_path(filename_kernel)) {
        pr_warn("[HMA++]fstatat/stat: Denied by block rule to %s\n", filename_kernel);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 模块初始化：挂钩目标syscall
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++]HMA++ init. Hooking core syscalls...\n");
    
    // 挂钩mkdirat
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook mkdirat failed: %d\n", err); return -EINVAL; }
    // 挂钩chdir
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++]Hook chdir failed: %d\n", err); return -EINVAL; }
    // 挂钩rmdir/unlinkat
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
#else
#   error "No suitable syscall for rmdir"
#endif
    if (err) { pr_err("[HMA++]Hook rmdir/unlinkat failed: %d\n", err); return -EINVAL; }
    // 挂钩fstatat
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
#endif
    if (err) { pr_err("[HMA++]Hook fstatat failed: %d\n", err); return -EINVAL; }
    
    pr_info("[HMA++]All core syscalls hooked successfully.\n");
    return 0;
}

// 模块退出：解绑syscall
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++]HMA++ exit. Unhooking syscalls...\n");
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
    pr_info("[HMA++]All syscalls unhooked successfully.\n");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
