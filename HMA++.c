#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h> // For __NR_* syscall
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/errno.h>    // For ENOENT
#include <accctl.h>         // For kernel patch api
#include <uapi/linux/limits.h>   // For PATH_MAX
#include <linux/kernel.h>
#include <linux/spinlock.h>

// 模块基础信息（精简描述，减少暴露）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("Path protect module");

// 核心宏定义（编译期定值，高效无冗余）
#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1) // 编译期计算，避免运行时strlen
#define MAX_TARGET_NAME 127 // 包名/文件夹名最大长度，精准匹配缓冲区
#define HIDE_ERR_CODE -ENOENT // 统一伪装错误码：路径不存在，更难被检测

// 内置 deny list（修复语法错误：补全最后元素逗号，剔除冗余）
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
    "bin.mt.plus", // 修复：补全缺失逗号
    "com.reveny.nativecheck",
    "chunqiu.safe.detector",
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

// 核心拦截文件夹列表（保留8大类风险，精准防护）
static const char *deny_folder_list[] = {
    // 1.Hook/注入核心风险
    "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp", "hook_framework",
    // 2.ROOT/系统篡改
    "magisk_temp", "ksu_cache", "system_modify", "root_tool_data", "kernel_mod_dir",
    // 3.隐私窃取/数据泄露
    "privacy_steal", "data_crack", "info_collect", "secret_monitor", "data_leak_dir",
    // 4.违规应用安装/篡改
    "apk_modify", "pirate_apk", "app_cracked", "patch_apk_dir", "illegal_install",
    // 5.终端/脚本运行
    "termux_data", "apktool_temp", "reverse_engineer", "hack_tool_data", "shell_script",
    // 6.模拟器/虚拟环境
    "emulator_data", "virtual_env", "fake_device", "emulator_cache",
    // 7.恶意插件/广告
    "ad_plugin", "malicious_plugin", "plugin_hack", "ad_inject",
    // 8.风险临时操作
    "risk_temp", "malicious_dir", "temp_hack", "unsafe_cache"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 全局状态（隐藏模块运行标识，避免暴露）
static int g_module_active = 0; // 0未激活，1正常运行
static spinlock_t g_state_lock; // 状态锁，避免并发冲突

// 整合拦截逻辑（优化效率+内存安全，核心逻辑不变）
static int is_blocked_path(const char *path) {
    if (!path || *path == '\0') return 0; // 空指针/空路径直接排除
    
    // 优先匹配监控根目录（编译期定值，高效无误差）
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    
    const char *target_part = path + TARGET_PATH_LEN;
    if (*target_part == '\0') return 0; // 仅根目录不拦截
    
    char target_buf[MAX_TARGET_NAME + 1] = {0}; // 初始化清零，避免脏数据
    size_t i = 0;
    // 提取根目录下一级名称（严格边界控制，不越界）
    while (*target_part && *target_part != '/' && *target_part != '\\' && i < MAX_TARGET_NAME) {
        target_buf[i++] = *target_part++;
    }
    
    // 包名校验
    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (!deny_list[j]) continue;
        if (strcmp(target_buf, deny_list[j]) == 0) return 1;
    }
    // 文件夹校验
    for (size_t k = 0; k < DENY_FOLDER_SIZE; ++k) {
        if (!deny_folder_list[k]) continue;
        if (strcmp(target_buf, deny_folder_list[k]) == 0) return 1;
    }
    return 0;
}

// 通用路径拷贝工具（复用逻辑，减少冗余，提升安全性）
static int copy_user_path(const char __user *user_path, char *kernel_buf, size_t buf_len) {
    if (!user_path || !kernel_buf || buf_len <= 1) return -1;
    
    // 安全拷贝用户空间路径，清理脏数据
    long len = compat_strncpy_from_user(kernel_buf, user_path, buf_len - 1);
    if (len <= 0 || len >= (long)(buf_len - 1)) return -1;
    
    kernel_buf[len] = '\0';
    return 0;
}

// -------------------------- 核心钩子函数（增强隐藏性，补全拦截场景）--------------------------
// mkdirat钩子：拦截违规创建（统一错误码，伪装路径不存在）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!g_module_active || !args) return; // 未激活/空指针直接返回，减少暴露
    
    char filename_kernel[PATH_MAX] = {0};
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    if (copy_user_path(filename_user, filename_kernel, sizeof(filename_kernel)) != 0) return;
    
    if (is_blocked_path(filename_kernel)) {
        args->skip_origin = 1;
        args->ret = HIDE_ERR_CODE; // 统一返回：路径不存在，伪装更真实
    }
}

// chdir钩子：拦截违规进入（保持核心逻辑，优化容错）
static void before_chdir(hook_fargs1_t *args, void *udata) {
    if (!g_module_active || !args) return;
    
    char filename_kernel[PATH_MAX] = {0};
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    if (copy_user_path(filename_user, filename_kernel, sizeof(filename_kernel)) != 0) return;
    
    if (is_blocked_path(filename_kernel)) {
        args->skip_origin = 1;
        args->ret = HIDE_ERR_CODE;
    }
}

// rmdir/unlinkat钩子：拦截违规删除（优化参数校验）
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    if (!g_module_active || !args) return;
    
    char filename_kernel[PATH_MAX] = {0};
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    if (copy_user_path(filename_user, filename_kernel, sizeof(filename_kernel)) != 0) return;
    
    if ((flags & 0x200) && is_blocked_path(filename_kernel)) {
        args->skip_origin = 1;
        args->ret = HIDE_ERR_CODE;
    }
}

// fstatat钩子：拦截违规查询（补全syscall分支，提升兼容性）
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    if (!g_module_active || !args) return;
    
    char filename_kernel[PATH_MAX] = {0};
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    if (copy_user_path(filename_user, filename_kernel, sizeof(filename_kernel)) != 0) return;
    
    if (is_blocked_path(filename_kernel)) {
        args->skip_origin = 1;
        args->ret = HIDE_ERR_CODE;
    }
}

// 新增openat钩子：拦截文件打开（补全隐藏场景，避免文件被读取）
static void before_openat(hook_fargs4_t *args, void *udata) {
    if (!g_module_active || !args) return;
    
    char filename_kernel[PATH_MAX] = {0};
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1);
    if (copy_user_path(filename_user, filename_kernel, sizeof(filename_kernel)) != 0) return;
    
    if (is_blocked_path(filename_kernel)) {
        args->skip_origin = 1;
        args->ret = HIDE_ERR_CODE;
    }
}

// 新增access钩子：拦截路径存在性判断（避免被检测到路径实际存在）
static void before_access(hook_fargs2_t *args, void *udata) {
    if (!g_module_active || !args) return;
    
    char filename_kernel[PATH_MAX] = {0};
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0);
    if (copy_user_path(filename_user, filename_kernel, sizeof(filename_kernel)) != 0) return;
    
    if (is_blocked_path(filename_kernel)) {
        args->skip_origin = 1;
        args->ret = HIDE_ERR_CODE;
    }
}

// -------------------------- 模块加载/卸载（完善回滚，减少日志暴露）--------------------------
// 解绑所有已挂钩syscall（回滚专用，避免残留）
static void unhook_all_syscalls(void) {
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#elif defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_rmdir, NULL);
#endif
#ifdef __NR_fstatat
    unhook_syscalln(__NR_fstatat, before_fstatat, NULL);
#elif defined(__NR_newfstatat)
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#endif
    unhook_syscalln(__NR_openat, before_openat, NULL);
#ifdef __NR_access
    unhook_syscalln(__NR_access, before_access, NULL);
#endif
}

// 模块初始化（完善回滚，激活后再运行，减少暴露）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    spin_lock_init(&g_state_lock);
    g_module_active = 0; // 初始未激活，避免未就绪拦截
    
    // 挂钩核心syscall（失败则回滚，无残留）
    // 1. 基础拦截：mkdirat/chdir/rmdir
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { unhook_all_syscalls(); return -EINVAL; }
    
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { unhook_all_syscalls(); return -EINVAL; }
    
    err = -1;
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
#else
    unhook_all_syscalls(); return -EINVAL;
#endif
    if (err) { unhook_all_syscalls(); return -EINVAL; }
    
    // 2. 状态查询拦截：fstatat
    err = -1;
#ifdef __NR_fstatat
    err = hook_syscalln(__NR_fstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_newfstatat)
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
#endif
    if (err) { unhook_all_syscalls(); return -EINVAL; }
    
    // 3. 增强隐藏：openat/access
    err = hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) { unhook_all_syscalls(); return -EINVAL; }
    
#ifdef __NR_access
    err = hook_syscalln(__NR_access, 2, before_access, NULL, NULL);
    if (err) { unhook_all_syscalls(); return -EINVAL; }
#endif
    
    // 所有挂钩成功，激活模块
    g_module_active = 1;
    pr_info("[HMA++]Init success.\n"); // 精简日志，减少暴露
    return 0;
}

// 模块退出（安全清理，无残留）
static long mkdir_hook_exit(void *__user reserved) {
    g_module_active = 0; // 先停止拦截，再解绑
    unhook_all_syscalls();
    pr_info("[HMA++]Exit success.\n");
    return 0;
}

// 模块入口出口（规范定义，适配APatch加载）
KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
