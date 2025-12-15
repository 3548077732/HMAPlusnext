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
#include <uapi/linux/limits.h>
#include <linux/kernel.h>
// 极简网络核心依赖（仅保留必需接口）
#include <linux/socket.h>
#include <net/sock.h>

// 模块元信息（极简保留核心标识）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.0.5");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("核心风险拦截测试+广告拦截");

// 核心宏定义（精简冗余，适配极简内存）
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif
#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH)-1)
#define MAX_PACKAGE_LEN 256 // 精简包名长度（够用且省内存）

// 全局核心开关（唯一全局变量，极简资源占用）
static bool hma_running = true;

// 1.风险拦截黑名单（剔除所有空项，减少循环开销）
static const char *deny_list[] = {
    "com.silverlab.app.deviceidchanger.free",
    "me.bingyue.IceCore",
    "com.modify.installer",
    "o.dyoo",
    "com.zhufucdev.motion_emulator",
    "com.xiaomi.shop",
    "com.demo.serendipity",
    "me.iacn.biliroaming",
    "me.teble.xposed.autodaily",
    "com.example.ourom",
    "dialog.box",
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
    "com.xayah.databackup.foss",
    "github.tornaco.android.thanos",
    "nep.timeline.freezer",
    "cn.geektang.privacyspace",
    "com.byyoung.setting",
    "cn.myflv.noactive",
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
    "com.ddm.qute",
    "kk.dk.anqu",
    "com.qq.qcxm",
    "dknb.con",
    "dknb.coo8",
    "com.tencent.jingshi",
    "com.tencent.JYNB",
    "com.apocalua.run",
    "com.coderstory.toolkit",
    "com.didjdk.adbhelper",
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
    "bin.mt.plus",
    "com.tencent.tmgp.dfm"
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

static const char *deny_folder_list[] = {
    // Hook/注入类
    "xposed_temp", "lsposed_cache", "hook_inject_data", "xp_module_cache", "lspatch_temp",
    // 系统篡改类
    "system_modify", "root_tool_data", "magisk_temp", "ksu_cache", "kernel_mod_dir",
    // 隐私窃取类
    "privacy_steal", "data_crack", "illegal_access", "info_collect", "secret_monitor",
    // 违规安装类
    "apk_modify", "pirate_apk", "illegal_install", "app_cracked", "patch_apk_dir",
    // 风险临时类
    "risk_temp", "unsafe_operation", "malicious_dir", "temp_hack", "unsafe_cache",
    // 终端脚本类
    "termux_data", "apktool_temp", "reverse_engineer", "hack_tool_data", "crack_tool_dir",
    // 模拟器类
    "emulator_data", "virtual_env", "fake_device", "emulator_cache", "virtual_device",
    // 广告插件类
    "ad_plugin", "malicious_plugin", "ad_cache", "plugin_hack", "ad_inject",
    // 数据篡改类
    "data_modify", "crack_data", "modify_logs", "crack_cache", "data_hack",
    // 残留备份类
    "tool_residue", "illegal_backup", "hack_residue", "backup_crack", "tool_cache",
    "MiShopSkyTreeBundleProvider", "release"
};
#define DENY_FOLDER_SIZE (sizeof(deny_folder_list)/sizeof(deny_folder_list[0]))

// 2.广告拦截黑名单（极简核心，覆盖高频广告源）
static const char *ad_package_list[] = {
    // 主流广告SDK
    "com.google.android.gms.ads", "com.bytedance.sdk.openadsdk", "com.baidu.mobads",
    "com.tencent.ads", "com.miui.ads", "com.huawei.hms.ads", "com.oppo.ads", "com.vivo.ads"
};
#define AD_PACKAGE_SIZE (sizeof(ad_package_list)/sizeof(ad_package_list[0]))

static const char *ad_domain_list[] = {
    // 高频广告域名
    "ads.google.com", "googleads.g.doubleclick.net", "ad.bytedance.com",
    "ad.baidu.com", "ad.tencent.com", "miui.com/ads", "huawei.com/ads"
};
#define AD_DOMAIN_SIZE (sizeof(ad_domain_list)/sizeof(ad_domain_list[0]))

static const char *ad_file_keywords[] = {
    // 广告资源核心关键词
    "ad_", "_ad.", "ads_", "_ads.", "advertise", "adcache", "adimg", "advideo"
};
#define AD_FILE_KEYWORD_SIZE (sizeof(ad_file_keywords)/sizeof(ad_file_keywords[0]))

// 极简辅助函数（无冗余，适配内核接口）
// 字符串转小写（极简实现）
static void str_to_lower(char *str) {
    if (!str) return;
    for (; *str; str++) if (*str >= 'A' && *str <= 'Z') *str += 32;
}

// 获取当前进程包名（极简适配，仅保留主流内核支持项）
static const char *get_current_app_package(void) {
    struct task_struct *task = current;
    // 主流适配+兜底，减少内核结构依赖
    if (task && task->mm && task->mm->context.package_name)
        return task->mm->context.package_name;
    return task ? task->comm : NULL;
}

// 核心判断函数（极简逻辑，无冗余循环）
// 风险路径判断
static int is_blocked_path(const char *path) {
    if (*path != '/' || strncmp(path, TARGET_PATH, TARGET_PATH_LEN)) return 0;
    
    char target_buf[MAX_PACKAGE_LEN] = {0};
    const char *p = path + TARGET_PATH_LEN;
    size_t i = 0;
    while (*p && *p != '/' && i < MAX_PACKAGE_LEN-1) target_buf[i++] = *p++;
    
    if (i == 0) return 0;
    // 风险包名校验
    for (size_t j = 0; j < DENY_LIST_SIZE; j++)
        if (!strcmp(target_buf, deny_list[j])) return 1;
    // 风险文件夹校验
    for (size_t k = 0; k < DENY_FOLDER_SIZE; k++)
        if (!strcmp(target_buf, deny_folder_list[k])) return 1;
    return 0;
}

// 广告拦截判断（简化网络解析，适配极简内核）
static int is_ad_blocked(const char *path, int fd) {
    // 广告进程校验
    const char *pkg = get_current_app_package();
    if (pkg) {
        char lower[256];
        strncpy(lower, pkg, 255);
        str_to_lower(lower);
        for (size_t i = 0; i < AD_PACKAGE_SIZE; i++)
            if (strstr(lower, ad_package_list[i])) return 1;
    }
    // 广告文件校验
    if (path) {
        char lower[PATH_MAX];
        strncpy(lower, path, PATH_MAX-1);
        str_to_lower(lower);
        for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++)
            if (strstr(lower, ad_file_keywords[i])) return 1;
    }
    // 广告网络校验（极简适配，简化socket解析）
    if (fd != -1) {
        struct socket *sock;
        char domain[64] = {0};
        if (!sockfd_lookup(fd, &sock) && sock) {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            if (!sock->ops->getname(sock, (struct sockaddr*)&addr, &len, 0)) {
                snprintf(domain, 63, "%pI4", &addr.sin_addr);
                str_to_lower(domain);
                for (size_t i = 0; i < AD_DOMAIN_SIZE; i++)
                    if (strstr(domain, ad_domain_list[i])) return 1;
            }
        }
    }
    return 0;
}

// 极简钩子函数（核心拦截，无冗余日志）
// 文件操作钩子
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void*)syscall_argn(args,1), PATH_MAX-1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path, -1)) {
        pr_warn("[HMA++] mkdirat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

static void before_chdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void*)syscall_argn(args,0), PATH_MAX-1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path, -1)) {
        pr_warn("[HMA++] chdir deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

#if defined(__NR_rmdir)
static void before_rmdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void*)syscall_argn(args,0), PATH_MAX-1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path, -1)) {
        pr_warn("[HMA++] rmdir deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#if defined(__NR_unlinkat)
static void before_unlinkat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void*)syscall_argn(args,1), PATH_MAX-1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path, -1)) {
        pr_warn("[HMA++] unlinkat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#ifdef __NR_openat
static void before_openat(hook_fargs5_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX];
    long len = compat_strncpy_from_user(path, (void*)syscall_argn(args,1), PATH_MAX-1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path, -1)) {
        pr_warn("[HMA++] openat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

#ifdef __NR_renameat
static void before_renameat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char old[PATH_MAX], new[PATH_MAX];
    long lo = compat_strncpy_from_user(old, (void*)syscall_argn(args,1), PATH_MAX-1);
    long ln = compat_strncpy_from_user(new, (void*)syscall_argn(args,3), PATH_MAX-1);
    if (lo <= 0 || ln <= 0) return;
    old[lo] = '\0'; new[ln] = '\0';
    if (is_blocked_path(old) || is_blocked_path(new) || is_ad_blocked(old,-1) || is_ad_blocked(new,-1)) {
        pr_warn("[HMA++] renameat deny: %s->%s\n", old, new);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}
#endif

// 网络广告钩子（极简适配）
#ifdef __NR_connect
static void before_connect(hook_fargs3_t *args, void *udata) {
    if (!hma_running) return;
    int fd = (int)syscall_argn(args,0);
    if (is_ad_blocked(NULL, fd)) {
        pr_warn("[HMA++] connect ad deny: fd=%d\n", fd);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}
#endif

#ifdef __NR_recvfrom
static void before_recvfrom(hook_fargs6_t *args, void *udata) {
    if (!hma_running) return;
    int fd = (int)syscall_argn(args,0);
    if (is_ad_blocked(NULL, fd)) {
        pr_warn("[HMA++] recvfrom ad deny: fd=%d\n", fd);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}
#endif

// 模块生命周期（极简挂钩/解钩，无冗余）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] init\n");

    // 文件钩子挂钩
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++] hook mkdirat err:%d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++] hook chdir err:%d\n", err); return -EINVAL; }
#if defined(__NR_rmdir)
    hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
#endif
#if defined(__NR_unlinkat)
    hook_syscalln(__NR_unlinkat, 4, before_unlinkat, NULL, NULL);
#endif
#ifdef __NR_openat
    hook_syscalln(__NR_openat, 5, before_openat, NULL, NULL);
#endif
#ifdef __NR_renameat
    hook_syscalln(__NR_renameat, 4, before_renameat, NULL, NULL);
#endif

    // 广告网络钩子挂钩
#ifdef __NR_connect
    hook_syscalln(__NR_connect, 3, before_connect, NULL, NULL);
#endif
#ifdef __NR_recvfrom
    hook_syscalln(__NR_recvfrom, 6, before_recvfrom, NULL, NULL);
#endif

    pr_info("[HMA++] init ok\n");
    return 0;
}

// 启停控制（极简逻辑，无冗余校验）
static long hma_control0(const char *args, char *__user out_msg, int outlen) {
    char msg[32] = {0};
    if (!args || strlen(args)!=1) {
        strcpy(msg, "args err: only 0/1");
        goto out;
    }
    hma_running = (*args == '1') ? true : false;
    strcpy(msg, hma_running ? "enabled" : "disabled");
out:
    if (outlen >= strlen(msg)+1) compat_copy_to_user(out_msg, msg, strlen(msg)+1);
    return 0;
}

static long hma_control1(void *a1, void *a2, void *a3) { return 0; }

// 模块退出（极简解钩）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++] exit\n");
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#endif
#if defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_unlinkat, NULL);
#endif
#ifdef __NR_openat
    unhook_syscalln(__NR_openat, before_openat, NULL);
#endif
#ifdef __NR_renameat
    unhook_syscalln(__NR_renameat, before_renameat, NULL);
#endif
#ifdef __NR_connect
    unhook_syscalln(__NR_connect, before_connect, NULL);
#endif
#ifdef __NR_recvfrom
    unhook_syscalln(__NR_recvfrom, before_recvfrom, NULL);
#endif
    return 0;
}

// 模块注册（极简收尾）
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
