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

KPM_NAME("HMA++");
KPM_VERSION("0.0.6");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("lshwjgpt and NightFallsLikeRain");
KPM_DESCRIPTION("测试更新");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

// 内置 deny list
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
    "chunqiu.safe.detector",
    "com.reveny.nativecheck",
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

// 检查路径是否命中 deny_list
static int is_in_deny_list(const char *path) {
    // path 形如 /storage/emulated/0/Android/data/com.xxx.xxx
    // 需提取包名部分
    const char *p = path;
    size_t prefix_len = strlen(TARGET_PATH);
    if (strncmp(p, TARGET_PATH, prefix_len) != 0) return 0;
    const char *pkg = p + prefix_len;
    // 只取包名部分（遇到 / 或 \ 或字符串结尾）
    char pkgname[128];
    size_t i = 0;
    while (*pkg && *pkg != '/' && *pkg != '\\' && i < sizeof(pkgname) - 1) {
        pkgname[i++] = *pkg++;
    }
    pkgname[i] = '\0';
    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(pkgname, deny_list[j]) == 0) return 1;
    }
    return 0;
}

static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1); // Path to create

    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return; // Let the original syscall handle invalid paths or too long paths
    }
    filename_kernel[len] = '\0'; // Ensure null-termination

    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        // 只拦名单，其它一律放行
        if (is_in_deny_list(filename_kernel)) {
            pr_warn("[HMA++]mkdirat: Denied by deny_list to create %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -EACCES;
        }
        // 不在名单直接 return
        return;
    }
}

// chdir 钩子，只拦截 /storage/emulated/0/Android/data/ 并命中 deny_list
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0); // chdir 第一个参数
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(filename_kernel)) {
            pr_warn("[HMA++]chdir: Denied by deny_list to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

// rmdir/unlinkat 钩子，只拦截 /storage/emulated/0/Android/data/ 并命中 deny_list
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1); // unlinkat 第2参数
    int flags = (int)syscall_argn(args, 2); // unlinkat 第3参数
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    // 只拦 AT_REMOVEDIR
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(filename_kernel)) {
            pr_warn("[HMA++]rmdir/unlinkat: Denied by deny_list to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

// fstatat 钩子，只拦截 /storage/emulated/0/Android/data/ 并命中 deny_list
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1); // fstatat 第2参数
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(filename_kernel)) {
            pr_warn("[HMA++]fstatat/stat: Denied by deny_list to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++]HMA++ init. Hooking mkdirat, chdir, rmdir, fstatat...\n");
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook mkdirat: %d\n", err);
        return -EINVAL;
    }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook chdir: %d\n", err);
        return -EINVAL;
    }
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook rmdir: %d\n", err);
        return -EINVAL;
    }
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook unlinkat (for rmdir): %d\n", err);
        return -EINVAL;
    }
#else
#   error "No suitable syscall number for rmdir/unlinkat"
#endif
    // fstatat 兼容新旧架构
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook newfstatat: %d\n", err);
        return -EINVAL;
    }
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook fstatat64: %d\n", err);
        return -EINVAL;
    }
#endif
    pr_info("[HMA++]Successfully hooked mkdirat, chdir, rmdir, fstatat.\n");
    return 0;
}

static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++]HMA++ exit. Unhooking mkdirat, chdir, rmdir, fstatat...\n");
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
    pr_info("[HMA++]Successfully unhooked all syscalls.\n");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
