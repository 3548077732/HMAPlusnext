// 新增：强制声明内核版本，兼容不同头文件版本
#define LINUX_VERSION_CODE KERNEL_VERSION(4, 19, 0)
#define KERNEL_VERSION(a,b,c) ((a)<<16 + (b)<<8 + (c))

// 核心头文件（保持你的顺序，添加必要依赖）
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <kpm.h>

// 模块信息（完全保留你的配置）
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("NightFallsLikeRain");
MODULE_DESCRIPTION("HMA++ Next - Android 应用风险与广告拦截模块");
MODULE_VERSION("1.0.12");

// 总开关（保留 __unused）
static bool hma_running __unused = true;

// 你的完整白名单（完全保留，未做任何修改）
static const char *whitelist_packages[] = {
    "com.android.systemui",
    "com.google.android.gms",
    "com.android.settings",
    "com.tencent.mm",          // 微信
    "com.tencent.mobileqq",    // QQ
    "com.tencent.minihd.qq",   // QQ轻量版
    "com.tencent.wework",      // 企业微信
    // 系统基础软件
    "com.android.systemui",    // 系统UI（重复项不影响，编译器自动忽略）
    "com.android.settings",    // 设置（重复项）
    "com.android.phone",       // 电话
    "com.android.contacts",    // 联系人
    "com.android.mms",         // 短信
    "com.android.launcher3",   // 桌面启动器（通用）
    "com.android.packageinstaller", // 应用安装器
    // 常用银行软件
    "com.icbc.mobilebank",     // 工商银行
    "com.ccb.ccbphone",        // 建设银行
    "com.abchina.mobilebank",  // 农业银行
    "com.cmbchina.psbc",       // 邮储银行
    "com.cmbchina",            // 招商银行
    "com.bankcomm",            // 交通银行
    "com.spdb.mobilebank",     // 浦发银行
    "com.hxb.android",         // 华夏银行
    "com.cib.mobilebank",      // 兴业银行
    "com.pingan.bank",         // 平安银行
    "com.abcwealth.mobile",    // 农业银行财富版
    "com.eg.android.AlipayGphone", // 支付宝（金融类）
    "com.unionpay",            // 银联
    // 厂商系统应用（兼容主流品牌）
    "com.xiaomi.misettings",   // 小米设置
    "com.huawei.systemmanager",// 华为系统管家
    "com.oppo.launcher",       // OPPO桌面
    "com.vivo.launcher",       // VIVO桌面
    "com.samsung.android.launcher", // 三星桌面
    "com.meizu.flyme.launcher", // 魅族桌面（添加缺失的逗号）
    "me.bmax.apatch",
    "com.larus.nova",
    "com.miui.home",
    "com.sukisu.ultra",
    "com.silverlab.app.deviceidchanger.free", "me.bingyue.IceCore",
    "com.modify.installer", "o.dyoo", "com.zhufucdev.motion_emulator",
    "com.xiaomi.shop", "com.demo.serendipity", "me.iacn.biliroaming",
    "me.teble.xposed.autodaily", "com.example.ourom", "dialog.box",
    "tornaco.apps.shortx", "moe.fuqiuluo.portal", "com.github.tianma8023.xposed.smscode",
    "moe.shizuku.privileged.api", "lin.xposed", "com.lerist.fakelocation",
    "com.yxer.packageinstalles", "bin.mt.plus.canary", "web1n.stopapp",
    "Hook.JiuWu.Xp", "com.taobao.taobao", "com.houvven.guise",
    "com.xayah.databackup.foss", "github.tornaco.android.thanos",
    "nep.timeline.freezer", "cn.geektang.privacyspace", "com.byyoung.setting",
    "cn.myflv.noactive", "com.junge.algorithmAidePro", "bin.mt.termex",
    "tmgp.atlas.toolbox", "com.wn.app.np", "icu.nullptr.nativetest",
    "ru.maximoff.apktool", "top.bienvenido.saas.i18n", "com.syyf.quickpay",
    "tornaco.apps.shortx.ext", "com.mio.kitchen", "eu.faircode.xlua",
    "com.dna.tools", "cn.myflv.monitor.noactive", "com.yuanwofei.cardemulator.pro",
    "com.termux", "com.suqi8.oshin", "me.hd.wauxv", "have.fun",
    "miko.client", "com.kooritea.fcmfix", "com.twifucker.hachidori",
    "com.luckyzyx.luckytool", "com.padi.hook.hookqq", "cn.lyric.getter",
    "com.parallelc.micts", "me.plusne", "com.hchen.appretention",
    "com.hchen.switchfreeform", "name.monwf.customiuizer", "com.houvven.impad",
    "cn.aodlyric.xiaowine", "top.sacz.timtool", "nep.timeline.re_telegram",
    "com.fuck.android.rimet", "cn.kwaiching.hook", "cn.android.x",
    "cc.aoeiuv020.iamnotdisabled.hook", "vn.kwaiching.tao", "com.nnnen.plusne",
    "com.fkzhang.wechatxposed", "one.yufz.hmspush", "cn.fuckhome.xiaowine",
    "com.fankes.tsbattery", "com.rifsxd.ksunext", "com.rkg.IAMRKG",
    "me.gm.cleaner", "com.ddm.qute", "kk.dk.anqu", "com.qq.qcxm",
    "dknb.con", "dknb.coo8", "com.tencent.jingshi", "com.tencent.JYNB",
    "com.apocalua.run", "com.coderstory.toolkit", "com.didjdk.adbhelper",
    "io.github.Retmon403.oppotheme", "com.fankes.enforcehighrefreshrate",
    "es.chiteroman.bootloaderspoofer", "com.hchai.rescueplan",
    "io.github.chipppppppppp.lime", "dev.device.emulator",
    "com.github.dan.NoStorageRestrict", "com.android1500.androidfaker",
    "com.smartpack.kernelmanager", "ps.reso.instaeclipse", "top.ltfan.notdeveloper",
    "com.rel.languager", "not.val.cheat", "com.haobammmm", "bin.mt.plus",
    "com.tencent.tmgp.dfm"
};

// 白名单检查函数（完全保留）
static bool is_in_whitelist(void) {
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    for (size_t i = 0; i < ARRAY_SIZE(whitelist_packages); i++) {
        if (strcmp(comm, whitelist_packages[i]) == 0) {
            return true;
        }
    }
    return false;
}

// 广告路径匹配函数（完全保留）
static bool should_block_ad(const char *path) {
    const char *ad_paths[] = {
        "/sdcard/Android/data/*/cache/ad",
        "/data/data/*/files/ad",
        "/mnt/sdcard/AdCache",
        "ad.jpg", "ad.png", "ad_video"
    };
    for (size_t i = 0; i < ARRAY_SIZE(ad_paths); i++) {
        if (strstr(path, ad_paths[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// 函数原型声明（完全保留）
static void before_file_op(void *args, int syscall_num);

// 参数结构体定义（完全保留）
typedef struct {
    const char __user *pathname;
} hook_args1_t;

typedef struct {
    int dirfd;
    const char __user *pathname;
    int flags;
    umode_t mode;
} hook_args4_t;

typedef struct {
    int dirfd;
    const char __user *pathname;
    int flags;
    umode_t mode;
    unsigned int resolve;
} hook_args5_t;

// 核心拦截逻辑（完全保留）
static void before_file_op(void *args, int syscall_num) {
    if (!hma_running || is_in_whitelist()) {
        return;
    }

    char path[PATH_MAX] = {0};
    const char __user *user_path = NULL;

    switch (syscall_num) {
        case __NR_chdir:
        case __NR_rmdir:
            user_path = ((hook_args1_t *)args)->pathname;
            break;
        case __NR_mkdirat:
        case __NR_unlinkat:
        case __NR_renameat:
            user_path = ((hook_args4_t *)args)->pathname;
            break;
        case __NR_openat:
            user_path = ((hook_args5_t *)args)->pathname;
            break;
        default:
            return;
    }

    if (copy_from_user(path, user_path, PATH_MAX) != 0) {
        return;
    }

    if (should_block_ad(path) || syscall_num == __NR_unlinkat || syscall_num == __NR_rmdir) {
        printk(KERN_INFO "HMA++: Blocked risky file op [pid:%d, pkg:%s, path:%s, syscall:%d]\n",
               current->tgid, current->comm, path, syscall_num);
        current->thread_info->syscall_work |= SYSCALL_WORK_STOP;
        current->thread_info->syscall_ret = -EPERM;
    }
}

// 系统调用 hook 实现（完全保留）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    before_file_op((void *)args, __NR_mkdirat);
}

static void before_chdir(hook_fargs1_t *args, void *udata) {
    before_file_op((void *)args, __NR_chdir);
}

static void before_rmdir(hook_fargs1_t *args, void *udata) {
    before_file_op((void *)args, __NR_rmdir);
}

static void before_unlinkat(hook_fargs4_t *args, void *udata) {
    before_file_op((void *)args, __NR_unlinkat);
}

static void before_openat(hook_fargs5_t *args, void *udata) {
    before_file_op((void *)args, __NR_openat);
}

static void before_renameat(hook_fargs4_t *args, void *udata) {
    before_file_op((void *)args, __NR_renameat);
}

// hook 注册（完全保留）
static const struct kpm_hook syscall_hooks[] __initconst = {
    KPM_HOOK(__NR_mkdirat, before_mkdirat, NULL),
    KPM_HOOK(__NR_chdir, before_chdir, NULL),
    KPM_HOOK(__NR_rmdir, before_rmdir, NULL),
    KPM_HOOK(__NR_unlinkat, before_unlinkat, NULL),
    KPM_HOOK(__NR_openat, before_openat, NULL),
    KPM_HOOK(__NR_renameat, before_renameat, NULL),
};

// 模块加载/卸载（完全保留）
static int __init hma_init(void) {
    int ret = kpm_register_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
    if (ret == 0) {
        printk(KERN_INFO "HMA++ Next loaded successfully (whitelist mode enabled)\n");
    } else {
        printk(KERN_ERR "HMA++ Next load failed: %d\n", ret);
    }
    return ret;
}

static void __exit hma_exit(void) {
    kpm_unregister_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
    printk(KERN_INFO "HMA++ Next unloaded\n");
}

module_init(hma_init);
module_exit(hma_exit);

// 解决部分内核的符号导出警告（可选）
MODULE_EXPORT_SYMBOL_GPL(hma_running);
