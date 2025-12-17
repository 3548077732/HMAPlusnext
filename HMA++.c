#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <kpm.h>  // KPM 内核模块必需头文件

// 模块信息（保持你的配置）
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("NightFallsLikeRain");
MODULE_DESCRIPTION("HMA++ Next - Android 应用风险与广告拦截模块");
MODULE_VERSION("1.0");

// 总开关（添加 __unused 消除未使用警告）
static bool hma_running __unused = true;

// 白名单应用包名（示例，可根据需求扩展）
static const char *whitelist_packages[] = {
    "com.android.systemui",
    "com.google.android.gms",
    "com.android.settings",
    "com.tencent.mm",          // 微信
    "com.tencent.mobileqq",    // QQ
    "com.tencent.minihd.qq",   // QQ轻量版
    "com.tencent.wework",      // 企业微信
    // 系统基础软件
    "com.android.systemui",    // 系统UI
    "com.android.settings",    // 设置
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
    "com.meizu.flyme.launcher" // 魅族桌面
    "me.bmax.apatch"
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

// 声明：检查当前进程是否在白名单中
static bool is_in_whitelist(void) {
    char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);  // 获取当前进程名称（对应应用包名）
    
    for (size_t i = 0; i < ARRAY_SIZE(whitelist_packages); i++) {
        if (strcmp(comm, whitelist_packages[i]) == 0) {
            return true;
        }
    }
    return false;
}

// 声明：广告路径匹配（用于 should_block_ad，消除未使用警告）
static bool should_block_ad(const char *path) {
    const char *ad_paths[] = {
        "/sdcard/Android/data/*/cache/ad",
        "/data/data/*/files/ad",
        "/mnt/sdcard/AdCache",
        "ad.jpg", "ad.png", "ad_video"  // 常见广告资源关键词
    };
    
    for (size_t i = 0; i < ARRAY_SIZE(ad_paths); i++) {
        if (strstr(path, ad_paths[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// 关键修复 1：添加函数原型声明（解决隐式声明错误）
static void before_file_op(void *args, int syscall_num);

// 关键修复 2：按系统调用类型定义参数结构体（适配不同 hook_fargsN_t）
typedef struct {
    const char __user *pathname;
} hook_args1_t;  // 对应 hook_fargs1_t（1 个字符串参数）

typedef struct {
    int dirfd;
    const char __user *pathname;
    int flags;
    umode_t mode;
} hook_args4_t;  // 对应 hook_fargs4_t（4 个参数）

typedef struct {
    int dirfd;
    const char __user *pathname;
    int flags;
    umode_t mode;
    unsigned int resolve;
} hook_args5_t;  // 对应 hook_fargs5_t（5 个参数）

// 核心文件操作拦截逻辑（关键修复：用 void* 兼容不同参数类型）
static void before_file_op(void *args, int syscall_num) {
    if (!hma_running || is_in_whitelist()) {
        return;  // 白名单应用直接放行
    }

    char path[PATH_MAX] = {0};
    const char __user *user_path = NULL;

    // 关键修复 3：根据系统调用号转换参数类型，提取文件路径
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

    // 拷贝用户空间路径到内核空间（安全检查）
    if (copy_from_user(path, user_path, PATH_MAX) != 0) {
        return;
    }

    // 风险拦截逻辑（广告路径 + 敏感操作）
    if (should_block_ad(path) || syscall_num == __NR_unlinkat || syscall_num == __NR_rmdir) {
        printk(KERN_INFO "HMA++: Blocked risky file op [pid:%d, pkg:%s, path:%s, syscall:%d]\n",
               current->tgid, current->comm, path, syscall_num);
        // 拦截系统调用（返回权限拒绝）
        current->thread_info->syscall_work |= SYSCALL_WORK_STOP;
        current->thread_info->syscall_ret = -EPERM;
    }
}

// 系统调用 hook 实现（关键修复：参数类型匹配 + 正确转换）
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

// 关键修复 4：注册 hook 函数（消除未使用警告，确保模块生效）
static const struct kpm_hook syscall_hooks[] __initconst = {
    KPM_HOOK(__NR_mkdirat, before_mkdirat, NULL),
    KPM_HOOK(__NR_chdir, before_chdir, NULL),
    KPM_HOOK(__NR_rmdir, before_rmdir, NULL),
    KPM_HOOK(__NR_unlinkat, before_unlinkat, NULL),
    KPM_HOOK(__NR_openat, before_openat, NULL),
    KPM_HOOK(__NR_renameat, before_renameat, NULL),
};

// 模块加载函数
static int __init hma_init(void) {
    int ret = kpm_register_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
    if (ret == 0) {
        printk(KERN_INFO "HMA++ Next loaded successfully (whitelist mode enabled)\n");
    } else {
        printk(KERN_ERR "HMA++ Next load failed: %d\n", ret);
    }
    return ret;
}

// 模块卸载函数
static void __exit hma_exit(void) {
    kpm_unregister_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
    printk(KERN_INFO "HMA++ Next unloaded\n");
}

module_init(hma_init);
module_exit(hma_exit);
