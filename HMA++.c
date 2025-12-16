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

// 模块元信息（整合优化版本）
KPM_NAME("HMA++ Next");
KPM_VERSION("1.1.0"); // 整合白名单+精准拦截优化
KPM_LICENSE("GPLv3");
KPM_AUTHOR("NightFallsLikeRain");
KPM_DESCRIPTION("核心风险拦截测试+广告拦截测试");

// 核心宏定义（精简适配+全量白名单）
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif
#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH)-1)
#define MAX_PACKAGE_LEN 2064

// 新增：常见合规应用白名单（社交+支付+办公+影音+出行+系统，精准放行）
// 1.社交核心类
#define WECHAT_PACKAGE "com.tencent.mm"
#define WECHAT_PATH "/storage/emulated/0/Android/data/com.tencent.mm/"
#define QQ_PACKAGE "com.tencent.mobileqq"
#define QQ_PATH "/storage/emulated/0/Android/data/com.tencent.mobileqq/"
#define TIM_PACKAGE "com.tencent.tim"
#define TIM_PATH "/storage/emulated/0/Android/data/com.tencent.tim/"
// 2.支付安全类
#define ALIPAY_PACKAGE "com.eg.android.AlipayGphone"
#define ALIPAY_PATH "/storage/emulated/0/Android/data/com.eg.android.AlipayGphone/"
#define UNIONPAY_PACKAGE "com.unionpay"
#define UNIONPAY_PATH "/storage/emulated/0/Android/data/com.unionpay/"
// 3.办公必备类
#define WPS_PACKAGE "cn.wps.moffice_eng"
#define WPS_PATH "/storage/emulated/0/Android/data/cn.wps.moffice_eng/"
#define DINGTALK_PACKAGE "com.alibaba.android.rimet"
#define DINGTALK_PATH "/storage/emulated/0/Android/data/com.alibaba.android.rimet/"
#define FEISHU_PACKAGE "com.bytedance.ee.en"
#define FEISHU_PATH "/storage/emulated/0/Android/data/com.bytedance.ee.en/"
// 4.影音娱乐类
#define DOUYIN_PACKAGE "com.ss.android.ugc.aweme"
#define DOUYIN_PATH "/storage/emulated/0/Android/data/com.ss.android.ugc.aweme/"
#define TENCENT_VIDEO_PACKAGE "com.tencent.qqlive"
#define TENCENT_VIDEO_PATH "/storage/emulated/0/Android/data/com.tencent.qqlive/"
#define NETEASE_CLOUD_PACKAGE "com.netease.cloudmusic"
#define NETEASE_CLOUD_PATH "/storage/emulated/0/Android/data/com.netease.cloudmusic/"
// 5.出行工具类
#define GAODE_MAP_PACKAGE "com.autonavi.minimap"
#define GAODE_MAP_PATH "/storage/emulated/0/Android/data/com.autonavi.minimap/"
#define BAIDU_MAP_PACKAGE "com.baidu.BaiduMap"
#define BAIDU_MAP_PATH "/storage/emulated/0/Android/data/com.baidu.BaiduMap/"
// 6.系统工具类（避免拦截核心系统应用）
#define SYSTEM_LAUNCHER_PACKAGE "com.android.launcher3"
#define SYSTEM_FILE_PACKAGE "com.android.documentsui"

// 白名单路径/包名长度宏（适配匹配逻辑，无冗余）
#define WECHAT_PACKAGE_LEN (sizeof(WECHAT_PACKAGE)-1)
#define WECHAT_PATH_LEN (sizeof(WECHAT_PATH)-1)
#define QQ_PACKAGE_LEN (sizeof(QQ_PACKAGE)-1)
#define QQ_PATH_LEN (sizeof(QQ_PATH)-1)
#define TIM_PACKAGE_LEN (sizeof(TIM_PACKAGE)-1)
#define TIM_PATH_LEN (sizeof(TIM_PATH)-1)
#define ALIPAY_PACKAGE_LEN (sizeof(ALIPAY_PACKAGE)-1)
#define ALIPAY_PATH_LEN (sizeof(ALIPAY_PATH)-1)
#define UNIONPAY_PACKAGE_LEN (sizeof(UNIONPAY_PACKAGE)-1)
#define UNIONPAY_PATH_LEN (sizeof(UNIONPAY_PATH)-1)
#define WPS_PACKAGE_LEN (sizeof(WPS_PACKAGE)-1)
#define WPS_PATH_LEN (sizeof(WPS_PATH)-1)
#define DINGTALK_PACKAGE_LEN (sizeof(DINGTALK_PACKAGE)-1)
#define DINGTALK_PATH_LEN (sizeof(DINGTALK_PATH)-1)
#define FEISHU_PACKAGE_LEN (sizeof(FEISHU_PACKAGE)-1)
#define FEISHU_PATH_LEN (sizeof(FEISHU_PATH)-1)
#define DOUYIN_PACKAGE_LEN (sizeof(DOUYIN_PACKAGE)-1)
#define DOUYIN_PATH_LEN (sizeof(DOUYIN_PATH)-1)
#define TENCENT_VIDEO_PACKAGE_LEN (sizeof(TENCENT_VIDEO_PACKAGE)-1)
#define TENCENT_VIDEO_PATH_LEN (sizeof(TENCENT_VIDEO_PATH)-1)
#define NETEASE_CLOUD_PACKAGE_LEN (sizeof(NETEASE_CLOUD_PACKAGE)-1)
#define NETEASE_CLOUD_PATH_LEN (sizeof(NETEASE_CLOUD_PATH)-1)
#define GAODE_MAP_PACKAGE_LEN (sizeof(GAODE_MAP_PACKAGE)-1)
#define GAODE_MAP_PATH_LEN (sizeof(GAODE_MAP_PATH)-1)
#define BAIDU_MAP_PACKAGE_LEN (sizeof(BAIDU_MAP_PACKAGE)-1)
#define BAIDU_MAP_PATH_LEN (sizeof(BAIDU_MAP_PATH)-1)

// 全局核心开关（极简变量，无冗余）
static bool hma_running = true;
static bool ad_block_running = true; // 广告拦截独立开关，方便排查

// 1.风险拦截黑名单（无空项，精简高效）
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

// 新增：风险文件后缀黑名单（精准匹配恶意文件，减少误判）
static const char *risk_suffix_list[] = {
    ".so", ".dex", ".apk", ".xposed", ".hook", ".inject", ".patch", ".mod"
};
#define RISK_SUFFIX_SIZE (sizeof(risk_suffix_list)/sizeof(risk_suffix_list[0]))

// 核心判断函数（整合优化，精准无冗余）
// 1.通用白名单校验（优先放行合规应用，杜绝闪退）
static int is_legal_path(const char *path) {
    if (!path) return 0;
    // 精准匹配应用完整存储路径
    if (strncmp(path, WECHAT_PATH, WECHAT_PATH_LEN) == 0 ||
        strncmp(path, QQ_PATH, QQ_PATH_LEN) == 0 ||
        strncmp(path, TIM_PATH, TIM_PATH_LEN) == 0 ||
        strncmp(path, ALIPAY_PATH, ALIPAY_PATH_LEN) == 0 ||
        strncmp(path, UNIONPAY_PATH, UNIONPAY_PATH_LEN) == 0 ||
        strncmp(path, WPS_PATH, WPS_PATH_LEN) == 0 ||
        strncmp(path, DINGTALK_PATH, DINGTALK_PATH_LEN) == 0 ||
        strncmp(path, FEISHU_PATH, FEISHU_PATH_LEN) == 0 ||
        strncmp(path, DOUYIN_PATH, DOUYIN_PATH_LEN) == 0 ||
        strncmp(path, TENCENT_VIDEO_PATH, TENCENT_VIDEO_PATH_LEN) == 0 ||
        strncmp(path, NETEASE_CLOUD_PATH, NETEASE_CLOUD_PATH_LEN) == 0 ||
        strncmp(path, GAODE_MAP_PATH, GAODE_MAP_PATH_LEN) == 0 ||
        strncmp(path, BAIDU_MAP_PATH, BAIDU_MAP_PATH_LEN) == 0) {
        return 1;
    }
    // 匹配应用包名（覆盖路径前缀场景）
    if (strncmp(path, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        const char *p = path + TARGET_PATH_LEN;
        if (strncmp(p, WECHAT_PACKAGE, WECHAT_PACKAGE_LEN) == 0 ||
            strncmp(p, QQ_PACKAGE, QQ_PACKAGE_LEN) == 0 ||
            strncmp(p, TIM_PACKAGE, TIM_PACKAGE_LEN) == 0 ||
            strncmp(p, ALIPAY_PACKAGE, ALIPAY_PACKAGE_LEN) == 0 ||
            strncmp(p, UNIONPAY_PACKAGE, UNIONPAY_PACKAGE_LEN) == 0 ||
            strncmp(p, WPS_PACKAGE, WPS_PACKAGE_LEN) == 0 ||
            strncmp(p, DINGTALK_PACKAGE, DINGTALK_PACKAGE_LEN) == 0 ||
            strncmp(p, FEISHU_PACKAGE, FEISHU_PACKAGE_LEN) == 0 ||
            strncmp(p, DOUYIN_PACKAGE, DOUYIN_PACKAGE_LEN) == 0 ||
            strncmp(p, TENCENT_VIDEO_PACKAGE, TENCENT_VIDEO_PACKAGE_LEN) == 0 ||
            strncmp(p, NETEASE_CLOUD_PACKAGE, NETEASE_CLOUD_PACKAGE_LEN) == 0 ||
            strncmp(p, GAODE_MAP_PACKAGE, GAODE_MAP_PACKAGE_LEN) == 0 ||
            strncmp(p, BAIDU_MAP_PACKAGE, BAIDU_MAP_PACKAGE_LEN) == 0 ||
            strncmp(p, SYSTEM_LAUNCHER_PACKAGE, sizeof(SYSTEM_LAUNCHER_PACKAGE)-1) == 0 ||
            strncmp(p, SYSTEM_FILE_PACKAGE, sizeof(SYSTEM_FILE_PACKAGE)-1) == 0) {
            return 1;
        }
    }
    return 0;
}

// 2.风险后缀校验（精准筛选恶意文件）
static int has_risk_suffix(const char *path) {
    if (!path) return 0;
    size_t path_len = strlen(path);
    if (path_len < 2) return 0; // 后缀至少2位，避免无效匹配
    for (size_t i = 0; i < RISK_SUFFIX_SIZE; i++) {
        size_t suffix_len = strlen(risk_suffix_list[i]);
        if (path_len >= suffix_len && 
            strcmp(path + path_len - suffix_len, risk_suffix_list[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// 3.风险路径判断（三重校验：白名单放行+黑名单匹配+风险后缀）
static int is_blocked_path(const char *path) {
    if (is_legal_path(path)) return 0; // 优先放行白名单，核心兼容逻辑
    if (*path != '/' || strncmp(path, TARGET_PATH, TARGET_PATH_LEN) != 0) return 0;
    size_t path_len = strlen(path);
    if (path_len <= TARGET_PATH_LEN) return 0; // 排除无效短路径
    
    char target_buf[MAX_PACKAGE_LEN] = {0};
    const char *p = path + TARGET_PATH_LEN;
    size_t i = 0;
    while (*p && *p != '/' && i < MAX_PACKAGE_LEN - 1) {
        target_buf[i++] = *p++;
    }
    if (i == 0) return 0;

    // 风险包名+风险后缀双重拦截
    for (size_t j = 0; j < DENY_LIST_SIZE; j++) {
        if (strcmp(target_buf, deny_list[j]) == 0) {
            return has_risk_suffix(path) ? 1 : 0;
        }
    }
    // 风险文件夹直接拦截
    for (size_t k = 0; k < DENY_FOLDER_SIZE; k++) {
        if (strcmp(target_buf, deny_folder_list[k]) == 0) {
            return 1;
        }
    }
    return 0;
}

// 4.广告拦截判断（精准关键词+独立开关）
static int is_ad_blocked(const char *path) {
    if (!ad_block_running || !path) return 0;
    char lower_path[PATH_MAX];
    memset(lower_path, 0, sizeof(lower_path));
    strncpy(lower_path, path, PATH_MAX - 1);
    // 转小写，避免大小写误判
    for (char *s = lower_path; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') *s += 32;
    }
    // 精准匹配广告关键词
    for (size_t i = 0; i < AD_FILE_KEYWORD_SIZE; i++) {
        if (strstr(lower_path, ad_file_keywords[i]) != NULL) return 1;
    }
    return 0;
}

// 核心文件操作钩子（统一错误码+白名单优先，无闪退）
static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX] = {0};
    // 修复：替换为KPM框架适配函数kf_strncpy_from_user
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] mkdirat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -EACCES; // 统一权限不足错误码，兼容所有应用
    }
}

static void before_chdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX] = {0};
    // 修复：替换为KPM框架适配函数kf_strncpy_from_user
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] chdir deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}

#if defined(__NR_rmdir)
static void before_rmdir(hook_fargs1_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX] = {0};
    // 修复：替换为KPM框架适配函数kf_strncpy_from_user
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 0), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] rmdir deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}
#endif

#if defined(__NR_unlinkat)
static void before_unlinkat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX] = {0};
    // 修复：替换为KPM框架适配函数kf_strncpy_from_user
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] unlinkat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}
#endif

#ifdef __NR_openat
static void before_openat(hook_fargs5_t *args, void *udata) {
    if (!hma_running) return;
    char path[PATH_MAX] = {0};
    // 修复：替换为KPM框架适配函数kf_strncpy_from_user
    long len = kf_strncpy_from_user(path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    if (len <= 0) return;
    path[len] = '\0';
    if (is_legal_path(path)) return; // 白名单应用文件读写直接放行
    if (is_blocked_path(path) || is_ad_blocked(path)) {
        pr_warn("[HMA++] openat deny: %s\n", path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}
#endif

#ifdef __NR_renameat
static void before_renameat(hook_fargs4_t *args, void *udata) {
    if (!hma_running) return;
    char old_path[PATH_MAX] = {0}, new_path[PATH_MAX] = {0};
    // 修复：两处均替换为KPM框架适配函数kf_strncpy_from_user
    long len_old = kf_strncpy_from_user(old_path, (void *)syscall_argn(args, 1), PATH_MAX - 1);
    long len_new = kf_strncpy_from_user(new_path, (void *)syscall_argn(args, 3), PATH_MAX - 1);
    if (len_old <= 0 || len_new <= 0) return;
    old_path[len_old] = '\0';
    new_path[len_new] = '\0';
    if (is_legal_path(old_path) || is_legal_path(new_path)) return; // 白名单路径放行
    if (is_blocked_path(old_path) || is_blocked_path(new_path) || is_ad_blocked(old_path) || is_ad_blocked(new_path)) {
        pr_warn("[HMA++] renameat deny: %s -> %s\n", old_path, new_path);
        args->skip_origin = 1;
        args->ret = -EACCES;
    }
}
#endif

// 模块生命周期（极简无冗余，解钩完整）
static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++] init start (v1.1.0, full whitelist+precise block)\n");

    // 挂钩核心文件操作syscall，容错处理
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) { pr_err("[HMA++] hook mkdirat err: %d\n", err); return -EINVAL; }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) { pr_err("[HMA++] hook chdir err: %d\n", err); return -EINVAL; }
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

    pr_info("[HMA++] init success\n");
    return 0;
}

// 启停控制（主拦截+广告拦截独立开关，适配排查）
static long hma_control0(const char *args, char *__user out_msg, int outlen) {
    char msg[64] = {0};
    if (!args || strlen(args) < 1 || strlen(args) > 2) {
        strncpy(msg, "args err: 0(off)/1(on)/2(ad_off)/3(ad_on)", sizeof(msg)-1);
        goto out_copy;
    }
    // 多开关精准控制
    switch (args[0]) {
        case '0': hma_running = false; strncpy(msg, "main interception disabled", sizeof(msg)-1); break;
        case '1': hma_running = true; strncpy(msg, "main interception enabled", sizeof(msg)-1); break;
        case '2': ad_block_running = false; strncpy(msg, "ad interception disabled", sizeof(msg)-1); break;
        case '3': ad_block_running = true; strncpy(msg, "ad interception enabled", sizeof(msg)-1); break;
        default: strncpy(msg, "args err: only 0/1/2/3", sizeof(msg)-1);
    }

out_copy:
    if (outlen >= strlen(msg) + 1) {
        compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
    }
    return 0;
}

// 预留控制接口（极简实现，方便后续扩展）
static long hma_control1(void *a1, void *a2, void *a3) {
    return 0;
}

// 模块退出（完整解钩所有syscall，无残留）
static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++] exit start\n");
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
    pr_info("[HMA++] exit success\n");
    return 0;
}

// 模块注册（符合KPM规范，可直接部署）
KPM_INIT(mkdir_hook_init);
KPM_CTL0(hma_control0);
KPM_CTL1(hma_control1);
KPM_EXIT(mkdir_hook_exit);
