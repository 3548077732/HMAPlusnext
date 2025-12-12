#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/delay.h>
// 渲染优化核心依赖头文件（兼容安卓10+64位内核，无高版本独有接口）
#include <linux/gpu/drm.h>
#include <linux/dma-buf.h>
#include <linux/egl.h>
#include <linux/fb.h>

// APatch KPM模块基础信息（符合官方规范）
KPM_NAME("RenderOpt++");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("Custom Dev");
KPM_DESCRIPTION("渲染优化KPM模块，适配安卓10+64位内核，支持系统/内核双运行模式");

// 核心优化配置宏（适配双运行模式，通用无版本依赖）
#define SYS_MODE_TARGET_FPS 90    // 系统加载模式目标帧率
#define KERNEL_MODE_TARGET_FPS 60 // 内核嵌入模式目标帧率
#define TEXTURE_BATCH_THRESHOLD 5 // 纹理批处理触发阈值
#define TARGET_RENDER_PATH "/dev/dri/" // 核心渲染设备路径（通用路径）
#define TARGET_PATH_LEN (sizeof(TARGET_RENDER_PATH) - 1)

// 渲染优化全局状态（记录配置，退出时恢复）
static struct render_opt_state {
    bool egl_cache_enabled;       // EGL缓存启用状态
    int origin_fps_limit;         // 原始帧率限制
    bool origin_sync_state;       // 原始渲染同步状态
    int run_mode;                 // 运行模式（系统/内核）
} render_state = {
    .egl_cache_enabled = false,
    .origin_fps_limit = 0,
    .origin_sync_state = true,
    .run_mode = -1
};

// 兼容层：判断运行模式（系统加载/内核嵌入，适配全KPM版本）
static int get_run_mode(void) {
#if KPM_VERSION >= 2.0
    return kpm_get_run_mode();
#else
    // 低版本KPM通过环境标识判断，符合官方兼容逻辑
    if (kpm_check_env("KERNEL_RUN_MODE")) return 1;
    else return 0;
#endif
}

// 兼容层：64位架构校验（适配全KPM版本+安卓内核）
static bool is_64bit_arch(void) {
#if KPM_VERSION >= 2.0
    return kpm_arch_is_64bit();
#else
    return (sizeof(void*) == 8) && IS_ENABLED(CONFIG_64BIT);
#endif
}

// 兼容层：安卓版本校验（确保≥10，API29对应内核4.19+）
static bool is_android_version_compat(void) {
    int api_level = kpm_android_get_api_level();
    if (api_level >= 29) return true;
    // 低版本KPM无api获取接口，通过内核版本兜底（安卓10内核≥4.19）
    if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)) return true;
    return false;
}

// 核心：兼容性综合校验（全条件满足才启动优化）
static bool render_opt_compat_check(void) {
    // 64位架构校验
    if (!is_64bit_arch()) {
        pr_err("[RenderOpt++] 不支持32位内核，适配失败");
        return false;
    }
    // 安卓版本校验
    if (!is_android_version_compat()) {
        pr_err("[RenderOpt++] 安卓版本低于10，适配失败");
        return false;
    }
    // KPM接口可用性校验
#if KPM_VERSION >= 1.5
    if (!kpm_render_api_available()) {
        pr_err("[RenderOpt++] 渲染接口不可用，适配失败");
        return false;
    }
#endif
    pr_info("[RenderOpt++] 兼容性校验通过");
    return true;
}

// 优化1：纹理批处理（合并同纹理绘制指令，减少GPU调度开销，通用适配）
static void render_texture_batch_optimize(void) {
    int tex_count = kpm_render_get_texture_count();
    if (tex_count >= TEXTURE_BATCH_THRESHOLD) {
        if (kpm_render_merge_texture_cmd() == 0) {
            pr_info("[RenderOpt++] 纹理批处理优化生效，合并纹理数：%d", tex_count);
        }
    }
}

// 优化2：EGL缓存复用（减少内存分配释放开销，仅系统模式支持）
static void render_egl_cache_optimize(void) {
    // 内核态不调用用户态EGL接口，避免跨态报错
    if (render_state.run_mode != 0) return;
    
    // 保存原始状态，退出时恢复
    render_state.egl_cache_enabled = kpm_egl_get_cache_state();
    if (!render_state.egl_cache_enabled) {
        kpm_egl_set_cache_reuse(true);
        pr_info("[RenderOpt++] EGL缓存复用优化生效");
    }
}

// 优化3：帧率稳定控制（双模式差异化适配，避免帧率波动）
static void render_fps_stabilize_optimize(void) {
    int target_fps = (render_state.run_mode == 1) ? KERNEL_MODE_TARGET_FPS : SYS_MODE_TARGET_FPS;
    // 保存原始配置
    render_state.origin_fps_limit = kpm_render_get_fps_limit();
    render_state.origin_sync_state = kpm_render_get_sync_state();
    
    kpm_render_set_fps_limit(target_fps);
    kpm_render_set_sync_state(false); // 关闭冗余同步，提升效率
    pr_info("[RenderOpt++] 帧率稳定优化生效，目标帧率：%d", target_fps);
}

// 钩子1：drm显示配置前置优化（渲染核心接口，适配安卓10+内核）
static void before_drm_mode_set_crtc(hook_fargs5_t *args, void *udata) {
    const char __user *dev_path = (const char __user *)syscall_argn(args, 0);
    char dev_kernel_path[PATH_MAX];
    long len = compat_strncpy_from_user(dev_kernel_path, dev_path, sizeof(dev_kernel_path));
    
    if (len <= 0 || len >= sizeof(dev_kernel_path)) return;
    dev_kernel_path[len] = '\0';
    
    // 仅对核心渲染设备路径触发优化
    if (strncmp(dev_kernel_path, TARGET_RENDER_PATH, TARGET_PATH_LEN) == 0) {
        render_texture_batch_optimize();
        pr_debug("[RenderOpt++] DRM显示配置触发渲染优化");
    }
}

// 钩子2：EGL绘制前置优化（系统模式专属，用户态渲染接口）
static void before_egl_swap_buffers(hook_fargs2_t *args, void *udata) {
    // 仅系统模式生效
    if (render_state.run_mode != 0) return;
    
    EGLDisplay display = (EGLDisplay)syscall_argn(args, 0);
    EGLSurface surface = (EGLSurface)syscall_argn(args, 1);
    if (display && surface) {
        render_egl_cache_optimize();
        pr_debug("[RenderOpt++] EGL绘制触发缓存优化");
    }
}

// 钩子3：渲染缓冲分配前置优化（双模式通用）
static void before_dma_buf_alloc(hook_fargs3_t *args, void *udata) {
    size_t buf_size = (size_t)syscall_argn(args, 1);
    // 大缓冲分配时启用复用逻辑，减少内存开销
    if (buf_size >= 1024 * 1024) { // 1MB以上缓冲触发
        kpm_dma_buf_set_reuse(true);
        pr_debug("[RenderOpt++] 大尺寸渲染缓冲分配触发复用优化");
    }
}

// 模块初始化（KPM_INIT指定，符合官方规范，双运行模式适配）
static long render_opt_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    
    pr_info("[RenderOpt++] 渲染优化模块启动初始化...");
    
    // 获取运行模式并记录
    render_state.run_mode = get_run_mode();
    pr_info("[RenderOpt++] 当前运行模式：%s", 
            render_state.run_mode == 0 ? "系统加载模式" : "内核嵌入模式");
    
    // 兼容性校验
    if (!render_opt_compat_check()) {
        pr_err("[RenderOpt++] 初始化失败，兼容性不满足");
        return -EINVAL;
    }
    
    // 初始化优化配置（保存原始状态，便于退出恢复）
    render_state.origin_fps_limit = kpm_render_get_fps_limit();
    render_state.origin_sync_state = kpm_render_get_sync_state();
    render_state.egl_cache_enabled = kpm_egl_get_cache_state();
    
    // 启动核心优化逻辑
    render_fps_stabilize_optimize();
    render_texture_batch_optimize();
    if (render_state.run_mode == 0) {
        render_egl_cache_optimize();
    }
    
    // 挂钩渲染核心接口（适配不同KPM版本，避免编译报错）
    // 1. DRM显示配置接口钩子
#if defined(__NR_drm_mode_set_crtc)
    err = hook_syscalln(__NR_drm_mode_set_crtc, 5, before_drm_mode_set_crtc, NULL, NULL);
    if (err) {
        pr_err("[RenderOpt++] DRM接口挂钩失败：%d", err);
        return -EINVAL;
    }
#endif
    // 2. EGL绘制接口钩子（仅系统模式挂钩）
    if (render_state.run_mode == 0 && defined(__NR_egl_swap_buffers)) {
        err = hook_syscalln(__NR_egl_swap_buffers, 2, before_egl_swap_buffers, NULL, NULL);
        if (err) {
            pr_warn("[RenderOpt++] EGL接口挂钩失败：%d，不影响核心优化", err);
        }
    }
    // 3. 渲染缓冲分配接口钩子
#if defined(__NR_dma_buf_alloc)
    err = hook_syscalln(__NR_dma_buf_alloc, 3, before_dma_buf_alloc, NULL, NULL);
    if (err) {
        pr_err("[RenderOpt++] DMA缓冲接口挂钩失败：%d", err);
        return -EINVAL;
    }
#endif
    
    pr_info("[RenderOpt++] 渲染优化模块初始化完成，所有核心优化已生效");
    return 0;
}

// 模块退出（KPM_EXIT指定，符合官方规范，资源完整回收）
static long render_opt_exit(void *__user reserved) {
    pr_info("[RenderOpt++] 渲染优化模块开始退出，恢复原始渲染配置...");
    
    // 恢复原始帧率配置
    kpm_render_set_fps_limit(render_state.origin_fps_limit);
    kpm_render_set_sync_state(render_state.origin_sync_state);
    // 恢复EGL缓存状态（仅系统模式）
    if (render_state.run_mode == 0) {
        kpm_egl_set_cache_reuse(render_state.egl_cache_enabled);
    }
    // 关闭缓冲复用
    kpm_dma_buf_set_reuse(false);
    
    // 解绑所有挂钩接口（适配不同KPM版本）
#if defined(__NR_drm_mode_set_crtc)
    unhook_syscalln(__NR_drm_mode_set_crtc, before_drm_mode_set_crtc, NULL);
#endif
    if (render_state.run_mode == 0 && defined(__NR_egl_swap_buffers)) {
        unhook_syscalln(__NR_egl_swap_buffers, before_egl_swap_buffers, NULL);
    }
#if defined(__NR_dma_buf_alloc)
    unhook_syscalln(__NR_dma_buf_alloc, before_dma_buf_alloc, NULL);
#endif
    
    // 重置全局状态
    memset(&render_state, 0, sizeof(struct render_opt_state));
    render_state.run_mode = -1;
    
    pr_info("[RenderOpt++] 渲染优化模块退出完成，所有资源已恢复");
    return 0;
}

// APatch KPM官方指定初始化/退出入口
KPM_INIT(render_opt_init);
KPM_EXIT(render_opt_exit);
