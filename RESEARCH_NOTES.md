# CVE-2026-43499 (GhostLock) 利用研究 — 思路与难点公布

> **项目性质**: 内核安全研究 / 漏洞利用技术移植
> **目标设备**: Xiaomi Pad 7 Ultra (jinghu), XRing O1 SoC
> **参考案例**: dijun (Xiaomi 15S Pro) 成功 exploit by Littlenine Ennea
> **日期**: 2026-07-18

---

## 1. 研究背景

CVE-2026-43499 是 Linux 内核 RT-Mutex 子系统的一个栈上 use-after-free 漏洞，影响 6.6.x 内核（含 Android GKI 6.6.77）。该漏洞允许在特定条件下实现内核任意地址写入，进而提权至 root。

本研究的目标是将该漏洞的利用技术从已公开的 dijun (Xiaomi 15S Pro) 成功案例，移植到同芯片同内核的 jinghu (Xiaomi Pad 7 Ultra) 设备上，并在此过程中理清利用链的每一环、定位移植难点、探索通用的内核信息泄露方法。

**关键事实**：dijun 和 jinghu 都是 XRing O1 芯片，内核版本完全一致（`6.6.77-android15-8-g5770c661275f-abogki443185593-4k`）。dijun 安全补丁更新（2026-04-01），jinghu 较旧（2026-03-01）。理论上 jinghu 更易利用，但当前未成功——原因在于**利用路线的偏差**，而非漏洞本身。

---

## 2. 漏洞原理 (GhostLock)

### 2.1 根因

`rt_mutex_cleanup_proxy_lock()` 在 `owner == current` 时跳过 `remove_waiter()`，导致 `task->pi_blocked_on`（位于 `task+0x938`）残留指向已释放的栈上 `rt_mutex_waiter` 结构体。

```
futex_wait_requeue_pi → rt_mutex_wait_proxy_lock 阻塞
    → owner 释放锁 → waiter 获取锁
    → rt_mutex_cleanup_proxy_lock 检查 owner==current
    → 跳过 remove_waiter() ← BUG
    → pi_blocked_on 不清理, 仍指向栈上 waiter
    → futex_wait_requeue_pi 返回, 栈回缩
```

### 2.2 触发链

```
1. waiter 线程: futex_wait_requeue_pi → 留下 dangling pi_blocked_on
2. 同一线程: pselect 复用同一栈区域
   → core_sys_select 的保存寄存器覆盖 freed waiter 字段
3. consumer 线程: sched_setattr(alternating nice)
   → rt_mutex_adjust_prio_chain 通过 pi_blocked_on 访问已覆盖的 waiter
   → 读到攻击者控制的 fd_set 值
   → PI 链遍历到伪造结构 → 实现任意地址写入
```

### 2.3 栈布局 (jinghu 反汇编验证)

```
KSP_TOP
  futex 链 (0x2F0 深): futex_wait_requeue_pi(0x70) → futex_wait(0x60) → task_blocks(0x1C0)
  waiter 位于 KSP_TOP - 0x2F0

  pselect 链 (0x6A0 深): syscall_entry → sys_pselect6 → core_sys_select(0x1F0) → do_select(0x3C0)
  core_sys_select sp = KSP_TOP - 0x2E0
  waiter = sp_css - 0x10
```

**关键字段覆盖映射**（waiter = sp_css - 0x10）：

| waiter 偏移 | core_sys_select sp 偏移 | 覆盖值 |
|---|---|---|
| +0x58 (lock) | sp+0x48 | readfds 用户指针 (PAN 不阻止访问) |
| +0x18 (prio) | sp+0x08 | SP_EL0 (task 指针低 32 位) |
| +0x50 (task) | sp+0x40 | writefds (NULL) |

---

## 3. 技术路线

### 3.1 写入原语

PI 链遍历到伪造的 `fake_w0` 节点时，`rb_insert` 会执行：

```
*(write_left + 0x08) = write_pc
```

其中：
- `write_left` = `fake_w0.pi_tree_entry.rb_left` = **写入目标地址 - 8**
- `write_pc` = `fake_w0.pi_tree_entry.__rb_parent_color` = **写入值**

通过 `set_pselect_write(target-8, value, 0)` 即可实现 `*target = value`。

### 3.2 dijun 成功路线 (cred 直写)

```
kernelsnitch leak mm_struct (futex hash 侧信道)
    ↓
读 mm->owner → task_struct 地址
    ↓
walk#1: 写 task->real_cred = init_cred   (slot_idx=1)
walk#2: 写 task->cred = init_cred        (slot_idx=2)
        + 写 selinux_state.enforcing = 0
    ↓
uid=0(root) context=kernel, SELinux Permissive
```

dijun 在 1 次 attempt 内完成，15 轮上限，10 秒超时。

### 3.3 jinghu 原路线 (fops 劫持) — 走偏

```
kernelsnitch leak mm_struct
    ↓
PI 链写 ashmem_misc_fops = fake_fops (劫持 file_operations)
    ↓
configfs_read_once 验证 fops 写入 ← 卡死 (返回 0 字节)
    ↓
leak_kernel_base → install_pipe → install_root
```

**问题**：fops 路线绕了一大圈，且依赖 `configfs_read_once` 做验证读。

---

## 4. 关键技术难点与突破

### 4.1 已突破的难点

| 难点 | 解决方式 | 状态 |
|---|---|---|
| **PAN 是否阻止内核访问用户空间** | 700+ 次 consumer 调用不崩，无 extable 条目。XRing O1 上软件 PAN 实际不生效 | ✅ 确认 |
| **rt_mutex_waiter 实际布局** | 反汇编 `futex_lock_pi` 验证：+0x00 tree_entry / +0x28 pi_tree_entry / +0x50 task / +0x58 lock | ✅ 验证 |
| **PI 树用 pi_tree_entry 而非 tree_entry** | 反汇编 `rt_mutex_adjust_prio_chain` 确认写入目标遍历发生在 owner->pi_waiters，用 pi_tree_entry（+0x28） | ✅ 验证 |
| **pselect 不阻塞 (ret=0 快速返回)** | readfds 全零 + exceptfds=NULL → do_select 无 fd 检查立即返回。修复：exceptfds 设 pipe read end | ✅ 解决 |
| **pi_blocked_on 指向错误** | fake_task->pi_blocked_on 必须指向 fake_w0 结构体起始（非 pi_tree_entry），使 waiter2->lock 从 +0x58 正确读取 | ✅ 修复 |
| **KASLR 绕过** | p0 profile delta=0，所有内核全局地址已知（init_task/init_cred/selinux_state 等） | ✅ 确认 |
| **写入目标偏移** | fake_w0.pi_prio=0x7FFFFFFF 保证走 right 路径到 [target+0x08]=0 → INSERT | ✅ 验证 |

### 4.2 kernelsnitch — 不依赖设备接口的信息泄露

本项目使用的 `kernelsnitch` 是一种**通过 futex hash 侧信道暴力搜索 mm_struct 地址**的技术，完全不依赖任何设备私有接口（如 `/dev/diag`）。

原理：`futex_hash(addr, mm)` 的哈希桶分布取决于 `mm` 参数。通过在多个 futex 地址上做 private wait，测量哈希桶碰撞，可以反推 `current->mm_struct` 地址。多线程暴力搜索 slab 范围内的候选地址，验证 `futex_hash(futex_addrs[0], candidate) == futex_hash(futex_addrs[i], candidate)`。

**这是通用 ARM64 内核信息泄露技术**，在 XRing O1 上同样适用。

### 4.3 当前卡点：mm_struct → task_struct

kernelsnitch 泄露的是 `mm_struct` 地址。要写入 `task->cred`，需要知道 `task_struct` 地址。这需要读取 `mm_struct + 0x408 (mm->owner)` 字段——即需要一次**内核内存读取**。

**configfs_read_once 失效的真正原因**（反汇编 `configfs_bin_read_iter` 证实）：

```
configfs_bin_read_iter 逻辑:
  [x24+0x50] (needs_read_fill) != 0 → 调用 read 函数填充 buffer
  [x24+0x50] == 0 → 跳到 0xe34, 直接从 buffer 读
    → buffer_size [x24+0x60] <= *ppos → 返回 0

configfs_read_once 设置:
  needs_read_fill = 0      ← 跳过填充
  buffer_size = 0 (未设)   ← 导致返回 0
```

**这不是 Android 16 修补，是代码实现的 bug**。CFG_* 偏移本身正确（反汇编验证 0x50/0x58/0x60/0x64 完全匹配）。该 bug 在 Pixel 上也存在，说明 configfs_read_once 可能从未真正成功过。早期文档中"Android 16 已修补 configfs"是误判。

### 4.4 路线偏差的教训

jinghu 项目早期误判 dijun 为 Qualcomm 平台（实际同为 XRing O1），错误地将 "DIAG" 解释为 `/dev/diag`，从而认为 jinghu 缺少信息泄露手段，转向 configfs + fops 路线。实际上：

- dijun 和 jinghu 同芯片同内核，dijun 能成功 = jinghu 理论上也能
- "DIAG" 更可能是日志中的 diagnostic 标签，而非独立技术
- dijun 走 cred 直写，**不依赖 configfs 验证**
- jinghu 走 fops 劫持，把 configfs 当成致命依赖

**核心教训**：路线选择应优先考虑**依赖最少的直写路径**，而非功能更全但链路更长的劫持路径。

---

## 5. 已完成的改造

基于 backup_v1 代码，已将 main.c 从 fops 路线改造为 cred 直写框架：

1. **target.h** 添加 `INIT_CRED` 定义（0xffffff80020f0548）
2. **main.c run_exploit** 重写为 3 次 walk：
   - walk#1: `set_pselect_write(real_cred-8, INIT_CRED, 0)` → `*real_cred = init_cred`
   - walk#2: `set_pselect_write(cred-8, INIT_CRED, 0)` → `*cred = init_cred`
   - walk#3: `set_pselect_write(selinux-8, 0, 0)` → `*enforcing = 0`
3. 调用 `current_kernelsnitch_mm_struct()`（backup_v1 原本 leak 了 mm_struct 却未使用）
4. `leak_task_struct()` 设计为可插拔接口（当前占位，待实现内核读）
5. 编译通过：`backup_v1/preload_cred.so` (142KB)

**写入机制已验证**：`set_pselect_write(target-8, value, 0)` 经 `prepare_skb_payload` 构造 `fake_w0.pi_tree.rb_left = target-8`、`pi_tree.__rb_parent_color = value`，PI 链触发后 `*(target) = value`。

---

## 6. 研究方向 (待解决)

### 6.1 核心问题：实现内核内存读取

要完成 cred 直写，必须有一种读取内核内存的方法来获取 `mm->owner`（task_struct 指针）。候选方案：

| 方案 | 原理 | 可行性 |
|---|---|---|
| **修复 configfs_read_once** | 设 needs_read_fill=非0 + 伪造 read 函数指针。需绕过 CFI 检查（brk #0x8228，校验 hash 0x741f28f8） | 中：需找到 hash 匹配的内核函数 |
| **XRing O1 替代内核读** | 探索 perf_event / ion / debugfs / sysfs 等接口的内核指针泄露 | 待真机实验 |
| **调整 kernelsnitch 直接 leak task_struct** | futex_hash 输入是 mm，能否改为 leak task？需分析 futex 内部是否用 task 作 hash | 低：需改核心算法 |
| **盲写 cred** | kernelsnitch leak mm + slab 布局推算 task_struct 位置，不验证直接写 | 低：mm 和 task 在不同 slab，无固定偏移 |

### 6.2 child mm → parent task 的推导

kernelsnitch 在 `clone_leak_child`（fork）中运行，leak 的是 child 的 mm_struct。要写 exploit 进程（parent）的 cred，需要：

```
child mm_struct → child task_struct (读 mm->owner@+0x408)
               → parent task_struct (读 task->real_parent@+0x628)
               → parent cred (task+0x818/0x820)
```

即需要**两次内核读**。若能让 kernelsnitch 在 parent 线程运行（leak parent mm），可减少为一次读。

### 6.3 多次 walk 的 slab 稳定性

当前框架每次 walk 调用 `prepare_good_kernel_page`，会重跑 kernelsnitch（重新 clone_child + memfd + spray）。mm_struct 地址可能变化，但 task_struct 一旦 leak 就固定。需验证多次 spray 不破坏已写入的 cred。

### 6.4 brk #0x800 crash

`rt_mutex_setprio` 在 `pi_blocked_on` 非空路径触发 BUG（约 20 轮后）。dijun 用 `csettle_us=500`（微秒级时序），比 jinghu 的 50ms 快 100 倍——快速完成可减少触发概率。

### 6.5 CFI 绕过研究

configfs_bin_read_iter 在调用 read 函数前检查 CFI hash（`[func-4] == 0x741f28f8`）。若能找到 hash 匹配且功能适用的内核函数，可修复 configfs_read_once。这本身是一个有研究价值的 CFI 绕过课题。

---

## 7. 关键地址与偏移 (jinghu, KASLR=0)

```
KIMAGE_TEXT_BASE  = 0xffffffc080000000
init_task         = 0xffffff80020de280
init_cred         = 0xffffff80020f0548
selinux_state     = 0xffffff8002315f68
ashmem_misc_fops  = 0xffffff800223b5e8

task_struct:  cred=+0x818  real_cred=+0x820  pi_blocked_on=+0x938
              pi_waiters=+0x920  real_parent=+0x628
mm_struct:    owner=+0x408
rt_mutex_waiter: tree_entry=+0x00  pi_tree_entry=+0x28  task=+0x50  lock=+0x58
```

---

## 8. 总结

本项目是一个完整的内核漏洞利用移植研究，涵盖：漏洞原理分析、内核反汇编、符号表重建、偏移量推导、侧信道信息泄露、PI 链写入原语、利用路线设计。

**已确认可行**：kernelsnitch leak + PI 链任意写 + cred 直写路线（dijun 已验证）。
**当前卡点**：mm_struct → task_struct 的内核读取（configfs_read_once 有 bug，需替代方案）。
**核心贡献**：理清了 configfs 失效的真正原因（代码 bug 而非 Android 16 修补）、定位了路线偏差（fops 劫持 vs cred 直写）、完成了 cred 直写框架改造。

欢迎对内核信息泄露、CFI 绕过、RT-Mutex 子系统感兴趣的研究者参与讨论。

---

*本研究仅供安全研究与防御目的。*
