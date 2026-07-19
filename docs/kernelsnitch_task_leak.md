# Kernelsnitch 扩展泄 task_struct 可行性报告

**日期**: 2026-07-19
**目标**: 审计 kernelsnitch 源码，判断能否扩展为泄露 task_struct 地址（破解 P1 的 task_struct leak 死结）。
**结论**: **kernelsnitch 不能直接扩展为泄 task_struct**。但本审计带来一个重要的认知纠正，并明确了真正的 blocker。

---

## 0. 结论速览

| 问题 | 答案 |
|---|---|
| kernelsnitch 能否泄 task_struct？ | ❌ 不能 |
| 为什么？ | futex_hash 第二个参数硬编码是 `current->mm`（在内核 `get_futex_key` 内），用户态不可控 |
| 能否换侧信道扫 task_struct？ | 理论可（task_struct 在 direct map），但需全新设计，工程量大 |
| dijun 怎么拿 task_struct？ | **所有现有文档未明说** —— 这是项目最大的认知空白 |
| 真正的 blocker 是什么？ | **waiter_thread 的 task_struct 地址未知**，PI 链 target 无法设置 |

---

## 1. Kernelsnitch 工作原理（源码审计）

### 1.1 文件位置

```
share-poc-XRing-O1/src/kernelsnitch/
├── kernelsnitch.h    (450 行, header-only 实现)
├── futex_hash.h      (215 行, Jenkins hash + futex_key 模拟)
├── timeutils.h       (70 行, rdtsc 计时)
└── utils.h           (260 行, 杂项)
```

### 1.2 核心原理

**Phase 1 — find_collisions** (`kernelsnitch.h:300-343`)：

1. 在 user space 拥有一个 futex 地址 `inc_futex[128]`
2. 往这个地址对应的 hash bucket 堆 4096 个等待线程（`__increase(ID, APPENDED_FUTEXES)`），让该 bucket 显著慢
3. 扫 256K 个 user futex 地址，测响应时间 `__measure(addr)`，时间长的 = 同 bucket = collision
4. 得到 `futex_addrs[0..n]`，它们在内核 `futex_hash(addr, current->mm)` 命中同一 bucket

**Phase 2 — bruteforce** (`kernelsnitch.h:197-242`)：

1. 扫 direct map 区域 `[0xffffff8000000000, +64GB]`（`__ARM, VA_BITS=39` 分支）
2. 每 `mm_struct_sz` 字节试一个候选 `mm_struct_candidate`
3. 验证：`futex_hash(futex_addrs[0], candidate) == futex_hash(futex_addrs[i], candidate)` 对所有 i 成立
4. 全部相等 → 找到 `current->mm` 地址

### 1.3 futex_hash 函数（futex_hash.h:207-215）

```c
uint32_t futex_hash(size_t addr, size_t mm) {
    futex_key_t key;
    key.private.mm = (void *)mm;              // ← 第二个参数填入 key.private.mm
    key.private.address = addr & ~KS_PAGE_MASK;
    key.private.offset = addr & KS_PAGE_MASK;
    return __futex_hash(&key, futex_hashsize);
}
```

**关键**：futex_hash 的第二个参数（`mm`）对应内核 `futex_key.private.mm` 字段。在内核 `get_futex_key()` 里，这个字段硬编码为 `current->mm`：

```c
// 内核 get_futex_key() 简化
key->private.mm = current->mm;   // ← 硬编码！
key->private.address = address;
```

**用户态无法替换 `current->mm` 为 `current` (task_struct)**。

---

## 2. 为什么不能扩展为泄 task_struct

### 2.1 futex_hash 第二参数硬编码

kernelsnitch 的 bruteforce 本质是：扫所有可能的 `mm` 候选，验证 `futex_hash(user_addr, candidate)` 与观测到的 hash 一致。

但内核里 futex_key.private.mm 字段填的是 `current->mm`，**不是 `current` 本身**。所以 kernelsnitch 只能扫 `mm_struct` 候选，不能扫 `task_struct` 候选。

### 2.2 候选替代方案

| 方案 | 可行性 | 说明 |
|---|---|---|
| 改 kernelsnitch 扫 task_struct | ❌ | futex_hash 第二参数不可控 |
| 找另一个侧信道扫 task_struct | ? | task_struct 在 direct map，理论可扫；但需全新设计，工程量大 |
| 用 mm_struct 反推 task_struct | ❌ | mm->owner (+0x408) 读取需要任意内核读，死结 |
| 让 kernelsnitch 在 waiter_thread 跑 | ❌ | 泄露的是 waiter_thread 的 mm，不是 task_struct |

**结论**：kernelsnitch 本身**不能**扩展为泄 task_struct。

---

## 3. 重要认知纠正：dijun 走的也是 spray fake cred

### 3.1 文档描述与反汇编证据的矛盾

`help_post.txt:18` 与 `README.md:124` 都说：

> "dijun 的成功路线是直接写 task->real_cred 和 task->cred 等于 init_cred"

但 `RESEARCH_NOTES/rb_insert_analysis.md:220` 反汇编明确：

> "PI 链写入的'值'是 **节点地址**，不是任意值。直接写 init_cred 指针不可行。"

### 3.2 真相

`rb_insert_analysis.md:221-222`：

> "要写 cred 指针，必须让 `task->pi_blocked_on` 指向一个 spray 页里的 fake waiter，这样 rb_insert 写入的'节点地址'就是 spray 页地址 → 写进 cred 槽就是 spray 页地址。
> 即 **正确主线 = 让 pi_blocked_on 指向可控 fake waiter → rb_insert 把 fake waiter 地址写进任意内核指针槽**（cred/real_cred 指向 spray 中伪造 cred）"

**所以 dijun 也是让 cred 指向 spray 页里伪造的 cred，不是内核的 init_cred**。文档里"等于 init_cred"是简化描述（伪造 cred 的内容复制自 init_cred）。

### 3.3 对当前代码的含义

`p1_code_gap.md` 的分析正确：fake_w0+0x28 处需放伪 cred，且 PI 链写入值是 `&fake_w0.pi_tree_entry`（或 `&fake_w0`，取决于分支，见 §4）。

---

## 4. PI 链写入值的精确确认（chain_disasm.txt 复核）

### 4.1 两个写入点

| 行 | 指令 | 写入值 | 写入位置 | 含义 |
|---|---|---|---|---|
| 193 | `ffffffc081052b50: str x25, [x11, x13]` | `x25 = task->pi_blocked_on` (waiter 自身) | `[x11 + x13]` (parent child slot) | 把 waiter 自身地址挂到 parent 的 child 槽 |
| 409 | `ffffffc081052eb0: str x0, [x11, x13]` | `x0 = x25 + 0x28 = &waiter.pi_tree_entry` | `[x11 + x13]` | 把 &pi_tree_entry 挂到 parent child 槽 |

其中 `x25 = task->pi_blocked_on` 指向的 waiter；分两种情况：

- **栈上 waiter（漏洞原态）**: `x25` = 栈地址（不可控）
- **spray fake_w0 (可控化后)**: `x25` = spray 页 fake_w0 地址（固定已知）

### 4.2 行 193 vs 409 走哪条分支

行 193 在 `rt_mutex_enqueue` 路径，行 409 在另一条 enqueue 路径（具体见 chain_disasm.txt 上下文）。**对漏洞利用而言，关键是只要写入值是"fake_w0 起点或 fake_w0+0x28"两者之一，都是 spray 页已知固定地址**。

### 4.3 对 cred 直写的实际含义

让 `task->pi_blocked_on` 指向 spray 页 fake_w0 后：

```
PI 链触发 → rb_insert 把 fake_w0 起点 (或 fake_w0+0x28) 写入 *(target)
```

其中 `target = write_left + 8`，由 `set_pselect_write(target-8, value, 0)` 设置。

- 若 `target = waiter_task + 0x818` → `waiter_task->real_cred = fake_w0` (或 fake_w0+0x28)
- 若 `target = waiter_task + 0x820` → `waiter_task->cred = fake_w0` (或 fake_w0+0x28)

**伪 cred 起点应对齐 fake_w0 起点（或 fake_w0+0x28，取决于走哪条分支）**。需在真机验证。

---

## 5. 真正的 blocker: task_struct 地址未知

### 5.1 为什么 PI 链 target 必须知道 task_struct 地址

PI 链的写入 target 是任意可控的（通过 pselect 覆盖栈上 waiter 的 lock/pi_tree_entry 字段实现）。但要写 `waiter_task->cred`，必须设 `target = waiter_task + 0x820`。

**`waiter_task` 是 waiter_thread 的 task_struct**，由 consumer_thread 调 `sched_setattr(waiter_tid, ...)` 触发 PI 链时被遍历（kernel 内 `find_get_task_by_vpid(waiter_tid)` 拿到）。

**waiter_tid 已知**（main_cred.c:27 `atomic_store(&waiter_tid, tid)`），但 **task_struct 地址未知**。

### 5.2 现有候选全部排除

| 候选 | 状态 | 原因 |
|---|---|---|
| /proc/kcore + /dev/mem 读 task_struct | ❌ | 文件不存在 (CONFIG_PROC_KCORE/DEVMEM=n) |
| 标准通道 (binder/fanotify/inotify/procfs) | ❌ | task_struct_leak_survey.md 全排除 |
| kernelsnitch 扩展 | ❌ | §2 本报告排除 |
| mm->owner 反推 | ❌ | 需任意内核读，死结 |
| init_task + pid 遍历 | ❌ | 需任意内核读，死结 |

### 5.3 项目最大的认知空白

**dijun 在同芯片同内核上成功了**（README 反复强调 dijun 是成功案例）。但**所有现有文档未明说 dijun 怎么拿到 task_struct 地址**。这是项目最大的待解谜题。

可能的猜测（**未验证**）：

1. dijun 可能用了某个我们没注意的侧信道
2. dijun 可能在 futex_wait_requeue_pi 触发后，通过某种方式让 task_struct 落在可预测地址（KASLR=0 + heap spray？）
3. dijun 可能根本不需要 task_struct 地址 —— 走了完全不同的路径（不写 cred，改写别的内核对象）
4. dijun 的 task_struct leak 可能依赖一个我们漏看的设备接口

---

## 6. 下一步推荐

### 6.1 离线可推进

- **深读 dijun 原始 README**：找 dijun 在哪一步泄露 task_struct，或它是否真的绕开了 task_struct leak
- **反汇编 rt_mutex_adjust_prio_chain 全貌**：看 PI 链传播过程中是否有"task_struct 指针被写到某处可读"的环节
- **审 waiter_thread 是否能自定义 sched_setattr 路径**：sched_setattr 包含 task_struct 指针，可能在某 syscall 返回路径泄出

### 6.2 真机可推进

- **测 waiter_thread 调 gettid()/getpid() 后内核返回的 task 地址**：通常被 hash 隐藏，但若有 leak 路径
- **观察 PI 链触发后 waiter_task->pi_waiters 树是否含可读信息**

### 6.3 ★最高杠杆: 重新审 dijun 案例

P3 wall（task_struct leak）是 P1 的真正 blocker。**所有候选人（kernelsnitch、binder、fsnotify、procfs、uhid fops）都已被排除**。下一步要么：

- (A) 找到 dijun 的 task_struct leak 方法（重新深读 dijun readme / 源码）
- (B) 设计全新的侧信道扫 task_struct（工程量大）

**推荐 A 路径**：找到 dijun 的 task_struct leak 方法比从零设计侧信道成本低 100 倍。

---

## 7. 附: 已审计文件清单

- `share-poc-XRing-O1/src/kernelsnitch/kernelsnitch.h` (450 行, 全文阅读)
- `share-poc-XRing-O1/src/kernelsnitch/futex_hash.h` (215 行, 全文阅读)
- `share-poc-XRing-O1/src/kernelsnitch/timeutils.h`
- `share-poc-XRing-O1/src/kernelsnitch/utils.h`
- `RESEARCH_NOTES/rb_insert_analysis.md` (PI 链写入值反汇编报告)
- `analysis/chain_disasm.txt` (PI 链反汇编原始 dump)
- `share-poc-XRing-O1/src/main_cred.c` (run_exploit 主流程，line 27 暴露 waiter_tid)
- `share-poc-XRing-O1/src/util.c` (set_pselect_write / put_fake_fops_table 实现)
- `share-poc-XRing-O1/src/target.h` (task_struct / cred / pi_blocked_on 偏移)
- `share-poc-XRing-O1/docs/p1_code_gap.md` (P1 代码审计)
- `share-poc-XRing-O1/docs/task_struct_leak_survey.md` (标准通道全排除)
