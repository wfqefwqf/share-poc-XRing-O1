# rb_insert / PI 链写入路径 逆向分析报告

**目标内核**: Xiaomi Pad 7 Ultra (jinghu), XRing O1, 内核 6.6.77-android15-8-g5770c661275f
**工具链**: android-ndk-r27d (llvm-objdump / llvm-nm)
**二进制**: vmlinux_extracted (ELF64 aarch64, not stripped, 41.6 MB)
**日期**: 2026-07-18

---

## 0. 关键结论速览

| 项目 | 结论 |
|------|------|
| rb_insert 是否有独立符号 | **否**。标准 `rb_insert` 内核中以 `__rb_insert_augmented` 形式存在 (0xffffffc08102dd40)，PI 树插入走 `rb_insert_color` (0xffffffc08102d91c) |
| PI 树节点连接字段 | waiter 的 **`pi_tree_entry` 在 +0x28**（不是 tree_entry +0x00） |
| 写入目标地址 | rb_insert_color 写入的是 **被插入节点 pi_tree_entry 的地址** (`&waiter->pi_tree_entry`)，不是任意值 |
| 漏洞触发源头 | `task_blocks_on_rt_mutex` @ 0xffffffc081051d40: `str x21, [x20, #0x938]` → **task->pi_blocked_on = waiter** |
| cleanup 跳过 remove_waiter | `rt_mutex_cleanup_proxy_lock` 当 `owner==current` 时 (X20==SP_EL0) 不调 remove_waiter，pi_blocked_on 残留指向栈 waiter |
| 栈覆盖点 | `core_sys_select` 用 `sub sp, sp, #0x1f0`，do_select 被调用时复用同一栈区，pselect 保存寄存器覆盖 waiter 字段 |

---

## 1. rb_insert_color (0xffffffc08102d91c — 0xffffffc08102da44)

**作用**: 给定已挂入树（但颜色未定）的节点，做红黑树再平衡（旋转 + 重新着色）。
**关键**: 它 **不负责把节点链入树**，只负责再平衡。链入发生在调用者（task_blocks / try_to_take / adjust_prio_chain）里的 `stp xN, xzr, [xNODE, #0x28]` 那一步。

关键写入指令（左旋/右旋路径里）:
```
ffffffc08102d9b0: f9400a0a  ldr x10, [x0, #0x10]      // 读右子
ffffffc08102d9b4: f900052a  str x10, [x9, #0x8]       // 改左子的右指针
ffffffc08102d9b8: f9000809  str x9, [x0, #0x10]       // 反向链
ffffffc08102d9d0: f900090a  str x10, [x8, #0x10]      // 父节点的子指针更新
ffffffc08102d9d4: f9000408  str x8, [x0, #0x8]        // x8 是新父
ffffffc08102d9e4: f9000020  str x0, [x1]              // ★ x1 = 新父的某子槽位（由 csel 选定），x0 是节点地址
```

注意 `ffffffc08102da08: str x0, [x1]` 和 `ffffffc08102d9e4`：x0 是 **节点自身地址**（= `&node->pi_tree_entry`），x1 是 **父节点 rb_left/rb_right 槽位** 或根指针。
→ rb_insert_color 写入的"值"永远是一个 **rb_node 的地址（节点自身 pi_tree_entry 地址）**，写入位置是父节点/根的指针槽或节点自身的左右指针。

**对利用的含义**: 我们能在 PI 链触发时让内核"写一个节点地址到某个内核指针槽"。如果我们能控制那个"节点"的位置（spray 页），就能把 spray 页地址写进任意内核指针槽——这就是 cred 直写 / fops 重定向的原语本质。

---

## 2. __rb_insert_augmented (0xffffffc08102dd40 — 0xffffffc08102df00)

**作用**: 通用 rb 插入（带 augment 回调）。内核标准 `rb_insert` 即此函数（符号未导出为 rb_insert，但这是实现）。
**调用约定**: x0=新节点, x1=树根指针(rb_root*), x2=augment 回调函数指针
**关键链接逻辑**（找到插入槽后）:
```
ffffffc08102de00: aa1603e1  mov x1, x22          // x22 = 父节点
ffffffc08102de04: f9000016  str x22, [x0]        // node->rb_parent_color = parent
ffffffc08102de28: f9000a88  str x8, [x20, #0x10] // parent->rb_right = node
ffffffc08102de2c: f90006d4  str x20, [x22, #0x8] // node->rb_left = 旧子
ffffffc08102de48: f9000296  str x22, [x20]       // 反向
ffffffc08102de60: mov x0, x20
ffffffc08102de68: f90002b6  str x22, [x21]       // ★ 根指针 = node  (x21 是 rb_root 地址)
```
结尾 `bl x19`（调用 augment 回调，典型是 `rb_add_cached_augmented` 用的 augment 函数）。
**关键**: `str x22, [x21]` 把 **节点地址写进 rb_root 的 rb_node 指针**（x21 是树根，如 task->pi_waiters 或 lock->waiters）。

→ 同样印证：**rb 插入写入的"值" = 节点地址（&node->pi_tree_entry）**。

---

## 3. rb_erase / rb_erase_cached (0xffffffc08102da44 / 0xffffffc080128074)

删除路径。rb_erase_cached 只是先 `rb_next` 更新 cache 再调 rb_erase。
**重要**: rb_erase 把被删节点的父/子槽位改成"替身节点地址"或 NULL（用 `str xZ, [xPARENT, #0xX]`）。
删除时若节点是树中节点，会写父节点的左右指针为替身地址。利用上我们也可以利用删除路径触发一次"写替身地址"。

---

## 4. task_blocks_on_rt_mutex (0xffffffc081051c08 — 0xffffffc081052058)

**这是 PI 链构建的核心，也是漏洞源头函数。**

### 4.1 把 waiter 插入 lock 的 waiter 树
```
ffffffc081051c64: stp x20, x19, [x21, #0x50]      // waiter->tree_entry 链表 + task 反指 (x21=waiter)
ffffffc081051c80: str w8, [x21, #0x18]            // waiter->prio = task->prio
ffffffc081051c84: mov x1, x19                     // x1 = &lock->waiters (rb_root)
ffffffc081051c88: ldr x9, [x20, #0x298]           // task->dl (deadline)
...
ffffffc081051d04: stp x12, xzr, [x21]             // ★ waiter->rb_node.rb_parent_color = x12(parent); waiter->rb_left = NULL
ffffffc081051d08: str xzr, [x21, #0x10]           // waiter->rb_right = NULL
ffffffc081051d0c: str x21, [x12, x15]             // ★ 父节点->child_slot = waiter  (x15 = 8 或 16 偏移)
ffffffc081051d30: str x21, [x19, #0x10]           // lock->waiters.rb_node = waiter (若树空，根是 waiter)
ffffffc081051d34: mov x0, x21
ffffffc081051d38: bl rb_insert_color              // 上色再平衡
```

### 4.2 ★ 漏洞源头：task->pi_blocked_on = waiter
```
ffffffc081051d40: str x21, [x20, #0x938]          // task->pi_blocked_on = waiter (x20=task, +0x938=pi_blocked_on)
```
**这是整个漏洞的"毒针"**: 把栈上 waiter 地址写进 `task->pi_blocked_on`。只要 cleanup_proxy_lock 走了"跳过 remove_waiter"分支，这个指针就永远指向栈上（已释放/复用的）waiter。

### 4.3 把 waiter 的 pi_tree_entry 插入 owner 的 pi_waiters 树
```
ffffffc081051e30: ldr x13, [x22, #0x920]          // owner->pi_waiters.rb_node (x22=owner, +0x920=pi_waiters 根)
ffffffc081051e34: add x0, x21, #0x28              // ★ x0 = &waiter->pi_tree_entry (+0x28!)
ffffffc081051e98: stp x11, xzr, [x21, #0x28]      // ★ waiter->pi_tree_entry.rb_parent_color = x11; pi_tree_entry.rb_left=NULL
ffffffc081051eac: stp xzr, xzr, [x0, #0x8]        // pi_tree_entry.rb_right = NULL
ffffffc081051eb8: str x0, [x22, #0x928]           // owner->pi_waiters.rb_leftmost = &waiter->pi_tree_entry
ffffffc081051ec0: bl rb_insert_color              // 上色 (x0 = &waiter->pi_tree_entry)
```
**确认**: PI 树（task->pi_waiters）用的节点字段是 **waiter 的 +0x28（pi_tree_entry）**。这与项目记忆一致。

### 4.4 后续 PI 传播
```
ffffffc081051ed0: ldr x1, [x8, #0x28]             // 读 waiter->pi_tree_entry (x8 = owner->pi_waiters.rb_leftmost)
... rt_mutex_setprio(owner, waiter) ...           // 提升 owner 优先级
```
→ setprio 之后会再次走进 `rt_mutex_adjust_prio_chain`，形成递归 PI 传播链。

---

## 5. try_to_take_rt_mutex (0xffffffc081051820 — 0xffffffc081051c08)

当 current 成功取锁时，把"栈顶 waiter"的 pi_tree_entry 顺手插入 **current（新 owner）的 pi_waiters**:
```
ffffffc081051a38: stp x12, xzr, [x8, #0x28]       // ★ waiter->pi_tree_entry.rb_parent_color = x12 (x8 = waiter)
ffffffc081051a3c: str xzr, [x8, #0x38]            // pi_tree_entry.rb_right = NULL
ffffffc081051a40: str x0, [x12, x15]              // 父->child = &waiter->pi_tree_entry
ffffffc081051a58: str x0, [x20, #0x928]           // current->pi_waiters.rb_leftmost = &waiter->pi_tree_entry
ffffffc081051a5c: bl rb_insert_color              // 上色 (x0 = &waiter->pi_tree_entry)
```
**注意 x20 = current（取锁者）**，+0x928 是 pi_waiters.rb_leftmost，+0x920 是 pi_waiters.rb_node。

→ 取锁路径也会"写 &waiter->pi_tree_entry 到 current 的 pi_waiters 指针槽"。

---

## 6. rt_mutex_cleanup_proxy_lock (0xffffffc081052634 — 0xffffffc081052868)

**漏洞函数本身。关键分支**:
```
ffffffc081052654: mrs x20, SP_EL0                 // x20 = current (SP_EL0 指向 current task)
ffffffc081052658: mov x0, x19 (lock)
ffffffc08105265c: mov x1, x20 (current)
ffffffc081052660: mov x2, x21 (waiter)
ffffffc081052664: bl try_to_take_rt_mutex
ffffffc081052668: ldr x8, [x19, #0x18]            // lock->owner
ffffffc08105266c: and x22, x8, #~1               // owner = lock->owner & ~1
ffffffc081052670: cmp x22, x20                    // owner == current ?
ffffffc081052674: b.eq +0x50                      // ★ 若 owner==current，跳过 remove_waiter！
ffffffc081052678: mov x0, x19
ffffffc08105267c: mov x1, x21
ffffffc081052680: bl remove_waiter                // 否则正常 remove_waiter (清理 pi_blocked_on)
```
**漏洞条件**: 当 `try_to_take_rt_mutex` 成功让 **current 成为 lock 的 owner**（owner==current），则 **不调用 remove_waiter**，于是 `task->pi_blocked_on` 仍指向栈上 waiter（已被 cleanup 函数返回后的栈复用覆盖）。

→ 这正是 CVE-2026-43499 (GhostLock) 的利用前提：futex_requeue_pi / pselect 序列构造出"owner==current 但 waiter 仍在 pi_blocked_on"的悬挂指针。

---

## 7. remove_waiter (0xffffffc0810520f0 — 0xffffffc081052364)

**正常清理路径**（被跳过后不执行）:
```
ffffffc081052178: str xzr, [x20, #0x938]          // ★ task->pi_blocked_on = NULL  (清理！)
ffffffc0810521c4: bl rb_erase                     // 从 lock->waiters 树删 waiter
... 从 owner->pi_waiters 也删 waiter->pi_tree_entry ...
ffffffc081052278: bl rb_insert_color              // 再平衡
```
**关键**: remove_waiter 第一行就是把 `task->pi_blocked_on` 清零。跳过它 = pi_blocked_on 残留。

---

## 8. rt_mutex_adjust_prio_chain (chain_disasm.txt, 0xffffffc081052868)

PI 传播主递归。内部遍历 `task->pi_blocked_on` 指向的 waiter，沿 waiter->lock->owner 一路向上。
**关键插入点** (改动 prio 后重新挂入 waiter 树):
```
ffffffc081052b48: stp x11, xzr, [x25]             // waiter->rb_parent_color = x11
ffffffc081052b50: str xzr, [x25, #0x10]
ffffffc081052b54: str x25, [x11, x13]             // 父->child = waiter
ffffffc081052b68: str x25, [x24, #0x10]           // 另一处写 waiter 地址
ffffffc081052b70: bl rb_insert_color
```
以及 pi_waiters 树的插入:
```
ffffffc081052ea8: stp x11, xzr, [x25, #0x28]       // ★ waiter->pi_tree_entry 链入 owner->pi_waiters
ffffffc081052eb0: str x0, [x11, x13]
ffffffc081052edc: str x0, [x19, #0x928]            // task->pi_waiters.rb_leftmost = &waiter->pi_tree_entry
ffffffc081052ee0: bl rb_insert_color
```
→ 整条递归链里，每次"写的值"都是 **waiter 节点地址（&waiter->pi_tree_entry 或 &waiter 本身）**。

---

## 9. core_sys_select 栈布局 (0xffffffc0803dfdf4)

**栈分配**:
```
ffffffc0803dfdf8: sub sp, sp, #0x1f0              // 496 字节栈帧
ffffffc0803dfe14: add x29, sp, #0x190             // 帧基
```
寄存器保存区: `stp x29,x30,[sp,#0x190]` ... `stp x20,x19,[sp,#0x1e0]`。
`sp+0x190` 到 `sp+0x1e0` 是寄存器（x19~x30）的保存槽。

**关键**: do_select 在 `core_sys_select` 帧内被调用（`bl do_select` @ 0xffffffc0803e00a0），do_select 自身又分配栈（sub sp,#...），其局部变量（含用于 poll 的 waiter 临时结构等）会落在 **sp+0x80 ~ sp+0x190** 区间。

当 pselect 第二次进入、core_sys_select 再次执行时，如果前一次的栈 waiter 恰好在这个区间，且 `task->pi_blocked_on` 仍指向旧地址 → **新 core_sys_select 保存寄存器 / memset 会覆盖旧 waiter 的 prio/deadline/task/lock 字段**。

→ 这正是项目记忆里说的"pselect 复用同一栈区域，core_sys_select 保存寄存器覆盖 waiter 字段，通过 PI 链实现内核任意地址写入"的硬件基础。

---

## 10. 对利用原语的最终判定（纠正项目记忆）

| 原语 | 实际写入内容 | 写入位置 | 可控性 |
|------|------------|---------|--------|
| rb_insert_color / __rb_insert_augmented | **被插入节点地址 (&node->pi_tree_entry)** | 父节点子槽 / 树根 / 节点自身左右指针 | 节点地址 = spray 页固定地址（若 pi_blocked_on 指向 spray fake waiter） |
| cleanup 跳过 remove_waiter | 不写（残留旧值）| — | 残留 pi_blocked_on = 旧栈地址 |
| 栈覆盖 | 寄存器值 / 0 | sp+0x80~0x190 | 攻击者可通过 pselect 参数精确控制 |

**结论**:
1. PI 链写入的"值"是 **节点地址**，不是任意值。直接写 init_cred 指针不可行。
2. 要写 cred 指针，必须让 `task->pi_blocked_on` 指向一个 **spray 页里的 fake waiter**，这样 rb_insert 写入的"节点地址"就是 spray 页地址 → 写进 cred 槽就是 spray 页地址。
3. 即 **正确主线 = 让 pi_blocked_on 指向可控 fake waiter → rb_insert 把 fake waiter 地址写进任意内核指针槽**（cred/real_cred 指向 spray 中伪造 cred，或 uhid fops 重定向）。

---

## 11. 反汇编产物清单 (RESEARCH_NOTES/disasm/)

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

---

## 12. 待办（下一步）

- [ ] 确认 spray fake waiter 布局：fake waiter 放在 spray 页何处，pi_blocked_on 如何指向它（需要 pselect 栈 spray 或 mmap 固定地址 spray）
- [ ] 确认 cred 直写路径：rb_insert 把 fake waiter 地址写入 `task->cred`/`real_cred` 槽（需确认 task_struct 中 cred 偏移与此写入槽匹配）
- [ ] uhid fops 重定向路线：rb_insert 把 fake waiter 地址写入 `uhid_misc.fops` 槽（0xffffffc082234fd0 附近），open(/dev/uhid) 触发劫持
- [ ] 验证 PAN/CFI：XRing O1 上软件 PAN 失效已确认；CFI/PAC 对 fake fops 函数指针的约束需进一步确认
