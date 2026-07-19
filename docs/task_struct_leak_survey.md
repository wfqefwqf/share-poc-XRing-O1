# Task_struct Leak 离线反汇编调研报告

**日期**: 2026-07-19
**目标**: 确认在 jinghu (Xiaomi Pad 7 Ultra, XRing O1) 内核 6.6.77-android15-8 上，是否有一条**不依赖 /dev/ashmem** 的路径，能在 **shell 域** 拿到 `current` (或对端) 的 `task_struct` 指针，从而破解 P3 wall (`mm->owner` → task_struct → cred 直写链的内核读断点)。
**方法**: 纯离线反汇编 `vmlinux_extracted`，用 `llvm-nm` + `llvm-objdump -d`，逐路径定性，不做真机实验。

---

## 0. 背景与卡点回顾

| 接口 | shell 域状态 | 备注 |
|---|---|---|
| `/dev/ashmem` open | **SELinux 拒** (errno=13 EACCES) | DAC 666 但 MAC 拦；configfs_read_once 整条读链饿死 |
| `/proc/kcore` | **文件不存在** | `CONFIG_PROC_KCORE` 未开 |
| `/dev/mem` | **文件不存在** | `CONFIG_DEVMEM` 未开（与 `STRICT_DEVMEM` 无关） |
| `/proc/kallsyms` 读 | **SELinux/paranoid 拒** | shell 域看不到 |
| `perf_event_open` | **SELinux 拒** | 不可用 |
| `/config` (configfs) | **Permission denied** | 挂载但 shell 域无法访问 |

唯一已知可用通道：`kernelsnitch` (futex hash 侧信道) 已真机泄出 `mm_struct` (例如 `0xffffff80186c5500`)，但 `mm->owner` (+0x408) 这 8 字节读不出。

**目标**：找一条 shell 域合法、不依赖 ashmem 的路径，读出任意内核指针 (尤其是 task_struct 或 mm->owner)。

---

## 1. 调查方法

1. `llvm-nm vmlinux_extracted` 枚举 binder / fsnotify / fanotify / inotify / procfs 相关符号
2. `llvm-objdump -d --start-address=...` 反汇编关键函数
3. 检查 copy_to_user 的源是否含 raw 内核指针
4. 检查 SELinux / kptr_restrict / ptrace_may_access 是否拦截
5. 对每条路径给出定性结论

---

## 2. Binder 路径调查

### 2.1 关键符号地址

```
binder_fops           = 0xffffffc0812d18f0
binder_ioctl          = 0xffffffc080cad96c
binder_open           = 0xffffffc080cae594
binder_release        = 0xffffffc080caea7c
binder_mmap           = 0xffffffc080cae474
binder_poll           = 0xffffffc080cad7fc
binder_ioctl_write_read        = 0xffffffc080cb242c
binder_ioctl_get_node_debug_info    = 0xffffffc080cb4b9c
binder_ioctl_get_node_info_for_ref  = 0xffffffc080cb4aac
binder_ioctl_get_freezer_info       = 0xffffffc080cb4f4c
binder_ioctl_get_extended_error     = (调用点在 ioctl 中段)
binder_thread_read           = 0xffffffc080cb5170
```

### 2.2 binder_fops 表完整字段

```
+0x00 owner           = 0
+0x08 llseek          = 0
+0x10 read            = 0
+0x18 write           = 0
+0x20 read_iter       = 0
+0x28 write_iter      = 0
+0x30 iopoll          = 0
+0x38 iterate_shared  = 0
+0x40 poll            = 0xffffffc080cad7fc (binder_poll)
+0x48 unlocked_ioctl  = 0xffffffc080cad96c (binder_ioctl)
+0x50 compat_ioctl    = 0
+0x58 mmap            = 0xffffffc080cae474 (binder_mmap)
+0x60 open            = 0xffffffc080cae594 (binder_open)
+0x68 flush           = 0
+0x70 release         = 0xffffffc080caea7c (binder_release)
```

### 2.3 ioctl 命令分派

| cmd | 含义 | 处理函数 | 回填 user 大小 |
|---|---|---|---|
| `0xc0306201` | BINDER_WRITE_READ | `binder_ioctl_write_read` | 复杂 |
| `0xc0046209` | BINDER_SET_MAX_THREADS | inline 写 proc->max_threads | 0 |
| `0xc00c620e` | BINDER_ENABLE_ONEWAY_SPAM_DETECTION | inline flag | 0 |
| `0xc018620a` | BINDER_GET_NODE_DEBUG_INFO | `binder_ioctl_get_node_debug_info` | 24 字节 |
| `0xc018620b` | (freeze info?) | inline | 4 字节 |
| `0xc018620c` | BINDER_GET_NODE_INFO_FOR_REF | `binder_ioctl_get_node_info_for_ref` | 24 字节 |
| `0x400c620e` | (freeze) | inline | 4 字节 |
| `0x4018620d` | BINDER_GET_FREEZER_INFO (?) | `binder_ioctl_get_freezer_info` | 12 字节 |
| `0xc00c620f` | BINDER_GET_EXTENDED_ERROR | `binder_ioctl_get_extended_error` | 12 字节 |

### 2.4 `binder_ioctl_get_node_debug_info` 反汇编关键路径

```
0xffffffc080cb4c10:  str x8, [x19]           ; x8 = [x0, #0x38] = binder_node.ptr
                                             ; 写回 user struct +0x00
```

**重要发现**：这个 ioctl **确实把 `binder_node.ptr` (raw 内核指针) 写回用户态 24 字节结构** 的 +0x00 字段。

但：
- `binder_node.ptr` 是 binder_node 内部成员（用户态 bookkeeping 用的 desc hash），**不是 task_struct 指针**
- 它指向 `binder_node` 结构本身在内核堆的位置（受 `kptr_restrict` 影响？需真机验证）
- 即便拿到 `binder_node*`，也无法进一步读 `binder_node->proc->tsk`（仍需任意内核读）

### 2.5 `binder_ioctl_get_node_info_for_ref` 反汇编

只回填 int 字段（strong_ref / weak_ref / 内部 id），**无 raw 内核指针**。

### 2.6 `binder_thread_read` (BR_TRANSACTION 路径)

回填 `binder_transaction_data` 结构，含 sender `pid` / `euid`，但**都是 32-bit 整数**（不是指针）。`BR_TRANSACTION_SECCTX` 额外带 secctx 字符串，但仍无 raw 内核指针。

### 2.7 Binder 路线结论

| 命令 | 泄露 raw 内核指针? | 是 task_struct? | 实用性 |
|---|---|---|---|
| BINDER_GET_NODE_DEBUG_INFO | ✅ 泄 `binder_node.ptr` | ❌ 不是 | 仅泄 binder_node 指针，无法链到 task |
| BINDER_GET_NODE_INFO_FOR_REF | ❌ | ❌ | 无用 |
| BINDER_WRITE_READ (BR_TRANSACTION) | ❌ (只 32-bit pid/euid) | ❌ | 无用 |

**Binder 不是 task_struct 泄露银弹**。理论上 `binder_node.ptr` 泄露 + 复用 PI 链做受限读，可以一步步走到 `node->proc->tsk`，但每一步都需要一次 PI 链触发（成本极高，且每次写入值都是节点地址非任意值）。

**SELinux 注意**：shell 域对 `/dev/binder` 的 ioctl 是否允许需真机验证；Android 默认 `binder_ioctl` 对所有 domain 开放，但 `BINDER_GET_NODE_DEBUG_INFO` 等命令可能受 `binder_use` 类约束。

---

## 3. Fsnotify / Fanotify 路径调查

### 3.1 符号枚举结果

```
fanotify_* 符号数量 = 0   ←  关键
inotify_* 完整符号集都存在
```

### 3.2 结论：fanotify 在 jinghu 内核**完全未编入**

`CONFIG_FANOTIFY` 未开。`FAN_CLASS_NOTIF` / `FAN_CLASS_CONTENT` / `FAN_CLASS_PRE_CONTENT` 全不可用。`fanotify_init` / `fanotify_mark` syscall 即使存在也是 stub。

这与 Android vendor 内核的常见配置一致 —— fanotify 主要给杀进程的 daemon (lmkd, traced) 用，HyperOS 不开。

### 3.3 inotify 路径

```
inotify_fops                = 0xffffffc08114c780
inotify_read                = 0xffffffc0804275fc
inotify_poll                = 0xffffffc08042766c
inotify_release             = 0xffffffc080427790
inotify_ioctl               = 0xffffffc0804271a4
inotify_show_fdinfo         = 0xffffffc080427838
inotify_handle_inode_event  = 0xffffffc080426834
inotify_ignored             = 0xffffffc0804264d8
inotify_find_inode          = 0xffffffc0804265f4
inotify_add_watch           = 0xffffffc080427070
inotify_rm_watch            = 0xffffffc080426c48
```

### 3.4 `inotify_read` 反汇编关键路径

copy_to_user 的源是 `struct inotify_event`：

```c
struct inotify_event {
    __s32 wd;           // +0x00  watch descriptor
    __u32 mask;         // +0x04  event mask
    __u32 cookie;       // +0x08
    __u32 len;          // +0x0c  name length
    char  name[];       // +0x10  可变长 name
};
```

**全是 32-bit 整数 + 文件名 string，没有任何 raw 内核指针**。`wd` 是用户态可见的 watch descriptor (int)，不是内核指针。

### 3.5 `inotify_handle_inode_event` 反汇编

构造 `inotify_event` 时只填 `wd/mask/cookie/name`，**不引用 task_struct**。

### 3.6 Inotify/Fsnotify 路线结论

- fanotify 不可用（未编入）
- inotify 可用，但 event 结构无内核指针
- **无法用于 task_struct 泄露**

---

## 4. Procfs 替代路径调查

### 4.1 `/proc/[pid]/wchan` (`proc_pid_wchan` @ 0xffffffc0804709b8)

反汇编关键路径：

```
0xffffffc0804709f8:  mov w1, #0x9; bl ptrace_may_access
0xffffffc080470a08:  bl get_wchan              ; 取 task 的 wchan (内核栈帧指针)
                  ; (随后) lookup_symbol_name(addr) → 符号名字符串
                  ; 若 ptrace_may_access 拒或 lookup 失败 → 填 '0'
```

**关键性质**：
- 返回的是**符号名字符串**（不是 raw 地址），符合 `%pK` / `kptr_restrict=1` 默认行为
- 真机实测：`/proc/self/wchan` 在 shell 域返回 `0`（被 kptr_restrict 拦）
- **不泄内核指针**

### 4.2 `/proc/[pid]/statm` (`proc_pid_statm` @ 0xffffffc08047811c)

全 numeric stat：size / resident / shared / text / lib / data / dt。**完全无指针**。

### 4.3 `/proc/[pid]/status` (`proc_pid_status` @ 0xffffffc080476ac0)

反汇编：从 `task+0x860` 等读 `task->mm` / `task->fs` 等 raw 指针，但全部通过 `seq_printf` 转 ASCII 数字（pid/ppid/uid/gid 等）。

**Android 内核默认 `kptr_restrict=1`**，所有 `%pK` 在 shell 域输出 `\0` 或 `(null)`。**不泄内核指针**。

### 4.4 `simple_attr_read` (@ 0xffffffc08040056c)

debugfs 常用 helper。反汇编：把 `attr->val` (unsigned long) 用 `scnprintf("%llu\n")` 转字符串写回。**不是 raw 指针**。

### 4.5 Procfs 路线结论

| 路径 | 返回内容 | 含 raw 指针? |
|---|---|---|
| `/proc/[pid]/wchan` | 符号名 or `'0'` (kptr_restrict 拦) | ❌ |
| `/proc/[pid]/statm` | 数字 stat | ❌ |
| `/proc/[pid]/status` | 数字 + 字符串 | ❌ |
| `/proc/[pid]/maps` | hex 地址（user space） | ❌（用户地址非内核） |
| `simple_attr_read` (debugfs) | `%llu` 字符串 | ❌ |

**Procfs 无可用泄露路径**。

---

## 5. 总结论

### 5.1 四条候选路径全部排除

| 路径 | 状态 | 原因 |
|---|---|---|
| **binder ioctl** | ❌ 不可用 | BINDER_GET_NODE_DEBUG_INFO 泄 binder_node.ptr 但非 task_struct；其余命令无 raw 指针 |
| **fanotify** | ❌ 不可用 | CONFIG_FANOTIFY 未编入 |
| **inotify** | ❌ 不可用 | event 结构全 int + 字符串，无指针 |
| **procfs** | ❌ 不可用 | kptr_restrict=1 + seq_printf 数字转义，shell 域看不到 raw 指针 |

### 5.2 为什么所有标准通道都被封堵

这正是现代 Android 内核的设计意图：
1. **`kptr_restrict=1`**：所有 `%pK` 在 unprivileged 域输出 `(null)` / `0`
2. **SELinux untrusted_app / shell 域**：拒绝 `open /dev/ashmem`、`perf_event_open`、读 `/proc/kallsyms`、`configfs` 访问
3. **`CONFIG_DEVMEM=n` / `CONFIG_PROC_KCORE=n`**：连 root 都没有 `/dev/mem` 与 `/proc/kcore`
4. **fanotify 未编入**：移除 fsnotify user-space 通道
5. **binder 接口设计**：用户态只可见 desc/handle，不可见 raw 内核指针（BINDER_GET_NODE_DEBUG_INFO 是个意外但泄的不是 task_struct）

**结论**：在没有漏洞原语的前提下，shell 域无法拿到 task_struct 指针。这印证了安全研究界的核心共识 —— **必须用漏洞本身做泄露**，不能依赖系统调用接口。

### 5.3 唯一可行的方向：用 PI 链原语做泄露

既然标准通道全封，唯一通路是把 PI 链写入**可控化**：

```
当前: PI 链写 &waiter.pi_tree_entry (栈地址, 不可控)
目标: PI 链写 &fake_w0.pi_tree_entry (spray 页固定地址, 可控)
      ↓
      fake_w0 页内伪造一份 cred (uid/gid/euid = 0)
      task->cred / task->real_cred 指向 fake_w0
      ↓
      = root
```

这条路线不需要"任意内核读 mm->owner"，**直接绕开 P3 wall**。

### 5.4 关于"绕过 P3"的可行性

cred 直写路线明确走的是这条：
1. `kernelsnitch` 泄 mm_struct（已通）
2. PI 链可控化 → 写 `task->cred = &fake_w0.pi_tree_entry`
3. **不需要** 读 mm->owner

jinghu 在 XRing O1 上 KASLR=0、PAN 软件失效，因此：
- 所有内核地址已知（KASLR=0）
- 写 task->cred 不被 PAN 拦（软件 PAN 失效）
- **不需要任意内核读**，因为 task_struct 地址可以通过 init_task + pid 链推算，或者通过 cred 直写后直接 `setuid(0)` 验证

---

## 6. 下一步建议

### 6.1 优先级 P1：PI 链可控化（核心突破点）

让 `task->pi_blocked_on` 指向 spray 页 `fake_w0`，而非栈上 waiter。这是 README/RESEARCH_NOTES 一直强调的主线，**不需要任意内核读**。

具体动作：
1. 审 `main_cred.c` 当前 walk 框架，确认 `pi_blocked_on` 是否已被改指向 spray
2. 在 spray 页 `fake_w0` 内伪造完整 `struct cred` (uid/gid/euid/suid/fsuid/egid/sgid/fsgid/cap_* = 0)
3. PI 链触发 → `task->cred = &fake_w0.pi_tree_entry` (其实指向 fake_w0 内的伪 cred)
4. `setuid(0); setgid(0)` 验证

### 6.2 优先级 P2：uhid fops 劫持（备用，仍受 KCFI 限制）

见 `uhid_gadget_survey.md`。KCFI 拦跨原型 helper，目前 fake fops 表只能全填 uhid 原版函数指针 → 不能用作任意读银弹。但可作为 PI 链写入有效的**验证手段**（劫持后 open("/dev/uhid") 行为异常 = 写入成功）。

### 6.3 优先级 P3：mm->owner 读取（暂搁置）

所有标准通道已确认不可用，**只能等 P1 完成后用 root 身份读**（root 后 `/proc/kallsyms` 等都开放）。P1 之前不要在这条路上继续耗时间。

### 6.4 已废弃的尝试（勿再走）

- ❌ "装 debuggable APK 跑 untrusted_app 域绕 ashmem"
- ❌ "/dev/mem fallback"（文件不存在）
- ❌ "configfs 代码 bug"（代码正确，blocker 是 SELinux）
- ❌ "binder 泄 task_struct"（本报告 §2 已排除）
- ❌ "fanotify 路线"（未编入）
- ❌ "inotify 路线"（无指针）
- ❌ "procfs wchan/statm/status 路线"（kptr_restrict 拦）

---

## 7. 反汇编证据索引

所有反汇编命令均可复现：

```bash
NM="d:/CVE-2026-43499/android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
OBJDUMP="d:/CVE-2026-43499/android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objdump.exe"

# binder
"$OBJDUMP" -d --start-address=0xffffffc080cad96c --stop-address=0xffffffc080cae400 vmlinux_extracted  # binder_ioctl
"$OBJDUMP" -d --start-address=0xffffffc080cb4b9c --stop-address=0xffffffc080cb4d00 vmlinux_extracted  # get_node_debug_info
"$OBJDUMP" -d --start-address=0xffffffc080cb4aac --stop-address=0xffffffc080cb4b9c vmlinux_extracted  # get_node_info_for_ref
"$OBJDUMP" -d --start-address=0xffffffc080cb5170 --stop-address=0xffffffc080cb5700 vmlinux_extracted  # binder_thread_read

# inotify
"$OBJDUMP" -d --start-address=0xffffffc0804275fc --stop-address=0xffffffc080427800 vmlinux_extracted  # inotify_read
"$OBJDUMP" -d --start-address=0xffffffc080426834 --stop-address=0xffffffc080426b60 vmlinux_extracted  # inotify_handle_inode_event

# procfs
"$OBJDUMP" -d --start-address=0xffffffc0804709b8 --stop-address=0xffffffc080470a70 vmlinux_extracted  # proc_pid_wchan
"$OBJDUMP" -d --start-address=0xffffffc08047811c --stop-address=0xffffffc080478290 vmlinux_extracted  # proc_pid_statm
"$OBJDUMP" -d --start-address=0xffffffc080476ac0 --stop-address=0xffffffc080476c80 vmlinux_extracted  # proc_pid_status

# simple_attr
"$OBJDUMP" -d --start-address=0xffffffc08040056c --stop-address=0xffffffc0804006c0 vmlinux_extracted  # simple_attr_read
```

---

## 8. 总结一句话

**所有 shell 域标准通道都拿不到 task_struct 指针** —— binder 泄的是 binder_node.ptr 不是 task；fanotify 没编入；inotify event 全 int；procfs 被 kptr_restrict 封。**唯一的出路是回归 PI 链可控化，让写入值落在 spray 页 fake_w0，直接走 cred 直写，完全绕开 mm->owner 那一步内核读**。
