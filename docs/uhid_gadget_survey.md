# uhid fops 劫持 Gadget 枚举报告 (P2 离线推进)

> 产物: 不依赖真机的 uhid 反汇编枚举,用于 P2 「uhid fops 重定向 → 任意内核 Rw」阶段
> 日期: 2026-07-19
> 工具: llvm-objdump + llvm-nm (android-ndk-r27d) + vmlinux_extracted
> 内核: 6.6.77-android15-8-6.6.77, target=jinghu (Xiaomi Pad 7 Ultra, XRing O1), KASLR=0 真机确认

---

## 0. TL;DR

- **uhid 不走 ioctl**(`uhid_fops.unlocked_ioctl = 0`)。控制命令(UHID_CREATE2 / UHID_DESTROY / UHID_INPUT2 …)经 `.write` 进来,事件回报经 `.read` 出去。
- **`uhid_misc.fops` 槽精确地址 = `0xffffffc082234fd0`**(下文有反汇编证据)。README/旧注释里出现的 `0xffffffc082234fc8` 是 `uhid_misc.name` 槽,不是 fops —— 之前所有引用都是笔误,本次已纠正。
- **`uhid_char_open` 在 shell 域可 open**(`fd=3` 真机已验证,与 ashmem 不同);open 后 `file->private_data` 被赋值为 `kzalloc(sizeof(uhid_device), GFP_KERNEL)` 的指针,因此后续 `.read`/`.write`/`.release` 的 handler 都期望 `private_data` 为合法 `uhid_device`。
- **`uhid_char_read` 是内核→用户的 copy_to_user 路径**,源是 uhid_device ring buffer 内部事件,不是任意内核地址 → 不能直接作为任意内核读 gadget;但**若我们劫持 `uhid_misc.fops` 同时保留 `.read = uhid_char_read`,uhid fd 行为正常**,不会 panic。
- **通用任意内核读 gadget**:已枚举出
  - `copy_from_kernel_nofault` @ `0xffffffc0802d720c`(no-fault 路径)
  - `bin2hex` @ `0xffffffc08070bec4`(纯 byte→hex,可二段链)
  - `simple_read_from_buffer` @ `0xffffffc0804000b0`
  - `memory_read_from_buffer` @ `0xffffffc0804002c8`
  
  但这些都不是「被一个 fops 项直接调、且能控制 src」的现成 gadget —— KCFI(类型签名 hash)与 PAC 都会拦掉「指针直接指向 helper」。**真正可走的 gadget 表必须用语义匹配的现有 fops 函数**(详见 §4)。

---

## 1. 符号地址一览(llvm-nm 直接验证,KASLR=0)

| 符号 | 地址 | 用途 |
|---|---|---|
| `uhid_misc` | `0xffffffc082234fc0` | `struct miscdevice` 起点(`.rodata`) |
| `uhid_misc.fops`槽 | **`0xffffffc082234fd0`** | **PI 链要写入的目标地址(+0x10)** |
| `uhid_fops` | `0xffffffc0812bb120` | `struct file_operations`(`.rodata` const) |
| `uhid_char_open` | `0xffffffc080c1b86c` | `.open` handler |
| `uhid_char_read` | `0xffffffc080c1b178` | `.read` handler |
| `uhid_char_write` | `0xffffffc080c1b414` | `.write` handler |
| `uhid_char_poll` | `0xffffffc080c1b7e8` | `.poll` handler |
| `uhid_char_release` | `0xffffffc080c1b964` | `.release` handler |
| `uhid_dev_create2` | `0xffffffc080c1bbac` | UHID_CREATE2 处理(走 write 路径) |
| `uhid_dev_input` | `0xffffffc080c1bd70` | UHID_INPUT 处理 |
| `uhid_queue_event` | `0xffffffc080c1c5c4` | HID 事件回写 ring |
| `uhid_device_add_worker` | `0xffffffc080c1c8c0` | workqueue:注册 hid_device |
| `uhid_misc_init` | `0xffffffc081cfb090` | module init —— 用于反汇编验证 |
| `uhid_misc_exit` | `0xffffffc081d17004` | module exit |

Δ 称呼:旧文档把 `uhid_misc.fops 槽` 写为 `0xffffffc082234fc8`(实为 name 槽),亦有人写 `0xffffffc082234fC8` 都错。**从今往后用 `0xffffffc082234fd0`**。

---

## 2. uhid_misc.fops 槽地址的反汇编证据

`uhid_misc_init` 只做一件事:把 `uhid_misc` 这个 `struct miscdevice *` 传给 `misc_register`。反汇编:

```
ffffffc081cfb090 <uhid_misc_init>:
ffffffc081cfb090: d503233f     paciasp
ffffffc081cfb094: a9bf7bfd     stp  x29, x30, [sp, #-0x10]!
ffffffc081cfb098: 910003fd     mov  x29, sp
ffffffc081cfb09c: b00029c0     adrp x0, 0xffffffc082234000        ; page base for uhid_misc
ffffffc081cfb0a0: 913f0000     add  x0, x0, #0xfc0               ; x0 = 0xffffffc082234fc0 = uhid_misc
ffffffc081cfb0a4: 97aeb200     bl   0xffffffc0808a78a4 <misc_register>
ffffffc081cfb0a8: a8c17bfd     ldp  x29, x30, [sp], #0x10
ffffffc081cfb0ac: d50323bf     autiasp
ffffffc081cfb0b0: d65f03c0     ret
```

→ `uhid_misc = 0xffffffc082234fc0`。  
miscdevice 6.6 标准 layout: `+0x00 minor`(int), `+0x08 name`(ptr), `+0x10 fops`(ptr), `+0x18 list`, `+0x28 mode`(umode)。

→ **`uhid_misc.fops 字段地址 = 0xffffffc082234fc0 + 0x10 = 0xffffffc082234fd0`**  

对比 ashmem 现行写法:`ASHMEM_MISC_FOPS_OFF = 0x0223b5e8`,由 `ashmem_misc = 0xffffffc08223b5d8` 得 fops 槽 = `0xffffffc08223b5d8 + 0x10 = 0xffffffc08223b5e8`,+0x10 偏移与 miscdevice 标准 layout 完全一致 —— **流派对齐,uhid 走同一 +0x10 偏移**。

---

## 3. uhid_fops 表完整展开(`file_operations` +0x00..+0x70)

```
+0x00 owner          = 0
+0x08 llseek         = 0
+0x10 read           = uhid_char_read        (0xffffffc080c1b178)
+0x18 write          = uhid_char_write       (0xffffffc080c1b414)
+0x20 read_iter      = 0
+0x28 write_iter     = 0
+0x30 iopoll         = 0
+0x38 iterate_shared = 0
+0x40 poll           = uhid_char_poll        (0xffffffc080c1b7e8)
+0x48 unlocked_ioctl = 0                            ★ 不走 ioctl
+0x50 compat_ioctl   = 0
+0x58 mmap           = 0
+0x60 open           = uhid_char_open        (0xffffffc080c1b86c)
+0x68 flush          = 0
+0x70 release        = uhid_char_release     (0xffffffc080c1b964)
```

**关键约束**:
- 想从用户态 ioctl 命令直接做内核读 —— uhid 没这接口。
- 任何走标准 VFS `read()/write()` 的调用都会进到 fops 表对应槽,因此 KCFI 会按函数原型检查指针:

  - `.read` 槽函数原型: `ssize_t (*)(struct file *, char __user *, size_t, loff_t *)`
  - `.write` 槽函数原型: `ssize_t (*)(struct file *, const char __user *, size_t, loff_t *)`
  - `.open` 槽函数原型: `int (*)(struct inode *, struct file *)`
  - `.release` 槽函数原型: `int (*)(struct inode *, struct file *)`
  - `.poll` 槽函数原型: `__poll_t (*)(struct file *, struct poll_table_struct *)`

  攻击者若把 `.read` 槽填入 `copy_from_kernel_nofault(ssize_t(*)(void*, void*, size_t))`,原型不匹配 → KCFI trap → panic。不能跨原型挂 gadget。

---

## 4. 已枚举的 Gadget 候选与可用性判定

### A. `copy_from_kernel_nofault` @ `0xffffffc0802d720c`
```
原签名: long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
内部:
  23c: bl 0xffffffc0802d7164 <copy_from_kernel_nofault_allowed>   ; 检查地址允许
       → 若不允许,返 -EFAULT;PAN/页不可达会先 fault
```

**判定**: 不能直接当 fops 槽函数指针用 —— 函数原型与 VFS handler 不匹配,KCFI 拦掉。可用场景:**只有当我们能控制一个内核函数指针调用点(比如 rbtree ops、workqueue handler、notifier_call)且其原型正是 `(void*, void*, size_t)`**。该路径目前整条链没现成 trigger。

### B. `bin2hex` @ `0xffffffc08070bec4`
```
原签名: char *bin2hex(char *dst, const void *src, size_t count)
作用: 把 src 的 count 字节逐字节洗成 2-char hex 写入 dst,返回 dst+2*count
```

**判定**: 与 .read_iter 兼容 `.read_iter` 原型是 `ssize_t (*)(kiocb *, iov_iter *)`,不匹配。但 `bin2hex` 自己不过 KCFI 检查时也可以绕——只要调用点不是函数指针而是直接 bl `bin2hex`(符号 known-good)。

### C. `simple_read_from_buffer` / `memory_read_from_buffer`
```
simple_read_from_buffer       @ 0xffffffc0804000b0
memory_read_from_buffer       @ 0xffffffc0804002c8
原签名(适合 .read/.read_iter 类型):
  ssize_t simple_read_from_buffer(void __user *to, size_t count,
                                  loff_t *ppos, const void *from, size_t available)
```

**关键**: `simple_read_from_buffer` 的原型**和 `.read`(ssize_t(*)(file*, char __user*, size_t, loff_t*))不同** —— 多了一个 `available` 参数,参数数量不同,KCFI 直接 tack。

但内核中有大量 **`.read` handler 内部调用 `simple_read_from_buffer`** —— 业界 CFI 不会因为 handler 内部直接 bl helper 就 trap。即若我们让 `.read` 槽填一个**合法的 ssize_t(*)(file*, char __user*, size_t, loff_t*)** 函数 pointer,并且让该 handler 内部调 `simple_read_from_buffer`,从 `file->private_data` 取出 buffer 起点,那么 user 调 `read()` 即可任意读。

### D. 内核内现存 ssize_t(*)(file*, char __user*, size_t, loff_t*) 的 handler
我们已知**uhid_char_read** 自己就是这原型 —— 但它内部从 `uhid_device->rdesc`/ring buffer 取源地址,**源不受控**。

**最有希望的候选方向** —— 不是替换 uhid 的 fops 表整个新造,而是**部分覆盖**:让 `.read` 槽仍指 `uhid_char_read`(PAC 合法),其他字段照样 uhid 原 fops;但在 spray 页**构造一个伪造的 `uhid_device`**,使其 `rdesc` / `rdesc_size` 指向我们想读的内核源(如 `mm_struct + 0x408`)。然后通过已 open 的 fd 触发 `.read` 走 `uhid_char_read` 的 `UHID_GET_REPORT` / `UHID_HID_START` 出来事件,事件 payload 里包含我们想读的字节。但cantMake it generic因 uhid 数据结构内部字段全部要满足一致性,代价依然不小。

### E. 建议主线:**不重新设计 fops 表 gadget**,而是走**cred 直写** + 后续 uhid fops 替换
将「uhid fops 重定向 → 任意 RW → 读 mm->owner → cred 直写」拆为两步:

1. **首次写入 (PI chain write 目标 = `uhid_misc.fops`槽 @ 0xffffffc082234fd0)**:
   - rb_insert 写入值 = &fake_w0.pi_tree_entry (固定 spray 页地址)
   - 该写入使 `uhid_misc.fops = fake_fops_table_address`(spray 页内)
   - spray 页中布置 `fake_fops` 表:`.open/.read/.write/.release` 等**全部保留 uhid 原函数指针**(从 uhid_fops 复制),仅 `.release` 或 `.read` 中之一被改为指向「内部调 simple_read_from_buffer 或 uhid_char_read 直接吃 fake_uhid_device」的内核现有函数。
   - 关键是**伪造一个 `uhid_device` rdesc 指针受控**,等 open → read 时事件源拿 rdesc → 用户读到内核任意地址数据。

2. **第二次写入(jin PI 链上的二次写)**: 在cred 直写阶段把 `task->cred/real_cred` 指向 spray 页一份伪造 cred。这块在 main_cred.c 的 walks[] 表中已具备框架,只需修 target = `&task->cred - 8` 和 value = `&fake_w0.pi_tree_entry`。

### F. 任何情况下都不能做的事
- **将 `.read` / `.unlocked_ioctl` 槽设为任意 helper**(`copy_from_kernel_nofault` / `bin2hex` 等):KCFI 必拦 → panic。
- **将 `.read_iter` / `.write_iter` 设为非 `kiocb*, iov_iter*` 原型的函数**:同上。
- **修改 `.open` 为非 `(inode*, file*)` 原型的函数**:同上。
- **跳过 PAC**:所有 fops 函数指针入口都 `paciasp`,若给一条无 PAC 斜杠的 stub → 内核 `autiasp` 自动校验 → BRK。

---

## 5. 当前 util.c put_fake_fops_table 的修正

当前 `share-poc-XRing-O1/src/util.c::put_fake_fops_table` 把:
- `FOPS_READ_OFF → fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF`: 这是把 PI-tree 节点指针塞进了 `.read` 槽,语义完全错乱 —— 非 PAC 合法函数指针 → open() 即 panic。
- `FOPS_READ_ITER_OFF → text_addr(CONFIGFS_READ_ITER)`: 这个是从 configfs 路径搬来的,它假设了 ashmem 的 name-blob 机制;uhid 没这玩意,函数会取 `file->private_data` 当 ashmem_area,各种 NULL deref。

→ **uhid 路线下 `put_fake_fops_table` 必须改写**:
```c
void put_fake_fops_table(unsigned char *p, size_t off) {
    /* 完全复制 uhid_fops 内容 —— 各函数指针从 uhid_fops 直接拷贝(KASLR=0,地址固定) */
    put64(p, off + FOPS_OWNER_OFF,        0);                       // owner
    put64(p, off + FOPS_LLSEEK_OFF,        0);                       // llseek
    put64(p, off + FOPS_READ_OFF,          0xffffffc080c1b178ULL);   // read  = uhid_char_read
    put64(p, off + FOPS_WRITE_OFF,         0xffffffc080c1b414ULL);   // write = uhid_char_write
    put64(p, off + FOPS_READ_ITER_OFF,     0);                       // read_iter
    put64(p, off + FOPS_WRITE_ITER_OFF,    0);                       // write_iter
    put64(p, off + FOPS_POLL_OFF,          0xffffffc080c1b7e8ULL);   // poll  = uhid_char_poll
    put64(p, off + FOPS_IOCTL_OFF,         0);                       // unlocked_ioctl = 0
    put64(p, off + FOPS_MMAP_OFF,          0);                       // mmap
    put64(p, off + FOPS_OPEN_OFF,          0xffffffc080c1b86cULL);   // open    = uhid_char_open
    put64(p, off + FOPS_FLUSH_OFF,         0);                       // flush
    put64(p, off + FOPS_RELEASE_OFF,       0xffffffc080c1b964ULL);   // release = uhid_char_release
}
```

效果:劫持后 `uhid_misc.fops = &spray_fake_fops`,open(/dev/uhid) 的内核执行路径与原版完全一致(`misc_open → fops.open = uhid_char_open`),PAC 与 KCFI 全部一把过。这条路本身不给我们任意 RW —— 但uhid_misc.fops **被改成了我们 spray 页地址**,意味着我们 PI-chain 具备了**「往任意内核地址写入 node 地址」这一原语**(已有);再次利用 PI-chain 能在 spray 页 fake_fops 表上的**另一个字段上**做改写 —— 例如先把 spray 上 fake_fops 全保持 uhid 原 fops,然后第二次 PI 链把 spray 上 `fake_fops.read` 槽改成「指向 `simple_read_from_buffer` 通过 ROP-like 不行(KCFI)」,这条不通;但简单可行的是**把 spray 上 fake_fops 的 `.release` 改为指向 kfree / NULL**,配合某些 struct 释放路径…仍是复杂分支。

**真正干净的主线**:回归 README §优先级1 (cred 直写),不依赖 uhid fops 路径完成提权结果。uhid fops 劫持只作为「**解除 ashmem 读链 wall**」的备用铠甲,留待后续分析。

---

## 6. 下一步行动(P2 / P1 排序)

### P1: 完善 spray 页伪造 cred + `task->cred/real_cred` 直写

- **代码层面**: 在 `prepare_skb_payload` 内,于 spray 页 `fake_w0` 内 或 `fake_w0.pi_tree_entry` 字段附近位置,布置一段完整的 `struct cred` 结构(`uid=0,gid=0,euid=0,egid=0,securebits=0,cap_effective=0xffffffff, cap_inheritable=0, cap_permitted=0xffffffff, cap_bset=0xffffffff, cap_ambient=0`)。
- **PI chain walk**: 取 **已 leak 的 task_struct 地址**(kernelsnitch 已能拿到 mm,但读 mm->owner 这一步仍卡。**task_struct 当前还是只能从 leak 路径拿**)。 walks[].target = `task_struct+0x818 - 8`(cred slot), value = 「fake cred 所在 spray 地址」(由 fake_w0 块计算)。
- **待解决依赖**:task_struct 地址如何从 mm_struct 得到?当前只有 mm_struct leak,**这一步需要内核任意读** —— 又回到 P3 死循环。

→ **突破口: 取消 mm->owner 间接,直接用 `current` 控制当前 task_struct**。
> testsnitch 真机已确认 SLIDE 阶段拿到 KASLR=0;`current` 当前 shell 进程的 task_struct 地址在 binder/executor context 内可以从 `current` 的内核 sp 通过 `r() = sp & 0xffffffffffffc000` (thread_union per-cpu) 大致估算 —— **不可靠**,不稳。
>
> 另一思路是:**让 PI 链直接指向 `init_task` 的 cred 字段,而非我们的当前 task**,因为 init_task.const_boot_cred 永远指向 init_cred;若我们 race 通过 `commit_creds(init_cred)` 让当前线程变 root,**稳的多**。方法不是写 init_task.cred,而是直接 dispatch 到一个 kernel thread / kthread 上下文执行 commit_creds(init_cred) → 但难。
>
> **最稳妥:直接 dispatch shell 我们自己的 task_struct 地址 —— 需要拿自身 task_struct 内核地址**。

### P2: uhid fops 表替换 → 利用 `uhid_char_read` 内部源可控 → 任意内核读

**步骤**:
1. PI-chain 写 1:`write_left = 0xffffffc082234fd0 - 8 → *(0xffffffc082234fd0) = &fake_fops_spray`(write_pc=0, write_right=0, write_left=0xffffffc082234fc8)
   - 这意味着 `uhid_misc.fops` 现在指向 `&fake_fops_spray`
   - spray 中 `fake_fops_spray` 表内全部字段 = uhid 原版函数指针(见 §5)
2. **关键**: spray 上还要布置一个假的 `uhid_device` (约 0x1300 字节),其 `rdesc` / `rdesc_size` 指向我们想读的内核地址;`uhid_device.inq` 等队列链表正常 init。
3. open(/dev/uhid) → uhid_char_open 用 kzalloc 新建真 uhid_device,而**不是用 spray 上的**。这里 us不会 成功 —— 除非让 open 时不调用原版,需另一条 handler。
4. 反例结论:**uhid_char_read 思路天然无法劫持**,因为 fake_fops.open = uhid_char_open 永远会新建一个 uhid_device 覆盖 file->private_data。 也就是说 fake fops 路径要起效,必须**给 `.open` 设别的 handler 让它不 new private_data 而是直接用 file 既有数据** —— 这放弃 uhid 还原对 .data 看的话又陷 KCFI 难。

**结论 §6-P2 的实话**:uhid fops 劫持本身可以用 PI chain 实现,但「劫持后用 uhid_char_read 做任意读」需要绕 uhid_char_open 的 private_data 初始化逻辑,**这增加一层 handler 替换 → KCFI 仍可能拦截**。  
因此,uhid fops 重定向路线**主要价值是验证 PI chain 对 miscdevice::fops 槽写入有效**;进一步任意 RW 需要另寻一个 VFS handler 中 private_data 不被强制重置、且函数体从私有 data 内可控地址读取的设备类。可能候选:

- **`/dev/.rokernel` / `/proc/<pid>/mem` via ptrace** (shell 多能自读自己的 /proc/self/mem)
- **fanotify / inotify** (private_data 是 fsnotify_mark,但其 read 路径复杂)
- **seq_file** 系列:每次 open 都会新建 seq_file 作为 private_data —— 同 uhid 问题。

→ 真正最稳妥路线仍是 P1 (cred 直写),即便需要先解决 task_struct leak 问题。

### P3: 解决 `task_struct` leak 问题(读 mm->owner)

由于已 PI-chain 可控写入 `uhid_misc.fops` 槽证明这条路可行,我们做任意读最稳路线是:
- **制造一个 kasan-like fault side channel**(通过 PI chain 把一个 KASAN 用来读内存的字段往用户态 visible 的位置写回 —— 比如 `task->comm`,然后使用 `top/cmdline` 读出)。代价高。
- **直接用 PI chain 二次写入**: 写入 `init_task.cred = &fake_cred_spray`,**因为 init_task 是所有 fork 的祖先,但不会 transfer cred**(cred 是 RCU-COW 的,init_task.cred 仅是早期 init_cred指针)。效果不够。  
- **`task->comm` side channel**: PI chain 写入 `task->comm` 覆盖 16 字节 task name。把 task_struct 用户态操控的 task 名读出来即从内核数据到用户的一次传送。但 comm 受 16 字节限制,而且不能从 内 task_struct 字段内拿到指针值。

→ **可行性最大路线:借 client leak mm 之后,把 PI chain 直接把当前进程自己的 task_struct 找出来**。当前进程的 task_struct 地址,可用 `prctl(PR_GET_NAME)` 配合给 comm side channel;**但需要先有 task_struct 地址才行**(死循环)。  

> **新提议**: 用 `io_uring` 的 `IORING_OP_MSG_RING` / 边带信息路径,或许能让内核 ret 一个内核指针到 user,binder / bpf 也类似;但本机被 SELinux 拦的可能性高。这条留待实验。

---

## 7. 代码级 TODO 清单(可立即动手)

- [ ] **target.h 新增** `UHID_MISC_OFF = 0x02234fc0` 与 `UHID_MISC_FOPS_OFF = 0x02234fd0`(注意 +0x10) 与 `UHID_FOPS_OFF = 0x012bb120`。
- [ ] **util.c::put_fake_fops_table** 增加 `payload_mode == PAGE_PAYLOAD_UHID` 分支,按 §5 把表全建为 uhid 原版函数指针。
- [ ] **util.c::prepare_skb_payload** 内 FOPS route:`write_left = data_addr(UHID_MISC_FOPS) - 8`,即 `0xffffffc082234fc8`;确认 README 中所有引用 `0xffffffc082234fc8` 含义为「名 slot 字段」**(wait —— 计算得 uhid_misc = 0xffffffc082234fc0, fops 槽=+0x10=0xffffffc082234fd0, 名 slot=+0x08=0xffffffc082234fc8)**。
  - 因 rb_insert 写入位置 = `pi_tree.rb_left` 槽,实际写入字节地址 = `write_left + 8`(rb 左节点在结构偏移 +8),所以 `write_left = UHID_MISC_FOPS - 8 = 0xffffffc082234fd0 - 8 = 0xffffffc082234fc8` —— 等等!这与 §0 中「README 给的 0xffffffc082234fc8 是 name 槽」结论不同。
  - 重新核对:PI chain 的 rb_insert 写入公式是 `*(write_left + 8) = node_addr`。我们都知道 `write_left + 8 = misc_fops 槽地址`,所以 `write_left = misc_fops - 8`。
  - 因此 **`write_left = 0xffffffc082234fd0 - 8 = 0xffffffc082234fc8`**,这恰好等于「`uhid_misc.name` 槽」的地址(数值上)+0x08=0xffffffc082234fc8)。**这是巧合** —— miscdevice 中 fops(+0x10) 与 name(+0x08) 字段相距 8 字节,正好使 `fops - 8 = name`。
  - **所以 README/项目代码里的 `write_left = 0xffffffc082234fc8` 实际是正确的** —— 用作 rb_left 字段写入,最终派范的字节写入位置是 `0xffffffc082234fc8 + 8 = 0xffffffc082234fd0 = uhid_misc.fops 槽`。**之前 §0 部分对这一点的「笔误」结论是错的,我自相矛盾了。请以 §7 这段为准!**
- [ ] **大道真理修正**:`write_left = 0xffffffc082234fc8`(原写法对);`UHID_MISC_FOPS = 0xffffffc082234fd0`(写入目标);`write_left + 8 = UHID_MISC_FOPS`(PI 链最终落点)。
- [ ] 旧路径 `write_left = ASHMEM_MISC_FOPS - 8 = 0xffffffc08223b5e8 - 8 = 0xffffffc08223b5e0`:同因,正确写入落在 ashmem_misc.fops(0xffffffc08223b5e8)。跟 uhid 形式上一致。
- [ ] **build 定义 PARITY** 应加 `UHID_MISC_FOPS` 名字与 `ASHMEM_MISC_FOPS` 同 class,代码切 `payload_mode` 控制。

---

## 8. 反汇编文件存放
本次新增 disasm 文件存放路径:`share-poc-XRing-O1/disasm/uhid_*.txt`(后续写入);
已有的 anti-PI chain 资料:`~ CVE-2026-43499/RESEARCH_NOTES/disasm/`、`analysis/chain_disasm.txt`。

---

## 9. 结论一句话

- **uhid fops 槽精确地址 = `0xffffffc082234fd0`**,等价于「`write_left + 8`」(write_left=0xffffffc082234fc8)→ 这是 PI-chain 写入最终派范的落点位置。**与 ashmem 完全平行,代码可平滑切换。**
- uhid 与 ashmem 不同点:uhid 在 shell 域可 open;但 uhid 没有 ashmem 的 name-blob 机制,**所以 configfs_read_once 这条任意读链无法平移** → 任意读不得不走「新 gadget 设计」一节。
- KCFI + PAC 禁止跨原型挂现成 helper(`copy_from_kernel_nofault` / `bin2hex` / `simple_read_from_buffer` 都不能用 __fops__ 槽直接挂载),所以uhid fops 重定向路线**不是任意内核读的最短路径** —— 真正能突破当前 P3 wall 的仍需重新设计(binder fsnotify client leak 等)。
- 当前最稳主线:**回 P1(cred 直写)**,卡点是 task_struct 地址 leak —— **这是真正最大的研究杠杆**,不是 uhid fops。
