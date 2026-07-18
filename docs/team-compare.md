# 团队报告对比分析 — ayyy7128/CVE-2026-43499-jinghu

> 克隆自 https://github.com/ayyy7128/CVE-2026-43499-jinghu (分支 2)
> 分析日期: 2026-07-18

## 1. 设备 / 内核一致性

| 项 | 我们 (jinghu) | 团队 (jinghu-CP2A) |
|---|---|---|
| 内核 | 6.6.77-android15-8-g5770c661275f-abogki443185593-4k | **完全相同** |
| SoC | XRing O1 | XRing O1 |
| init_task | 0xffffff80020de280 | 0xffffff80020de280 ✓ |
| init_cred | 0xffffff80020f0548 | (同推导) |
| selinux_enforcing | 0xffffff8002315f68 | 0xffffff8002315f68 ✓ |
| ashmem_misc_fops | 0xffffff800223b5e8 | 0xffffff800223b5e8 ✓ |
| 指纹 | BP2A.250605.031.A3 / Android 16 | CP2A.260605.012 / Android 16 |
| KASLR | 0 (slide 固定) | 0 |

**结论**: 双方内核是同一构建, 所有符号偏移完全对齐。指纹 build ID 不同只是小米不同周次的 userdebug/release 包, 内核二进制一致。

## 2. 架构对比

### 我们 (backup_v1)
- `main.c` (cred 直写框架, 3 次 walk) + `util.c` (kernelsnitch + prepare_kernel_page + configfs_read_once)
- `fops.c` (PI 链触发) + `slide.c` (KASLR) + `test_minimal.c` (STAGE 1-7 分阶段)
- 路线: kernelsnitch leak → configfs 读 mm->owner → cred 直写

### 团队 (exploit/ 完整)
- `direct.c`: /dev/mem 物理内存直写 fops (Android 不可用, 仅 fallback)
- `root.c`: `install_android_root` — task walk + cred patch + selinux 清零 (通过 pipe physrw)
- `pipe.c`: `install_pipe_physrw` — 用 pipe buffer page 做任意物理读写
- `poc/poc.c`: 独立 PoC (多 lane stamp: prctl/socket/pselect/tcp/keyctl/futex)
- 路线: kernelsnitch → **configfs 任意读写** → pipe physrw → root

### 关键差异
团队的 root 提权 (`install_android_root`) 和 pipe physrw **全部建立在 `configfs_read_once` / `configfs_write_once` 之上** (pipe.c 的 `pipe_phys_read_data` → `kernel_read_data` → `configfs_read_once`)。也就是说, 团队的整个后段 (任意 RW + 提权) 都依赖 configfs 读原语。

## 3. ★ 核心结论: 双方卡在同一处

### configfs_read_once 代码双方已一致
我们当前 `backup_v1/src/util.c:790` 的 configfs_read_once:
```c
off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
uintptr_t page = target - (uintptr_t)pos;
put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
ssize_t rd = pread(fd, data, len, pos);
```
与团队 `util.c:768` **逐字相同**。早期 README "configfs 有 bug (needs_read_fill=0 不设 buffer_size)" 描述的是更老的版本, 当前代码已修正。

### 真正的 blocker: /dev/ashmem 在 shell 域被 SELinux 拒
configfs_read_once 需要一个 **ashmem fd** 来承载 target 地址 (ASHMEM_SET_NAME ioctl)。但:
- `/dev/ashmem` 在 shell 域 `cat` → `Permission denied` (DAC 666 但 SELinux 拦截 open)
- 团队的 `open_ashmem_device` 用 `SYSCHK(open(ashmem_path))` — 在 shell 域同样会失败
- 团队 `main.c` 探针: `configfs_read_once(afd, ...)` 在 ashmem fd 不可开时返回 0

### 团队 PROGRESS.md 自证
> "泄露 mm->owner（KernelSnitch 已有 mm；configfs 读仍 rd=0）后走 dijun cred"
> 总体进度 78%, 卡点从「盲目 stamp」收敛到「hold + 只叠 lock」

即团队也确认 **configfs 读返回 0**, 和我们完全一样。

### 团队 /dev/mem fallback 不可行
`direct.c` 试图 `open("/dev/mem")` 直接写物理内存覆盖 ashmem fops。但:
- Android 默认 `CONFIG_STRICT_DEVMEM=y`, /dev/mem 不可开
- 即使可开, 也需要 phys→vaddr 换算且 shell 域通常无权限
- 这是 "nice to have" fallback, 不是主路径

### 团队 build/ 里的 preload.so
`build/jinghu-CP2A.260605.012/bin/preload.so` 存在, 但 PROGRESS.md (2026-07-17) 显示仍卡在 configfs 读 + hold 阶段。无法确认是否已完整 root (无实机运行验证)。

## 4. ★ 突破方向: uhid fops 重定向 (绕过 ashmem SELinux 墙)

### 不对称发现
| 设备 | 权限 | shell 域可 open? | 用途 |
|---|---|---|---|
| /dev/ashmem | crw-rw-rw- root root | ❌ SELinux 拒 | configfs 任意读写载体 |
| /dev/uhid | crw-rw-rw- uhid uhid | ✅ 可 (我们 uhid_test.c 验证 fd=3) | HID 设备 |

`/dev/uhid` 在 shell 域**可正常 open** (我们之前的 uhid_test.c 已验证 fd=3, 仅 UHID_CREATE 因协议参数返回 EINVAL)。而 /dev/ashmem 被 SELinux 拦截。

### 思路
KASLR=0 → 所有静态内核地址已知 → `uhid_fops` (全局 file_operations) 地址可从 vmlinux 符号表拿 (固定)。

GhostLock 写入原语可把 `uhid_fops` 指向 spray 页面的 fake fops 表 (与团队对 ashmem 做的 fops 劫持同构, 只是目标设备换成 uhid):
```
write_left = &uhid_fops - 8
→ PI 链 rb_insert: *(uhid_fops) = &fake_w0.pi_tree_entry (spray 页面)
```
然后 `open("/dev/uhid")` (shell 域允许) → 该 fd 的 f_op 已被劫持 → 调用 fake fops 中的函数 → 任意内核 RW。

### 关键 caveat (未验证, 待研究)
团队 configfs 任意读依赖 **ashmem 专属的 name blob 机制** (ASHMEM_SET_NAME 承载 target 地址, configfs_bin_read_iter 从该 blob 取 target)。uhid 没有这套机制, 所以不能直接复用 `configfs_read_iter` 的 target 传递。需要为 uhid fd 找一条 **自然 syscall → 可控参数 → 任意 RW** 的 gadget:
- 候选: fake fops 的 `.read`/`.read_iter`/`.unlocked_ioctl` 指向一个内核函数, 其参数 (buf/arg 用户态可控, 且能从某可控地址取源/目的)。
- 或: 用 uhid 劫持只做 "任意地址写已知值" 的跳板, 再链式升级。

这是当前最有价值的**未验证假设**, 需设备重连后实验。

### ★ 已从 vmlinux_extracted 提取的 uhid 具体目标 (KASLR=0, 直接是运行时地址)
```
uhid_fops         = 0xffffffc0812bb120   (const struct file_operations uhid_fops)
uhid_misc         = 0xffffffc082234fc0   (struct miscdevice uhid_misc)
uhid_misc.fops @ +0x10 = 0xffffffc082234fd0   ← 当前指向 uhid_fops (已反汇编验证)
```
校正上面 "write_left = &uhid_fops - 8" 的写法: 要劫持的是 **miscdevice 的 .fops 指针字段**, 不是 fops 表本身。正确目标:
```
write_left = uhid_misc.fops - 8 = 0xffffffc082234fc8
→ PI 链 rb_insert: *(0xffffffc082234fd0) = &fake_w0.pi_tree_entry (spray 页面)
```
劫持后 `open("/dev/uhid")` 得到的 fd, 其 `file->f_op` 指向 spray 页面 fake fops。

fake fops 表需填 (struct file_operations 布局, 同团队 target.h):
```
+0x00 owner           (ptr)
+0x08 llseek          (ptr)
+0x10 read            (ptr)  ← read(uhid_fd,...) 走这里
+0x18 write           (ptr)  ← write(uhid_fd,...) 走这里
+0x20 read_iter       (ptr)
+0x28 write_iter      (ptr)
+0x48 unlocked_ioctl  (ptr)  ← ioctl(uhid_fd,...) 走这里
```
下一步: 在 spray 页面伪造上述表, 把 `.read`/`.unlocked_ioctl` 指向一个能做任意 RW 的内核 gadget (参数 buf/arg 用户态可控)。gadget 候选需反汇编 vmlinux 枚举。

## 5. 原语限制 (再次强调)

GhostLock 写入原语 `str x25, [x11,x13]` 写的是 **x25 = &fake_w0.pi_tree_entry (spray 页面已知地址, 非0)**。因此:
- ❌ 不能直接写 0 (清零 selinux 失败)
- ❌ 不能直接写 init_cred 地址
- ✅ 能写 spray 页面已知地址 (指针重定向)

要清零 selinux / patch cred, **必须先有任意 RW**, 而任意 RW 需要 fops 劫持 bootstrap。fops 劫持的目标设备必须是 shell 域可 open 的 → **ashmem 不行, uhid 是候选**。

## 6. 下一步 (设备重连后实验)

- [ ] 从 `vmlinux_extracted` 提取 `uhid_fops` 符号地址 (用 extract_symbols.py / find_kallsyms.py)
- [ ] 确认 /dev/uhid open 在 shell 域成功 (已验证 fd=3)
- [ ] 枚举 shell 域可 open 的全部设备 (找比 uhid 更优的 fops 劫持目标)
- [ ] 改造 `prepare_skb_payload`: FOPS 模式 `write_left = uhid_fops - 8`
- [ ] 设计 uhid fake fops: 找 `.read`/`.unlocked_ioctl` 的任意 RW gadget (参数可控)
- [ ] open /dev/uhid → 触发 gadget → 验证任意读 (拿 task_struct)
- [ ] 复用团队 `install_android_root` 逻辑 (task walk + cred patch + selinux 清零)

## 7. 与团队共享进度建议

双方可合并的价值:
- 我们: kernelsnitch 真机验证通过 + PI 链触发通过 + 精确的 rt_mutex_adjust_prio_chain 反汇编 (写入值确认)
- 团队: 完整的 pipe physrw 任意 RW 实现 + install_android_root 提权逻辑 + 多 lane stamp PoC
- 共同缺口: **shell 域内核读原语** (ashmem SELinux 墙)
- 建议: 双方合力验证 uhid (或其他可 open 设备) 的 fops 劫持 bootstrap, 这是打通整条链的最后一块拼图
