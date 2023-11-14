#ifndef __THREADS_H
#define __THREADS_H

pthread_t spawn_thread_core(void *(*start_routine)(void *), void *restrict arg, int cpu);
int set_cpu_affinity(int cpu);

#endif
