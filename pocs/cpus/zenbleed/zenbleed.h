#ifndef __ZENBLEED_H
#define __ZENBLEED_H

struct zenleak {
    int      cpu;
    uint64_t regbuf[4];
};

extern bool quiet;

void * pattern_leak_consumer(void *param);
int save_new_leak(struct zenleak *leak);
struct zenleak * load_new_leak(void);
void logmsg(char *format, ...);
void print(char *format, ...);
bool num_inrange(char *range, int num);

#endif
