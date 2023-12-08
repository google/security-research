#ifndef __UTIL_H
#define __UTIL_H

extern bool quiet;

void logmsg(char *format, ...);
void print(char *format, ...);
bool num_inrange(char *range, int num);

#endif
