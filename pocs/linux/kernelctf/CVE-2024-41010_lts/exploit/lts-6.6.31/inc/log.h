#ifndef _LOG_H_
#define _LOG_H_

#include <stdlib.h>
#include <unistd.h>


#define errout(msg) do {perror("[-] " msg); exit(EXIT_FAILURE); } while(0)

void hexdump(void *, unsigned int );

#endif /* _LOG_H_ */