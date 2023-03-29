#include <stdio.h>
// Execute with taskset -c 0 ./victim


void f1()
{
    for (register int i = 0; i < 200; i++)
    {
    }
}

int main()
{
    printf("Dst: %p\n", f1);
    while (1)
    {
        f1();
    }
}
