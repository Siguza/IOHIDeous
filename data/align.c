// gcc -o align align.c -Wall -O3 -framework IOKit
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <IOKit/hidsystem/IOHIDShared.h>

void print(void *ptr)
{
    uint64_t val = (uint64_t)ptr;
    printf("\x1b[%um0x%04llx\x1b[0m ", val % 0x1000 < 8 ? 91 : 92, val);
}

int main(int argc, const char **argv)
{
    EvGlobals *evg = NULL;
    size_t off = atoi(argv[1]) * sizeof(uint32_t);
    for(size_t i = 0x1000; i < 0x6000; i += 0x1000)
    {
        size_t idx = (i - ((uintptr_t)&evg->lleq - (uintptr_t)evg)) / sizeof(NXEQElement);
        NXEQElement *el = (NXEQElement*)((uintptr_t)&evg->lleq[idx] + off);
        for(size_t j = 0; j < 2; ++j)
        {
            print(&el[j].next);
            print(&el[j].sema);
            print(&el[j].event.type);
            print(&el[j].event.time);
            print((char*)&el[j].event.time + sizeof(uint32_t));
            print(&el[j].event.flags);
        }
        printf("\n");
    }
    return 0;
}
