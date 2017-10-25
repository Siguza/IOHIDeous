#ifndef CONFIG_H
#define CONFIG_H

// This file contains all values that were not found deterministically by some
// formula or logic, but through experimenting. They have proven to yield good
// results on my setup, but might require tweaking in order to work on others.

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

// These values affect heap spraying and evg offset amount.
// KALLOC_* is for High Sierra, KERNEL_* is for Sierra.
// There is no kalloc spray amount, because that value is computed at runtime
// by means of sysctlbyname("hw.memsize"). Note that this value is also added
// to KERNEL_SPRAY_AMOUNT, in order to fill up the kalloc_map first.
// Defining PLAY_IT_SAFE only affects Sierra and causes more conservative values
// to be used, which yield a higher likelihood of success, at the expense of
// a HUGE performane impact.
#ifdef PLAY_IT_SAFE /* not defined by default */
#   define KERNEL_SPRAY_AMOUNT  0x80000000
#   define KERNEL_OFFSET_AMOUNT 0x7f000000
#else
#   define KERNEL_SPRAY_AMOUNT  0x30000000
#   define KERNEL_OFFSET_AMOUNT 0x2f000000
#endif
#define KALLOC_OFFSET_AMOUNT  (-0x30000000)

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

// This is the threshold for the prefetch timing attack.
// I'm doing N timings per address, sort the array of timings, take the average
// of the middle N/4 values (i.e. 3/8th to 5/8th) and use that as my indicator.
// For unmapped pages, I have seen that value anywhere from 58 to 600, but for
// mapped pages it has been strictly between 28 and 32.
// Therefore I have chosen 50 as the value for which I will treat a page as
// unmapped if its indicator value is above it.
#define PREFETCH_LIMIT 50

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- -----

// TODO: docu
#define EXPLOIT_TIMEOUT 1000000 /* 1 second */

#endif
