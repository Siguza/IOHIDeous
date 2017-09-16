_Siguza, 16. Sep 2017_

# IOHIDeous

"IOHIDFamily once again."

## Introduction

This is the tale of a macOS-only vulnerability in IOHIDFamily that yields kernel r/w and can be exploited by any unprivileged user.

IOHIDFamily has been notorious in the past for the many race conditions it contained, which ultimately lead to large parts of it being rewritten to make use of command gates, as well as large parts of it being made accessible only to processes with certain entitlements. I was originally looking through its source in the hope of finding a low-hanging fruit that would let me compromise an iOS kernel. I didn't know it then, but some parts of IOHIDFamily exist only on macOS - specifically `IOHIDSystem`, which contains the vulnerability discussed herein.

Note: The `ioprint` and `ioscan` utilities I'm using in this write-up are available at my [`iokit-utils`](https://github.com/Siguza/iokit-utils) repository.

## Technical background

In order to understand the attack surface as well as the vulnerability, you need to know about the involved parts of IOHIDFamily.

It starts with the [`IOHIDSystem`](TODO) class and the UserClients it offers. There are currently three of those:

- `IOHIDUserClient`
- `IOHIDParamUserClient`
- `IOHIDEventSystemUserClient`

(There used to be a fourth, `IOHIDStackShotUserClient`, but that has been commented out for a while now.) Like almost all IOUserClient in IOHIDFamily, `IOHIDEventSystemUserClient` requires an entitlement to be spawned (`com.apple.hid.system.user-access-service`), however the other two do not. `IOHIDParamUserClient` can actually be spawned by any unprivileged process, but of interest to us is `IOHIDUserClient`, arguably the most powerful of the three, which during normal system operation is held by `WindowServer`:

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

This is an important point because as it turns out, IOHIDSystem restricts the amount of any given `IOHIDUserClient` to one. This is specifically enforced by the `evOpenCalled` class variable, which is set to `true` when an `IOHIDUserClient` is spawned and to `false` again when it is closed. This variable is checked in `IOHIDSystem::evOpen`, which in turn is called from `IOHIDSystem::newUserClientGated`.

Bottom line, there can only be one `IOHIDUserClient` at any given moment, and chances are that when your code runs, `WindowServer` will be up and running with its UserClient already. So snatching that is not straightforward, but we'll get to that later. For now we're gonna look at what it actually uses that UserClient for.

`IOHIDSystem`/`IOHIDUserClient` offer some shared memory for an event queue that `WindowServer` can map into its address space via `clientMemoryForType`. This memory is split into three parts packed after each other in this order:

-   The `EvOffsets` structure.  
    This structs holds information about where the other parts of the shared memory are located in respect to the beginning of the shared memory (so they're given as offsets). The definition is:

        typedef volatile struct _evOffsets {
            int evGlobalsOffset;    /* Offset to EvGlobals structure */
            int evShmemOffset;      /* Offset to private shmem regions */
        } EvOffsets;

-   The `EvGlobals` structure.  
    This is where the actual event queue resides, and this makes up 99% of the shared memory. I'll omit the lengthy declaration here, you can view it in [`IOHIDShared.h`](TODO) or see my annotated version in [`data/evg.c`](TODO).
-   Private driver memory.  
    As far as I can see, this remains unused as has a size of 0 bytes.

In `IOHIDSystem`, the extensively used `EvGlobals` address is assigned to an `evg` variable, and although unused, the address of the private driver memory is assigned to an `evs` variable.

To initialise that memory, `IOHIDSystem` offers a `createShmem` function, which `IOHIDUserClient` implements as external method 0. Like pretty much any IOHIDFamily interface these days, `IOHIDSystem::createShmem` is neatly gated to prevent any concurrent access, and the actual implementation resides in `IOHIDSystem::createShmemGated`.  
That one merely performs a versioning check, allocates the memory if it hasn't been allocated before, and then calls `IOHIDSystem::initShmem` to clean/initialise the actual data structures.

And that's where it gets interesting.

## The vulnerability

This is the beginning of `IOHIDSystem::initShmem`, which contains the vulnerability:

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

Can you spot it? What if I told you that this function can be called with the shared memory already being mapped in the calling task, and that `EvGlobals` is declared as `volatile`? :P

The thing is that between this line:

    eop->evGlobalsOffset = sizeof(EvOffsets);

and this one:

    evg = (EvGlobals *)((char *)shmem_addr + eop->evGlobalsOffset);

The value of `eop->evGlobalsOffset` can change, which will then cause `evg` to point to somewhere other than intended.

From looking [at the source](TODO), this vulnerability has been present ever since the kext's original release back in 2002.

## Putting the exploit together

The fun part. :P

### Getting access

Before we can do anything else, we have to look at how we can actually get access to thing we wanna play with, i.e. how we can spawn an `IOHIDUserClient` when `WindowServer` is holding the only available, and is there before us.

The first option I implemented was to just get `WindowServer`'s task port and "steal" its client with `mach_port_extract_right`. Works like a charm, the only problem is that this requires you to be root, and SIP to be disabled.

The next lower option is to simply `kill -9 WindowServer`. Still requires root, but at least that works with SIP fully enabled. `WindowServer` goes down, its UserClient gets cleaned up and we have plenty of time to spawn our own. As a side effect, you'll also notice the system's entire graphical interface going down along with `WindowServer` - so we're not exactly stealthy at this point.

I did some more digging and found that `WindowServer` actually lets go of its UserClient for a few seconds when a user logs out - more than enough time for us to grab it. So finally we have something that doesn't require us to run as root, but merely as the currently logged-in user, since we can easily force a logout with:

    launchctl reboot logout

But can we go lower? Can we do this as any unprivileged user? TL;DR: Yes we can!  
First, we can try with some AppleScript trickery. `loginwindow` implements something called "AppleEventReallyLogOut" or "aevtrlgo" for short, which attempts to log the user out without a confirmation dialogue. For reasons of general insanity, `loginwindow` does not seem to verify where this event is coming from, so any unprivileged account such as, say, `nobody`, can get away with this:

    osascript -e 'tell application "loginwindow" to «event aevtrlgo»'

Now, it doesn't work quite as flawlessly as the previous method. It acts as if the user had actually chosen to log out via the GUI - which means that apps with unsaved changes can still abort the logout, or at least prompt for confirmation (an example for this is Terminal with a running command). In contrast, `launchctl` just tears down your GUI session without letting anyone say a damn thing. (Another drawback is that we cannot test the success of `aevtrlgo`, since the call returns while the confirmation popup is still active. This seems like a limitation of AppleScript.)

But second, alternatively to a logout, a shutdown or reboot will do as well. This makes for an interesting possibility: we could write a sleeper program and just _wait_ for conditions to become favourable - I have no access to any statistics, but I'd assume most Macs are _eventually_ shut down or rebooted manually, rather than only ever going down as the result of a panic. And if that assumption holds, then our sleeper will get the chance to run and snatch the UserClient it needs.

So in order to maximise our success rate, we do the following:

1. Install signal handlers for `SIGTERM` and `SIGHUP`. This should buy us at least a few seconds after a logout/shutdown/reboot has been initiated.
2. Run `launchctl reboot logout`.
3. If the former failed, run `osascript -e 'tell application "loginwindow" to «event aevtrlgo»'`.
4. Try spawning the desired UserClient repeatedly. Whether we succeeded in logging the user out doesn't matter at this point, we'll just wait for a manual logout/shutdown/reboot if not. So as long as the return value of `IOServiceOpen` is `kIOReturnBusy`, we keep looping.

_This is implemented in [`src/obtain.c`](TODO) with some parts residing in [`src/main.c`](TODO)._

### Triggering the bug

With access secured, we can now get to triggering our bug. It's obvious that we _can_ be lucky enough to modify `eop->evGlobalsOffset` just in the right moment - but how likely is that, and what can go wrong? There are three possible outcomes:

- We lose the race, i.e. `evg` is set to what it should be.
- We win the race, manage to offset `evg`, and `evg` now points to a data structure we placed on the heap.
- We win the race, but `evg` lands in something other than we intended.

The last case will probably cause a panic sooner (unmapped memory) or later (corruption of some data structure). Luckily I've had this happen only very rarely. Because of that, and because we cannot repair any such corruption anyway, we're just gonna focus on the other two cases. The first one is undesirable but unproblematic (we can just try again), and the second one is the one we want. Thanks to the initialisation performed by `IOHIDSystem`, we can even detect which of those happened: first the entire shared memory (with the correct address) is `bzero`'ed, and afterwards many fields are set (with the offset address), some of which hold a constant value `!= 0`. After calling the initialisation routine, we can query any such field and if it holds `0`, `evg` was offset, otherwise we failed. I chose the `version` field in my implementation.

In conclusion:

- In one thread, we just spam a value to `eop->evGlobalsOffset`.
- In another thread, we call the initialisation routine until `evg->version == 0`.

_This is implemented in [`src/exploit.c`](TODO)._

### Shmem basics

Now that we can trigger our memory corruption, what exactly can we do with it? First we'll look at how big of a corruption we can actually cause. `eop->evGlobalsOffset` is of type (signed) `int`, so we can offset `evg` by `INT_MAX` bytes in either direction. That's quite a lot.

Next we'll look at the structure's size. Since it's exposed to userland, we can just include an IOKit header and do some `sizeof`:

    // gcc -o t t.c -Wall -framework IOKit
    #include <stdio.h>
    #include <IOKit/hidsystem/IOHIDShared.h>

    int main(void)
    {
        printf("0x%lx\n", sizeof(EvOffsets) + sizeof(EvGlobals));
        return 0;
    }

On Sierra 10.12.6, that yields `0x5ae8` bytes. That's also quite a lot... in other words, we can slap one monster of a memory structure an entire two gigabytes back and forth through memory (that's what inspired the name "IOHIDeous").

Now, we know neither where this structure resides, nor where anything else of the kernel lies in respect to it. What we _do_ know however is that it is allocated via an `IOBufferMemoryDescriptor`, which ultimately goes through `kalloc`. `kalloc` passes most allocations down to `zalloc`, however this one is too large. The biggest kalloc zone on macOS is `kalloc.8192`, i.e `0x2000` bytes (in comparison, on iOS this goes up to `kalloc.32768`) - anything above that limit will go to the `kalloc_map`, or if that one is full, straight to the `kernel_map`. The nice thing about that is that there is no freelist employed, and allocations simply take place in the lowest free address gap large enough for the requested allocation. And thanks to `WindowServer`, our shared memory will almost certainly have been allocated very early, i.e. at one of the lowest addresses possible. Looking at memory pages, this means that we know next to nothing about those lying in front of our shared memory, but for those after it we can pretty much say the further away they are, the less likely they are to have been allocated. The furthest we can reach is 2GB, and if we allocate more than 2GB, we are almost guaranteed to have allocated the memory at +2GB, if it hasn't been allocated by someone else already.

So the general strategy is:

1. Make >2GB worth of allocations on the kernel heap.
2. Offset `evg` by 2GB.
3. Read or corrupt the structure we put at that offset.

Now, it turns out allocating a full 2GB takes a lot of time, and the first ca. 256MB take very little while the latter couple hundred MB take more and more time. I have found that allocating 1GB and offsetting by 768MB takes only about 25% of the time of allocating a full 2GB and still works 90% of the time. I added both variants to [`src/config.h`](TODO), with 1GB being the default and >2GB being selectable through a `-DPLAY_IT_SAFE` compiler flag.

### Reading and writing memory



### Leaking the kernel slide, the tedious way
