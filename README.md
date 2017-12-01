# IOHIDeous

A macOS kernel exploit based on an IOHIDFamily 0day.

Write-up [here](docs/index.md).

### Usage

The exploit consists of three parts:

- `poc` panics the kernel to demonstrate the present of a memory corruption, should work on all macOS versions.
- `leak` leaks the kernel slide, could be adapted to other versions but as-is works only on High Sierra.
- `hid` achieves full kernel r/w, tested only on Sierra and High Sierra, might work on earlier versions too.

`poc` and `leak` need to be run as the user that is currently logged in via the GUI, and they log you out in order to perform the exploit. `hid` on the other hand, gives you four options for a first argument:

- `steal` requires to be run as root and SIP to be disabled, but leaves you logged in the entire time.
- `kill` requires root and forces a dirty logout by killing `WindowServer`.
- `logout` if executed as root or the currently logged in user, logs you out via `launchctl`. Otherwise tries to log you out via AppleScript, and then falls back to `wait`.
- `wait` simply waits for a logout, shutdown or reboot to occur.

Additionally you can specify a second argument `persist`. If given, `hid` will permanently disable SIP and AMFI, and install a root shell in `/System/pwned`.

`leak` and `hid` should be run either via SSH or from a `screen` session, if you wish to observe their output.

### Building

Should all be self-explanatory:

    make all
    make poc
    make leak
    make hid
    make clean
