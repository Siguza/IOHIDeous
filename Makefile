TARGET  = hid
HELPER  = helper
LEAK    = leak
POC     = poc
SRCDIR  = src
MIGDIR  = mig
OSFMK  ?= /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include
CFLAGS ?= -O3 -Wall

.PHONY: all clean fullclean

all: $(TARGET) $(LEAK) $(POC)

$(TARGET): $(SRCDIR)/$(TARGET)/*.c $(SRCDIR)/$(HELPER)/$(HELPER)_bin.c $(MIGDIR)/iokitUser.c
	$(CC) -o $@ $^ $(CFLAGS) -DIOKIT=1 -framework IOKit -framework CoreFoundation -I$(MIGDIR)

$(SRCDIR)/$(HELPER)/$(HELPER)_bin.c: $(SRCDIR)/$(HELPER)/$(HELPER)
	cd $(SRCDIR)/$(HELPER) && xxd -i $(HELPER) > $(HELPER)_bin.c

$(SRCDIR)/$(HELPER)/$(HELPER): $(SRCDIR)/$(HELPER)/$(HELPER).c
	$(CC) -o $@ $^ $(CFLAGS)

$(MIGDIR)/iokitUser.c: | $(MIGDIR)
	cd $(MIGDIR) && mig -arch x86_64 -DIOKIT=1 $(OSFMK)/device/device.defs

$(MIGDIR):
	mkdir $(MIGDIR)

$(LEAK): $(SRCDIR)/$(LEAK)/*.c
	$(CC) -o $@ $^ $(CFLAGS) -framework IOKit -framework CoreFoundation

$(POC): $(SRCDIR)/$(POC)/*.c
	$(CC) -o $@ $^ $(CFLAGS) -framework IOKit

clean:
	rm -f $(TARGET) $(LEAK) $(POC) $(SRCDIR)/$(HELPER)/$(HELPER) $(SRCDIR)/$(HELPER)/$(HELPER)_bin.c

fullclean: clean
	rm -rf $(MIGDIR)
