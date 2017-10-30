// gcc -o t t.c -Wall -framework CoreFoundation -framework IOSurface
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOSurface/IOSurface.h>

int main(void)
{
    int size = 1;
    CFStringRef str = CFSTR("IOSurfaceAllocSize");
    CFNumberRef num = CFNumberCreate(NULL, kCFNumberIntType, &size);
    CFDictionaryRef props = CFDictionaryCreate(NULL, (const void**)&str, (const void**)&num, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef surface = IOSurfaceCreate(props);
    IOSurfaceSetValue(surface, CFSTR("herp"), CFSTR("derp"));
    return 0;
}
