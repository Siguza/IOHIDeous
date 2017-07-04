typedef volatile struct _evGlobals                  // kernel   user    size    initialized to
{
    OSSpinLock      cursorSema;                     // rw       -          4    0
    int             eNum;                           // -        -          4    13
    int             buttons;                        // -        -          4    0
    int             eventFlags;                     // rw       rw         4    oldFlags
    int             VertRetraceClock;               // -        -          4    -
    IOGPoint        cursorLoc {
        SInt16          x;                          // rw       -          2    _cursorHelper...
        SInt16          y;                          // rw       -          2    _cursorHelper...
    };
    int             frame;                          // rw       r          4    -
    IOGBounds       workBounds {
        SInt16          minx;                       // -        -          2    -
        SInt16          maxx;                       // -        -          2    -
        SInt16          miny;                       // -        -          2    -
        SInt16          maxy;                       // -        -          2    -
    };
    IOGBounds       mouseRect {
        SInt16          minx;                       // r        -          2    -
        SInt16          maxx;                       // r        -          2    -
        SInt16          miny;                       // r        -          2    -
        SInt16          maxy;                       // r        -          2    -
    };
    int             version;                        // -        -          4    4
    int	            structSize;                     // -        -          4    0x5ad0
    int             lastFrame;                      // rw       -          4    3
    IOFixedPoint32  screenCursorFixed {
        int32_t         x;                          // rw       r          4    _cursorHelper...
        int32_t         y;                          // rw       r          4    _cursorHelper...
    };
    IOFixedPoint32  desktopCursorFixed {
        int32_t         x;                          // rw       -          4    _cursorHelper...
        int32_t         y;                          // rw       -          4    _cursorHelper...
    };
    unsigned int    reservedA[27];                  // -        -       24*7    -
    unsigned        reserved:25;                    // -        -               -
    unsigned        updateCursorPositionFromFixed:1;// r        -               0
    unsigned        logCursorUpdates:1;             // r        -               0
    unsigned        wantPressure:1;                 // -        -               0
    unsigned        wantPrecision:1;                // -        -               0
    unsigned        dontWantCoalesce:1;             // -        -               0
    unsigned        dontCoalesce:1;                 // -        -               0
    unsigned        mouseRectValid:1;               // rw       -               0
    int             movedMask;                      // -        -          4    0
    OSSpinLock      waitCursorSema;                 // rw       -          4    0
    int             AALastEventSent;                // -        -          4    -
    int             AALastEventConsumed;            // -        -          4    -
    int             waitCursorUp;                   // rw       -          4    -
    char            ctxtTimedOut;                   // r        -          1    -
    char            waitCursorEnabled;              // r        -          1    1
    char            globalWaitCursorEnabled;        // r        -          1    1
                    /* padding */                   // -        -          1    -
    int             waitThreshold;                  // -        -          4    74
    int             LLEHead;                        // r        -          4    1
    int             LLETail;                        // r        -          4    1
    int             LLELast;                        // -        -          4    0
    NXEQElement     lleq[240] {                     //                240*96
        int             next;                       // -        -          4    i+1
        OSSpinLock      sema;                       // -        -          4    0
        NXEvent         event {
            SInt32          type;                   // -        -          4    0
            struct          location {
                SInt32          x;                  // -        -          4    -
                SInt32          y;                  // -        -          4    -
            };
            UInt64          time ((packed));        // -        -          8    0
            SInt32          flags;                  // -        -          4    0
            UInt32          window;                 // -        -          4    -
            UInt64          service_id ((packed));  // -        -          8    -
            SInt32          ext_pid;                // -        -          4    -
            NXEventData     data;                   // -        -         48    -
        };
    };
} EvGlobals;
