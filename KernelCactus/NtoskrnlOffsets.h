#define NO_STRINGS 0

#if NO_STRINGS
#define _putts_or_not(...)
#define _tprintf_or_not(...)
#define wprintf_or_not(...)
#define printf_or_not(...)
#pragma warning(disable : 4189)

#else
#define _putts_or_not(...) _putts(__VA_ARGS__)
#define _tprintf_or_not(...) _tprintf(__VA_ARGS__)
#define printf_or_not(...) printf(__VA_ARGS__)
#define wprintf_or_not(...) wprintf(__VA_ARGS__)
#endif

#include <Windows.h>
#include <winver.h>
#include <iostream>


#define _SUPPORTED_NTOSKRNL_OFFSETS_END 14


union NtoskrnlOffsets {
    // structure version of ntoskrnl.exe's offsets
    struct {
        DWORD64 ActiveProcessLinks;
        
        DWORD64 UniqueProcessId;
        
        DWORD64 ThreadListHead;
        
        DWORD64 Protection;
        
        DWORD64 Token;
        
        DWORD64 ObjectTable;
        
        DWORD64 TrapFrame;
        
        DWORD64 Rip;
        
        DWORD64 ThreadListEntry;
        
        DWORD64 Cid;

        DWORD64 EtwThreatIntProvRegHandle;

        DWORD64 GuidEntry;

        DWORD64 EnableInfo;

        DWORD64 Guid;
    } st;

    // array version (usefull for code factoring)
    DWORD64 ar[_SUPPORTED_NTOSKRNL_OFFSETS_END];
};

NtoskrnlOffsets LoadNtoskrnlOffsetsFromFile(const TCHAR* ntoskrnlOffsetFilename);

class NtoskrnlOffsetsBuild
{

public:
    DWORD64 ActiveProcessLinks;

    DWORD64 UniqueProcessId;

    DWORD64 ThreadListHead;

    DWORD64 Protection;

    DWORD64 Token;

    DWORD64 ObjectTable;

    DWORD64 TrapFrame;

    DWORD64 Rip;

    DWORD64 ThreadListEntry;

    DWORD64 Cid;

    DWORD64 EtwThreatIntProvRegHandle;

    DWORD64 GuidEntry;

    DWORD64 EnableInfo;

    DWORD64 Guid;

    NtoskrnlOffsetsBuild() {
        g_ntoskrnlOffsets = LoadNtoskrnlOffsetsFromFile(TEXT("NtoskrnlCSV.csv"));
        Guid = g_ntoskrnlOffsets.st.Guid;
        EnableInfo = g_ntoskrnlOffsets.st.EnableInfo;
        GuidEntry = g_ntoskrnlOffsets.st.GuidEntry;
        EtwThreatIntProvRegHandle = g_ntoskrnlOffsets.st.EtwThreatIntProvRegHandle;
        Cid = g_ntoskrnlOffsets.st.Cid;
        ThreadListEntry = g_ntoskrnlOffsets.st.ThreadListEntry;
        Rip = g_ntoskrnlOffsets.st.Rip;
        TrapFrame = g_ntoskrnlOffsets.st.TrapFrame;
        ObjectTable = g_ntoskrnlOffsets.st.ObjectTable;
        Token = g_ntoskrnlOffsets.st.Token;
        Protection = g_ntoskrnlOffsets.st.Protection;
        ThreadListHead = g_ntoskrnlOffsets.st.ThreadListHead;
        UniqueProcessId = g_ntoskrnlOffsets.st.UniqueProcessId;
        ActiveProcessLinks = g_ntoskrnlOffsets.st.ActiveProcessLinks;
    }
private:
    NtoskrnlOffsets g_ntoskrnlOffsets;

};




