#include <tchar.h>
#include <stdio.h>

#include "NtoskrnlOffsets.h"


NtoskrnlOffsets LoadNtoskrnlOffsetsFromFile(const TCHAR* ntoskrnlOffsetFilename) {

    NtoskrnlOffsets g_ntoskrnlOffsets = { 0 };

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, ntoskrnlOffsetFilename, L"r");

    if (offsetFileStream == NULL) {
        _putts_or_not(L"[!] Offset CSV file connot be opened");
        exit(1);
    }

    TCHAR smark[256];
    TCHAR line[2048];
    while (_fgetts(line, _countof(line), offsetFileStream)) {
        TCHAR* dupline = _tcsdup(line);
        TCHAR* tmpBuffer = NULL;
        _tcscpy_s(smark, _countof(smark), _tcstok_s(dupline, L",", &tmpBuffer));
        if (_tcscmp(TEXT("SOF"), smark) == 0) {
            TCHAR* endptr;
            for (int i = 0; i < _SUPPORTED_NTOSKRNL_OFFSETS_END; i++) {
                g_ntoskrnlOffsets.ar[i] = _tcstoull(_tcstok_s(NULL, L",", &tmpBuffer), &endptr, 16);
            }
            break;
        }
    }

    fclose(offsetFileStream);

    return g_ntoskrnlOffsets;
}

