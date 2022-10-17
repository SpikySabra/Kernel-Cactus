#pragma once

#include <ntddk.h>
#include <wdf.h>

#define DRIVER_PREFIX "MIOB: "

static const ULONG DBUTIL_READ_IOCTL = 0x9B0C1EC4;
static const ULONG DBUTIL_WRITE_IOCTL = 0x9B0C1EC8;

__declspec(dllexport) VOID Prevention(HANDLE, PIRP);
__declspec(dllexport) NTSTATUS HookedUp(PDEVICE_OBJECT, PIRP);
NTSTATUS InstallVulnerDriverHook(BOOLEAN);

__declspec(dllexport) NTSTATUS MalIOBlockCreateClose(PDEVICE_OBJECT, PIRP);