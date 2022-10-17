
#include <Windows.h>
#include <atlstr.h>
#include <easyhook.h>
#include <string>
#include <iostream>
using namespace std;
static const DWORD DBUTIL_READ_IOCTL = 0x9B0C1EC4;
static const DWORD DBUTIL_WRITE_IOCTL = 0x9B0C1EC8;
#define IsConsoleHandle(h) (((((ULONG_PTR)h) & 0x10000003) == 0x3) ? TRUE : FALSE)
struct OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name; 
	WCHAR NameBuffer;
};

DWORD GetNtPathFromHandle(HANDLE h_File, CString* ps_NTPath)
{
	if (h_File == 0 || h_File == INVALID_HANDLE_VALUE)
		return ERROR_INVALID_HANDLE;

	if (IsConsoleHandle(h_File))
	{
		ps_NTPath->Format("\\Device\\Console%04X", (DWORD)(DWORD_PTR)h_File);
		return 0;
	}

	BYTE  u8_Buffer[2000];
	DWORD u32_ReqLength = 0;

	UNICODE_STRING* pk_Info = &((OBJECT_NAME_INFORMATION*)u8_Buffer)->Name;
	pk_Info->Buffer = 0;
	pk_Info->Length = 0;


	NtQueryObject(h_File, (OBJECT_INFORMATION_CLASS)1, u8_Buffer, sizeof(u8_Buffer), &u32_ReqLength);

	// On error pk_Info->Buffer is NULL
	if (!pk_Info->Buffer || !pk_Info->Length)
		return ERROR_FILE_NOT_FOUND;

	pk_Info->Buffer[pk_Info->Length / 2] = 0; // Length in Bytes!

	*ps_NTPath = pk_Info->Buffer;
	return 0;
}



CHAR Path[MAX_PATH];
BOOL MyDeviceIoControlHook(
	IN               HANDLE       hDevice,
	IN               DWORD        dwIoControlCode,
	IN OPTIONAL      LPVOID       lpInBuffer,
	IN               DWORD        nInBufferSize,
	OUT OPTIONAL     LPVOID       lpOutBuffer,
	IN               DWORD        nOutBufferSize,
	OUT OPTIONAL     LPDWORD      lpBytesReturned,
	IN OUT OPTIONAL  LPOVERLAPPED lpOverlapped
) {
	CString a;
	GetNtPathFromHandle(hDevice, &a);
	if ((dwIoControlCode == DBUTIL_READ_IOCTL || dwIoControlCode == DBUTIL_WRITE_IOCTL)&& a.Find("DBUtil_2_3") != -1) {
		std::cout << "Sorry bro, aint gonna happen...BYEEEEEE" << endl;
		MessageBox(NULL, dwIoControlCode == DBUTIL_READ_IOCTL ? "Found Read IOCTL for DBUtil - blocking" : "Found Write IOCTL for DBUtil - blocking","Found Usage Of malicious IOCTL" ,  MB_OK);
		exit(1);
	}



	return DeviceIoControl(
		hDevice,
		dwIoControlCode,
		lpInBuffer,
		nInBufferSize,
		lpOutBuffer,
		nOutBufferSize,
		lpBytesReturned,
		lpOverlapped);
}



extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{

	HOOK_TRACE_INFO hHook2 = { NULL }; // keep track of our hook
	
	NTSTATUS result2 = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "DeviceIoControl"),
		MyDeviceIoControlHook,
		NULL,
		&hHook2);
	if (FAILED(result2))
	{

		MessageBox(GetActiveWindow(), (LPCSTR)RtlGetLastErrorString(), (LPCSTR)L"Failed to install hook", MB_OK);
	}
	
	
	ULONG ACLEntries[1] = { 0 };
	LhSetExclusiveACL(ACLEntries, 0, &hHook2);


	return;
}
