#include <tchar.h>
#include <iostream>
#include <string>
#include <Windows.h>
#include <WinNT.h>
#include <easyhook.h>
#include <TlHelp32.h>
#include <map>
using namespace std;
#define RESULT_MAXIMUMLENGTH (511)

typedef struct _MYRESULT {
	WCHAR Result[RESULT_MAXIMUMLENGTH + 1];
} MYRESULT;
typedef map<int, bool> MapType;
bool AlreadyInjected = false;
map<int, bool> myMap;



int _tmain(int argc, _TCHAR* argv[])
{

	WCHAR* dllToInject = argv[1];


	while (true) {
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 processEntry = {};
		processEntry.dwSize = sizeof(PROCESSENTRY32);
		LPCWSTR processName = L"";

		Process32First(snapshot, &processEntry);
		myMap.insert({ processEntry.th32ProcessID, false });

		while (Process32Next(snapshot, &processEntry)) {


			MapType::iterator lb = myMap.lower_bound(processEntry.th32ProcessID);

			if (lb != myMap.end() && !(myMap.key_comp()(processEntry.th32ProcessID, lb->first)))
			{
			}
			else
			{
				myMap.insert(lb, MapType::value_type(processEntry.th32ProcessID, false));

			}

			wstring processwString(processName);
			string processString(processwString.begin(), processwString.end());

			if (!wcscmp(processEntry.szExeFile, L"POC.exe") && myMap[processEntry.th32ProcessID] == false) {

				cout << "found target process-  " << processString << endl;
				HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, false, processEntry.th32ProcessID);
				if (p == NULL) {
					cout << "cant get handle" << endl;
					myMap[processEntry.th32ProcessID] = true;

					for (int i = 0; i < 3; i++)
					{
						cout << "Retry " << i << "... " << endl;
						HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, false, processEntry.th32ProcessID);
						if (p != NULL) break;
						else continue;
					}
				}
				DWORD returnCode;
				GetExitCodeProcess(p, &returnCode);
				if (returnCode == STILL_ACTIVE && p != NULL) {
					Sleep(1);
					NTSTATUS nt = RhInjectLibrary(
						processEntry.th32ProcessID,
						0,
						EASYHOOK_INJECT_DEFAULT,
						NULL,
						dllToInject,
						NULL,
						0
					);

					if (nt != 0)
					{
						printf("RhInjectLibrary failed with error code = %d\n", nt);
						PWCHAR err = RtlGetLastErrorString();
						std::wcout << err << "\n";
						myMap[processEntry.th32ProcessID] = true;

					}
					else
					{
						std::wcout << L"Library injected successfully.\n";
						myMap[processEntry.th32ProcessID] = true;

					}
				}

			}
		}

	}

	return 0;
}
