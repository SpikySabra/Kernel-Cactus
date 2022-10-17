// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#define _ARM64_
#include "../../../../../Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/shared/minwindef.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

