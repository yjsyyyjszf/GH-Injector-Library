#include "pch.h"

#include "Injection.h"
#include "Symbol Parser.h"

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hInjMod = hDll;

#ifdef _WIN64
		sym_ntdll_wow64_ret = std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_wow64, "C:\\Windows\\SysWOW64\\ntdll.dll", false);
#endif

		sym_ntdll_native_ret = std::async(std::launch::async, &SYMBOL_PARSER::Initialize, &sym_ntdll_native, "C:\\Windows\\System32\\ntdll.dll", false);
	}

#ifdef _DEBUG

	AllocConsole();

	FILE * pFile = nullptr;
	freopen_s(&pFile, "CONOUT$", "w", stdout);

#endif

	return TRUE;
}