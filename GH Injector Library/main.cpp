#include "pch.h"

#include "Injection.h"
#include "Symbol Parser.h"

HINSTANCE g_hInjMod = NULL;

#ifdef _WIN64
SYMBOL_PARSER				sym_ntdll_wow64;
std::shared_future<DWORD>	sym_ntdll_wow64_ret;
#endif

SYMBOL_PARSER				sym_ntdll_native;
std::shared_future<DWORD>	sym_ntdll_native_ret;

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