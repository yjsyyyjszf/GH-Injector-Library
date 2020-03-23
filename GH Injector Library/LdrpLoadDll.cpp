#include "pch.h"

#include "LdrpLoadDll.h"
#pragma comment (lib, "Psapi.lib")

DWORD LdrpLoadDll_Shell(LDRP_LOAD_DLL_DATA * pData);
DWORD LdrpLoadDll_Shell_End();

DWORD _LdrpLoadDll(const wchar_t * szDllFile, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD & LastWin32Error)
{
	LDRP_LOAD_DLL_DATA data{ 0 };
	data.pModuleFileName.MaxLength = sizeof(data.Data);

	size_t size_out = 0;
	if (FAILED(StringCbLengthW(szDllFile, data.pModuleFileName.MaxLength, &size_out)))
	{
		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	if (FAILED(StringCbCopyW(ReCa<wchar_t*>(data.Data), data.pModuleFileName.MaxLength, szDllFile)))
	{
		return INJ_ERR_STRINGC_XXX_FAIL;
	}

	data.pModuleFileName.Length = (WORD)size_out;

	HINSTANCE hNTDLL = GetModuleHandleEx(hTargetProc, TEXT("ntdll.dll"));
	if (!hNTDLL)
	{
		return INJ_ERR_REMOTEMODULE_MISSING;
	}

	if (sym_ntdll_native_ret.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready)
	{
		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}

	DWORD sym_ret = sym_ntdll_native_ret.get();
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LastWin32Error = sym_ret;

		return INJ_ERR_SYMBOL_INIT_FAIL;
	}

	DWORD rva = 0;
	sym_ret = sym_ntdll_native.GetSymbolAddress("LdrpLoadDll", rva);
	if (sym_ret != SYMBOL_ERR_SUCCESS || !rva)
	{
		LastWin32Error = sym_ret;

		return INJ_ERR_SYMBOL_INIT_FAIL;
	}

	data.pLdrpLoadDll = ReCa<f_LdrpLoadDll>(ReCa<BYTE*>(hNTDLL) + rva);

	ULONG_PTR ShellSize = (ULONG_PTR)LdrpLoadDll_Shell_End - (ULONG_PTR)LdrpLoadDll_Shell;

	BYTE * pAllocBase	= ReCa<BYTE*>(VirtualAllocEx(hTargetProc, nullptr, sizeof(LDRP_LOAD_DLL_DATA) + ShellSize + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE * pArg			= pAllocBase;
	BYTE * pShell		= ReCa<BYTE*>(ALIGN_UP(ReCa<ULONG_PTR>(pArg) + sizeof(LDRP_LOAD_DLL_DATA), 0x10));

	if (!pArg)
	{
		LastWin32Error = GetLastError();

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(LDRP_LOAD_DLL_DATA), nullptr))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	if (!WriteProcessMemory(hTargetProc, pShell, LdrpLoadDll_Shell, ShellSize, nullptr))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);

		return INJ_ERR_WPM_FAIL;
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShell), pArg, Method, (Flags & INJ_THREAD_CREATE_CLOAKED) != 0, LastWin32Error, remote_ret);

	if (dwRet != SR_ERR_SUCCESS)
	{
		if (Method != LAUNCH_METHOD::LM_QueueUserAPC && !(Method == LAUNCH_METHOD::LM_HijackThread && dwRet == SR_HT_ERR_REMOTE_TIMEOUT))
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return dwRet;
	}
	else if (remote_ret != INJ_ERR_SUCCESS)
	{
		if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return remote_ret;
	}

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(LDRP_LOAD_DLL_DATA), nullptr))
	{
		LastWin32Error = GetLastError();

		if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
		{
			VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
		}

		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	if (Method != LAUNCH_METHOD::LM_QueueUserAPC)
	{
		VirtualFreeEx(hTargetProc, pAllocBase, 0, MEM_RELEASE);
	}

	hOut = data.hRet;

	return INJ_ERR_SUCCESS;
}

DWORD LdrpLoadDll_Shell(LDRP_LOAD_DLL_DATA * pData)
{
	if (!pData)
	{
		return INJ_LDRPL_ERR_NO_DATA;
	}
	else if (!pData->pLdrpLoadDll)
	{
		return INJ_LDRPL_ERR_INV_DATA;
	}

	pData->pModuleFileName.szBuffer = ReCa<wchar_t*>(pData->Data);
	pData->ntRet = pData->pLdrpLoadDll(&pData->pModuleFileName, &pData->search_path_buffer, NULL, &pData->p_entry_out);

	if (NT_FAIL(pData->ntRet) || !pData->p_entry_out)
	{
		return INJ_LDRPL_ERR_LL_FAIL;
	}

	pData->hRet = ReCa<HINSTANCE>(pData->p_entry_out->DllBase);

	return INJ_ERR_SUCCESS;
}

DWORD LdrpLoadDll_Shell_End() { return 2; }