#include "pch.h"

#ifdef _WIN64

#include "Injection.h"
#pragma comment (lib, "Psapi.lib")

DWORD Cloaking_WOW64(HANDLE hTargetProc, DWORD Flags, HINSTANCE hMod, DWORD & LastError);

DWORD InjectDLL_WOW64(const wchar_t * szDllFile, HANDLE hTargetProc, INJECTION_MODE im, LAUNCH_METHOD Method, DWORD Flags, DWORD & LastError, HINSTANCE & hOut)
{
	HRESULT hr = S_OK;

	if (Flags & INJ_LOAD_DLL_COPY)
	{
		size_t len_out = 0;
		hr = StringCchLengthW(szDllFile, STRSAFE_MAX_CCH, &len_out);
		if (FAILED(hr))
		{
			LastError = (DWORD)hr;

			return INJ_ERR_STRINGC_XXX_FAIL;
		}

		const wchar_t * pFileName = szDllFile;
		pFileName += len_out - 1;
		while (*(pFileName-- - 2) != '\\');
		
		wchar_t new_path[MAXPATH_IN_TCHAR]{ 0 };
		if (!GetTempPathW(MAXPATH_IN_TCHAR, new_path))
		{
			LastError = GetLastError();

			return INJ_ERR_CANT_GET_TEMP_DIR;
		}

		hr = StringCchCatW(new_path, MAXPATH_IN_TCHAR, pFileName);
		if (FAILED(hr))
		{
			LastError = (DWORD)hr;

			return INJ_ERR_STRINGC_XXX_FAIL;
		}

		if (!CopyFileW(szDllFile, new_path, FALSE))
		{
			LastError = GetLastError();

			return INJ_ERR_CANT_COPY_FILE;
		}

		szDllFile = new_path;
	}

	if (Flags & INJ_SCRAMBLE_DLL_NAME)
	{
		wchar_t new_name[15]{ 0 };
		UINT seed = rand() + Flags + LOWORD(hTargetProc);
		LARGE_INTEGER pfc{ 0 };
		QueryPerformanceCounter(&pfc);
		seed += pfc.LowPart;	
		srand(seed);

		for (UINT i = 0; i != 10; ++i)
		{
			auto val = rand() % 3;
			if (val == 0)
			{
				val = rand() % 10;
				new_name[i] = wchar_t('0' + val);
			}
			else if (val == 1)
			{
				val = rand() % 26;
				new_name[i] = wchar_t('A' + val);
			}
			else
			{
				val = rand() % 26;
				new_name[i] = wchar_t('a' + val);
			}
		}
		new_name[10] = '.';
		new_name[11] = 'd';
		new_name[12] = 'l';
		new_name[13] = 'l';
		new_name[14] = '\0';

		wchar_t OldFilePath[MAXPATH_IN_TCHAR]{ 0 };
		hr = StringCchCopyW(OldFilePath, MAXPATH_IN_TCHAR, szDllFile);
		if (FAILED(hr))
		{
			LastError = (DWORD)hr;

			return INJ_ERR_STRINGC_XXX_FAIL;
		}

		size_t len_out = 0;
		hr = StringCchLengthW(szDllFile, STRSAFE_MAX_CCH, &len_out);
		if (FAILED(hr))
		{
			LastError = (DWORD)hr;
		
			return INJ_ERR_STRINGC_XXX_FAIL;
		}

		wchar_t * pFileName = const_cast<wchar_t*>(szDllFile) + len_out;
		while (*(pFileName-- - 2) != '\\');

		memcpy(pFileName, new_name, 15 * sizeof(wchar_t));

		auto ren_ret = _wrename(OldFilePath, szDllFile);
		if (ren_ret)
		{
			LastError = (DWORD)ren_ret;

			return INJ_ERR_CANT_RENAME_FILE;
		}
	}

	DWORD Ret = 0;

	switch (im)
	{
		case INJECTION_MODE::IM_LoadLibraryExW:
			Ret = _LoadLibrary_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, LastError);
			break;

		case INJECTION_MODE::IM_LdrLoadDll:
			Ret = _LdrLoadDll_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, LastError);
			break;

		case INJECTION_MODE::IM_LdrpLoadDll:
			Ret = _LdrpLoadDll_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, LastError);
			break;

		case INJECTION_MODE::IM_ManualMap:
			Ret = _ManualMap_WOW64(szDllFile, hTargetProc, Method, Flags, hOut, LastError);
			break;

		default:
			Ret = INJ_ERR_INVALID_INJ_METHOD;
			break;
	}

	if (Ret != INJ_ERR_SUCCESS)
	{
		return Ret;
	}

	if (!hOut)
	{
		return INJ_ERR_REMOTE_CODE_FAILED;
	}

	if (im != INJECTION_MODE::IM_ManualMap)
	{
		Ret = Cloaking_WOW64(hTargetProc, Flags, hOut, LastError);
	}
	
	return Ret;
}

DWORD Cloaking_WOW64(HANDLE hTargetProc, DWORD Flags, HINSTANCE hMod, DWORD & LastError)
{
	if (!Flags) 
	{
		return INJ_ERR_SUCCESS;
	}

	if (Flags & INJ_ERASE_HEADER)
	{
		BYTE Buffer[0x1000]{ 0 };
		DWORD dwOld = 0; 
		BOOL bRet = VirtualProtectEx(hTargetProc, hMod, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
		if (!bRet)
		{
			LastError = GetLastError();

			return INJ_ERR_VPE_FAIL;
		}

		bRet = WriteProcessMemory(hTargetProc, hMod, Buffer, 0x1000, nullptr);
		if (!bRet)
		{
			LastError = GetLastError();

			return INJ_ERR_WPM_FAIL;
		}
	}
	else if (Flags & INJ_FAKE_HEADER)
	{
		void * pK32 = ReCa<void*>(GetModuleHandleEx_WOW64(hTargetProc, TEXT("kernel32.dll")));
		DWORD dwOld = 0;

		BYTE buffer[0x1000];
		BOOL bRet = ReadProcessMemory(hTargetProc, pK32, buffer, 0x1000, nullptr);
		if (!bRet)
		{
			LastError = GetLastError();

			return INJ_ERR_RPM_FAIL;
		}

		bRet = VirtualProtectEx(hTargetProc, hMod, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
		if (!bRet)
		{
			LastError = GetLastError();

			return INJ_ERR_VPE_FAIL;
		}

		bRet = WriteProcessMemory(hTargetProc, hMod, buffer, 0x1000, nullptr);
		if (!bRet)
		{
			LastError = GetLastError();

			return INJ_ERR_WPM_FAIL;
		}

		bRet = VirtualProtectEx(hTargetProc, hMod, 0x1000, dwOld, &dwOld);
		if (!bRet)
		{
			LastError = GetLastError();

			return INJ_ERR_VPE_FAIL;
		}
	}

	if (Flags & INJ_UNLINK_FROM_PEB)
	{
		ProcessInfo PI;
		PI.SetProcess(hTargetProc);

		LDR_DATA_TABLE_ENTRY32 * pEntry = PI.GetLdrEntry_WOW64(hMod);
		if (!pEntry)
		{
			return INJ_ERR_CANT_FIND_MOD_PEB;
		}

		LDR_DATA_TABLE_ENTRY32 Entry{ 0 };
		if (!ReadProcessMemory(hTargetProc, pEntry, &Entry, sizeof(Entry), nullptr))
		{
			return INJ_ERR_CANT_ACCESS_PEB_LDR;
		}
		
		auto Unlink = [=](LIST_ENTRY32 entry)
		{
			LIST_ENTRY32 list;
			if (ReadProcessMemory(hTargetProc, MPTR(entry.Flink), &list, sizeof(LIST_ENTRY32), nullptr))
			{
				list.Blink = entry.Blink;
				WriteProcessMemory(hTargetProc, MPTR(entry.Flink), &list, sizeof(LIST_ENTRY32), nullptr);
			}

			if (ReadProcessMemory(hTargetProc, MPTR(entry.Blink), &list, sizeof(LIST_ENTRY32), nullptr))
			{
				list.Flink = entry.Flink;
				WriteProcessMemory(hTargetProc, MPTR(entry.Blink), &list, sizeof(LIST_ENTRY32), nullptr);
			}
		};
		
		Unlink(Entry.InLoadOrderLinks);
		Unlink(Entry.InMemoryOrderLinks);
		Unlink(Entry.InInitializationOrderLinks);
		Unlink(Entry.HashLinks);

		WORD MaxLength_Full = Entry.FullDllName.MaxLength;
		WORD MaxLength_Base = Entry.BaseDllName.MaxLength;
		char * Buffer_Full = new char[MaxLength_Full];
		char * Buffer_Base = new char[MaxLength_Base];
		memset(Buffer_Full, 0, MaxLength_Full);
		memset(Buffer_Base, 0, MaxLength_Base);
		WriteProcessMemory(hTargetProc, MPTR(Entry.FullDllName.szBuffer), Buffer_Full, MaxLength_Full, nullptr);
		WriteProcessMemory(hTargetProc, MPTR(Entry.BaseDllName.szBuffer), Buffer_Base, MaxLength_Base, nullptr);
		delete[] Buffer_Full;
		delete[] Buffer_Base;

		LDR_DATA_TABLE_ENTRY32 entry_new{ 0 };
		WriteProcessMemory(hTargetProc, pEntry, &entry_new, sizeof(entry_new), nullptr);

		//todo LdrpModuleBaseAddressIndex (cancer)
	}
	
	return INJ_ERR_SUCCESS;
}

#endif