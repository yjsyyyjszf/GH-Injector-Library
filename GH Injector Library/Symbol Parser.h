#pragma once

#include "pch.h"

#include "Error.h"

class SYMBOL_PARSER
{
	HANDLE m_hProcess;

	HANDLE		m_hPdbFile;
	std::string	m_szPdbPath;
	DWORD		m_Filesize;
	DWORD64		m_SymbolTable;

	std::string m_szModulePath;

	bool m_Initialized;

public:

	SYMBOL_PARSER();
	~SYMBOL_PARSER();

	DWORD Initialize(const char * szModulePath, bool Redownload = false);
	DWORD GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut);
};

struct PdbInfo
{
	DWORD	Signature;
	GUID	Guid;
	DWORD	Age;
	char	PdbFileName[1];
};

#ifdef  _WIN64
extern SYMBOL_PARSER				sym_ntdll_wow64;
extern std::shared_future<DWORD>	sym_ntdll_wow64_ret;
#endif

extern SYMBOL_PARSER				sym_ntdll_native;
extern std::shared_future<DWORD>	sym_ntdll_native_ret;