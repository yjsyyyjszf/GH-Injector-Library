#pragma once

#include "Process Info.h"
#include "Import Handler.h"

enum class LAUNCH_METHOD
{
	LM_NtCreateThreadEx,
	LM_HijackThread,
	LM_SetWindowsHookEx,
	LM_QueueUserAPC
};
//enum which is used to select the method to execute the shellcode

enum class SR_REMOTE_STATE : ULONG_PTR
{
	SR_RS_ExecutionPending	= 0,
	SR_RS_Executing			= 1,
	SR_RS_ExecutionFinished	= 2
};
//enum which is used to determine the state of the remote code

#ifdef _WIN64
using f_Routine			= ULONG_PTR(__fastcall*)(void * pArg);
using f_Routine_WOW64	= DWORD; //ULONG_PTR(__stdcall*)(ULONG pArg);
#else
using f_Routine = ULONG_PTR(__stdcall*)(void * pArg);
#endif

#define SR_REMOTE_TIMEOUT 2000
//Routine timeout in ms

struct SR_REMOTE_DATA
{
	SR_REMOTE_STATE State;
	ULONG_PTR		Ret;
	DWORD			LastWin32Error;
	void *			pArg;
	void *			pRoutine;
	UINT_PTR		Buffer;
};

#define PTR_64_ARR 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#define PTR_86_ARR 0x00, 0x00, 0x00, 0x00,

#define SR_REMOTE_DATA_BUFFER_64 PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR
#define SR_REMOTE_DATA_BUFFER_86 PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR


DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, LAUNCH_METHOD Method, bool CloakThread, DWORD & LastWin32Error, DWORD & Out);
//Executes shellcode in the target process.
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the target process. Access rights depend on the launch method. PROCESS_ALL_ACCESS is the best option here.
//		pRoutine (f_Routine):
///			A pointer to the shellcode in the virtual memory of the target process.
//		pArg (void*):
///			A pointer to the argument which gets passed to the shellcode.
//		Method (LAUNCH_METHOD):
///			A LAUNCH_METHOD enum which defines the method to be used when executing the shellcode.
//		CloakThread (bool):
///			A boolean which is only used when the Method parameter is LM_NtCreateThreadEx. Then a few cloaking related flags get passed to NtCreateThreadEx.
//		LastWin32Error (DWORD&):
///			A reference to a DWORD which can be used to store an errorcode if something goes wrong. Otherwise it's INJ_ERROR_SUCCESS (0).
//		hOut (ULONG_PTR&):
///			A reference to a ULONG_PTR which is used to store the returned value of the shellcode. This can be changed into any datatype (a 32 bit type on x86 and a 64 bit type on x64).
//
//Returnvalue (DWORD):
///		On success: 0 (INJ_ERR_SUCCESS).
///		On failure:	An errorcode from Error.h (start routine section).

DWORD SR_NtCreateThreadEx	(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error, bool CloakThread,			DWORD & Out);
DWORD SR_HijackThread		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error,							DWORD & Out);
DWORD SR_SetWindowsHookEx	(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error, ULONG TargetSessionId,	DWORD & Out);
DWORD SR_QueueUserAPC		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error,							DWORD & Out);
//Subroutines called by StartRoutine.

#ifdef _WIN64
struct SR_REMOTE_DATA_WOW64
{
	DWORD State;
	DWORD Ret;
	DWORD LastWin32Error;
	DWORD pArg;
	DWORD pRoutine;
	DWORD Buffer;
};

#define SR_REMOTE_DATA_BUFFER_WOW64 SR_REMOTE_DATA_BUFFER_86

DWORD StartRoutine_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, LAUNCH_METHOD Method, bool CloakThread, DWORD & LastWin32Error, DWORD & Out);
//Equivalent of StartRoutine when injecting from x64 into a WOW64 process. For documentation check the comments on StartRoutine.

DWORD SR_NtCreateThreadEx_WOW64	(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error, bool CloakThread,		DWORD & Out);
DWORD SR_HijackThread_WOW64		(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error,							DWORD & Out);
DWORD SR_SetWindowsHookEx_WOW64	(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error, ULONG TargetSessionId,	DWORD & Out);
DWORD SR_QueueUserAPC_WOW64		(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error,							DWORD & Out);
#endif