#pragma once

/// ###############	##########		##########		     #######	   ##########			###			###
/// ###############	############	############	  ####     ####    ############			###			###
/// ###				###        ###	###        ###	 ###         ###   ###        ###		###			###
/// ###				###        ###	###        ###	###           ###  ###        ###		###			###
/// ###				###       ###	###       ###	###           ###  ###       ###		###			###
/// ###############	###########		###########		###           ###  ###########			###############
/// ###############	###########		########### 	###			  ###  ###########			###############
/// ###				###      ###	###		###     ###			  ###  ###		###			###			###
/// ###				###		  ###	###		  ###	###           ###  ###		  ###		###			###
/// ###				###		   ###	###		   ###	 ###         ###   ###		   ###	 #	###			###
/// ###############	###		   ###	###		   ###	  ####     ####    ###		   ###  ###	###			###
/// ###############	###        ###	###        ###	     #######	   ###         ###   #	###			###

//Injection errors:
#define INJ_ERR_SUCCESS					0x00000000
													
													//Source							:	error description

#define INJ_ERR_INVALID_PROC_HANDLE		0x00000001	//GetHandleInformation				:	win32 error
#define INJ_ERR_FILE_DOESNT_EXIST		0x00000002	//GetFileAttributesW				:	win32 error
#define INJ_ERR_OUT_OF_MEMORY_EXT		0x00000003	//VirtualAllocEx					:	win32 error
#define INJ_ERR_OUT_OF_MEMORY_INT		0x00000004	//VirtualAlloc						:	win32 error
#define INJ_ERR_IMAGE_CANT_RELOC		0x00000005	//internal error					:	base relocation directory empty
#define INJ_ERR_LDRLOADDLL_MISSING		0x00000006	//GetProcAddressEx					:	can't find pointer to LdrLoadDll
#define INJ_ERR_REMOTEFUNC_MISSING		0x00000007	//LoadFunctionPointer				:	can't find remote function
#define INJ_ERR_CANT_FIND_MOD_PEB		0x00000008	//internal error					:	module not linked to PEB
#define INJ_ERR_WPM_FAIL				0x00000009	//WriteProcessMemory				:	win32 error
#define INJ_ERR_CANT_ACCESS_PEB			0x0000000A	//ReadProcessMemory					:	win32 error
#define INJ_ERR_CANT_ACCESS_PEB_LDR		0x0000000B	//ReadProcessMemory					:	win32 error
#define INJ_ERR_VPE_FAIL				0x0000000C	//VirtualProtectEx					:	win32 error
#define INJ_ERR_CT32S_FAIL				0x0000000D	//CreateToolhelp32Snapshot			:	win32 error
#define	INJ_ERR_RPM_FAIL				0x0000000E	//ReadProcessMemory					:	win32 error
#define INJ_ERR_INVALID_PID				0x0000000F	//internal error					:	process id is 0
#define INJ_ERR_INVALID_FILEPATH		0x00000010	//internal error					:	INJECTIONDATA::szDllPath is nullptr
#define INJ_ERR_CANT_OPEN_PROCESS		0x00000011	//OpenProcess						:	win32 error
#define INJ_ERR_PLATFORM_MISMATCH		0x00000012	//internal error					:	file error (0x20000001 - 0x20000003, check below)
#define INJ_ERR_NO_HANDLES				0x00000013	//internal error					:	no process handle to hijack
#define INJ_ERR_HIJACK_NO_NATIVE_HANDLE	0x00000014	//internal error					:	no compatible process handle to hijack
#define INJ_ERR_HIJACK_INJ_FAILED		0x00000015	//internal error					:	injecting injection module into handle owner process failed, additional errolog(s) created
#define INJ_ERR_HIJACK_CANT_ALLOC		0x00000016	//VirtualAllocEx					:	win32 error
#define INJ_ERR_HIJACK_CANT_WPM			0x00000017	//WriteProcessMemory				:	win32 error
#define INJ_ERR_HIJACK_INJMOD_MISSING	0x00000018	//internal error					:	can't find remote injection module
#define INJ_ERR_HIJACK_INJECTW_MISSING	0x00000019	//internal error					:	can't find remote injection function
#define INJ_ERR_GET_MODULE_HANDLE_FAIL	0x0000001A	//GetModuleHandleA					:	win32 error
#define INJ_ERR_OUT_OF_MEMORY_NEW		0x0000001B	//operator new						:	internal memory allocation failed
#define INJ_ERR_REMOTE_CODE_FAILED		0x0000001C	//internal error					:	the remote code wasn't able to load the module
#define INJ_ERR_INVALID_INJ_METHOD		0x0000001D	//bruh moment						:	bruh moment
#define INJ_ERR_STRINGC_XXX_FAIL		0x0000001E	//StringCXXX failed					:	HRESULT
#define INJ_ERR_VERIFY_RESULT_FAIL		0x0000001F	//ReadProcessMemory					:	win32 error
#define INJ_ERR_CANT_RENAME_FILE		0x00000020	//_wrename							:	scrambling the filename failed
#define INJ_ERR_CANT_SET_PAGE_PROT		0x00000021	//VirtualProtectEx					:	win32 error
#define INJ_ERR_REMOTEMODULE_MISSING	0x00000022	//GetModuleHandleEx(WOW64)			:	can't find remote function
#define INJ_ERR_CANT_ALLOC_MEM_FOR_LDR	0x00000023	//VirtualAllocEx					:	win32 error (can't allocate memory for LDR_DATA_TABLE_ENTRY(32))
#define INJ_ERR_SYMBOL_INIT_NOT_DONE	0x00000024	//SYMBOL_PARSER::Initialize			:	initializations process of the symbol parser isn't finished
#define INJ_ERR_SYMBOL_INIT_FAIL		0x00000025	//SYMBOL_PARSER::Initialize			:	initialization failed, last win32 error is SYM_ERR_XXX code
#define INJ_ERR_SYMBOL_GET_FAIL			0x00000026	//SYMBOL_PARSER::GetSymbolAddress	:	couldn't get address of required symbol, last win32 error is SYM_ERR_XXX code
#define INJ_ERR_CONVERSION_TO_WCHAR		0x00000027	//mbstowcs_s						:	ansi to unicode conversion failed
#define INJ_ERR_CANT_GET_TEMP_DIR		0x00000028	//GetTempPathW						:	win32 error
#define INJ_ERR_CANT_COPY_FILE			0x00000029	//CopyFileW							:	win32 error
#define INJ_ERR_LOAD_CONFIG_EMPTY		0x0000002A	//internal error					:	load config directory is emtpy

///////////////////
///LoadLibraryExW
											//Source				:	error description

#define INJ_LLEXW_ERR_NO_DATA	0x00100001	//LoadLibraryExW_Shell	:	pData is NULL
#define INJ_LLEXW_ERR_INV_DATA	0x00100002	//LoadLibraryExW_Shell	:	pData is invalid
#define INJ_LLEXW_ERR_LL_FAIL	0x00100003	//LoadLibraryExW_Shell	:	pData->pLoadLibraryExW returned NULL

///////////////////
///LdrLoadDll
											//Source			:	error description

#define INJ_LLDLL_ERR_NO_DATA	0x00200001	//LdrLoadDll_Shell	:	pData is NULL
#define INJ_LLDLL_ERR_INV_DATA	0x00200002	//LdrLoadDll_Shell	:	pData is invalid
#define INJ_LLDLL_ERR_LL_FAIL	0x00200003	//LdrLoadDll_Shell	:	pData->pLdrLoadDll failed

///////////////////
///LdrpLoadDll
											//Source			:	error description

#define INJ_LDRPL_ERR_NO_DATA	0x00300001	//LdrpLoadDll_Shell	:	pData is NULL
#define INJ_LDRPL_ERR_INV_DATA	0x00300002	//LdrpLoadDll_Shell	:	pData is invalid
#define INJ_LDRPL_ERR_LL_FAIL	0x00300003	//LdrpLoadDll_Shell	:	pData->pLdrpLoadDll failed

///////////////////
///ManualMap
													//Source				:	error description

#define INJ_MM_ERR_NO_DATA				0x00400001	//ManualMapping_Shell	:	pData is NULL
#define INJ_MM_LOADLIBRARYA_MISSING		0x00400002	//ManualMapping_Shell	:	can't resolve imports because pLoadLibraryA is NULL
#define INJ_MM_GETMODULEHANDLEA_MISSING	0x00400003	//ManualMapping_Shell	:	can't resolve imports because pGetModuleHandleA is NULL
#define INJ_MM_GETPROCADDRESS_MISSING	0x00400004	//ManualMapping_Shell	:	can't resolve imports because pGetProcAddress is NULL
#define INJ_MM_CANT_LOAD_MODULE			0x00400005	//ManualMapping_Shell	:	can't load required module (GetModuleHandleA and LoadLibraryA returned NULL)
#define INJ_MM_CANT_GET_IMPORT			0x00400006	//ManualMapping_Shell	:	can't load required import (GetProcAddress returned NULL)
#define INJ_MM_CANT_LOAD_DELAY_MODULE	0x00400007	//ManualMapping_Shell	:	can't load required delayed module (GetModuleHandleA and LoadLibraryA returned NULL)
#define INJ_MM_CANT_GET_DELAY_IMPORT	0x00400008	//ManualMapping_Shell	:	can't load required delayed import (GetProcAddress returned NULL)
#define INJ_MM_KERNEL32_POINTER_MISSING	0x00400009	//ManualMapping_Shell	:	can't fake PE header since kernel32.dll reference is missing
#define INJ_MM_FUNCTION_TABLE_MISSING	0x0040000A	//ManualMapping_Shell	:	function to enable exceptions handlers is missing (NULL)
#define INJ_MM_ENABLING_SEH_FAILED		0x0040000B	//ManualMapping_Shell	:	function to enable exceptions handlers failed
#define INJ_MM_VIRTUALALLOC_MISSING		0x0040000C	//ManualMapping_Shell	:	can't initialize static TLS because pVirtualAlloc is NULL
#define INJ_MM_VIRTUALALLOC_FAIL		0x0040000D	//ManualMapping_Shell	:	can't initialize static TLS because VirtualAlloc failed


/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//Start Routine errors:
#define SR_ERR_SUCCESS					0x00000000
													
													//Source					:	error description

#define SR_ERR_CANT_QUERY_SESSION_ID	0x00000001	//NtQueryInformationProcess	:	NTSTATUS
#define SR_ERR_INVALID_LAUNCH_METHOD	0x10000002	//bruh moment				:	bruh moment
#define SR_ERR_NOT_LOCAL_SYSTEM			0x10000003	//internal error			:	SetWindowsHookEx with handle hijacking only works within the same session or from session 0 (LocalSystem account) because of the WtsAPIs


///////////////////
///NtCreateThreadEx
														//Source					:	error description

#define SR_NTCTE_ERR_NTCTE_MISSING			0x10100001	//GetProcAddress			:	win32 error
#define SR_NTCTE_ERR_CANT_ALLOC_MEM			0x10100002	//VirtualAllocEx			:	win32 error
#define SR_NTCTE_ERR_WPM_FAIL				0x10100003	//WriteProcessMemory		:	win32 error
#define SR_NTCTE_ERR_NTCTE_FAIL				0x10100004	//NtCreateThreadEx			:	NTSTATUS
#define SR_NTCTE_ERR_GET_CONTEXT_FAIL		0x10100005	//(Wow64)GetThreadContext	:	win32 error
#define SR_NTCTE_ERR_SET_CONTEXT_FAIL		0x10100006	//(Wow64)SetThreadContext	:	win32 error
#define SR_NTCTE_ERR_RESUME_FAIL			0x10100007	//ResumeThread				:	win32 error
#define SR_NTCTE_ERR_RPM_FAIL				0x10100008	//ReadProcessMemory			:	win32 error
#define SR_NTCTE_ERR_REMOTE_TIMEOUT			0x10100009	//WaitForSingleObject		:	win32 error
#define SR_NTCTE_ERR_GECT_FAIL				0x1010000A	//GetExitCodeThread			:	win32 error
#define SR_NTCTE_ERR_GET_MODULE_HANDLE_FAIL	0x1010000B	//GetModuleHandle			:	win32 error
#define SR_NTCTE_ERR_SHELLCODE_SETUP_FAIL	0x1010000C	//shellcode argument is 0	:	

///////////////
///HijackThread
														//Source					:	error description

#define SR_HT_ERR_PROC_INFO_FAIL			0x10200001	//internal error			:	can't grab process information
#define SR_HT_ERR_NO_THREADS				0x10200002	//internal error			:	no thread to hijack
#define SR_HT_ERR_OPEN_THREAD_FAIL			0x10200003	//OpenThread				:	win32 error
#define SR_HT_ERR_CANT_ALLOC_MEM			0x10200004	//VirtualAllocEx			:	win32 error
#define SR_HT_ERR_SUSPEND_FAIL				0x10200005	//SuspendThread				:	win32 error
#define SR_HT_ERR_GET_CONTEXT_FAIL			0x10200006	//(Wow64)GetThreadContext	:	win32 error
#define SR_HT_ERR_WPM_FAIL					0x10200007	//WriteProcessMemory		:	win32 error
#define SR_HT_ERR_MAMBDA_IS_NOOB			0x10200008	//NtStupidNoobFunction		:	NTSTATUS
#define SR_HT_ERR_SET_CONTEXT_FAIL			0x10200009	//(Wow64)SetThreadContext	:	win32 error
#define SR_HT_ERR_RESUME_FAIL				0x1020000A	//ResumeThread				:	win32 error
#define SR_HT_ERR_REMOTE_TIMEOUT			0x1020000B	//internal error			:	execution time exceeded SR_REMOTE_TIMEOUT (can't be deallocated safely)
#define SR_HT_ERR_REMOTE_PENDING_TIMEOUT	0x1020000C	//internal error			:	execution time exceeded SR_REMOTE_TIMEOUT while pending (can be deallocated safely)

////////////////////
///SetWindowsHookEx
														//Source				:	error description

#define SR_SWHEX_ERR_CANT_QUERY_INFO_PATH	0x10300001	//internal error		:	can't resolve own module filepath
#define SR_SWHEX_ERR_CANT_OPEN_INFO_TXT		0x10300002	//internal error		:	can't open swhex info file
#define SR_SWHEX_ERR_VAE_FAIL				0x10300003	//VirtualAllocEx		:	win32 error
#define SR_SWHEX_ERR_CNHEX_MISSING			0x10300004	//GetProcAddressEx		:	can't find pointer to CallNextHookEx
#define SR_SWHEX_ERR_WPM_FAIL				0x10300005	//WriteProcessMemory	:	win32 error
#define SR_SWHEX_ERR_WTSQUERY_FAIL			0x10300006	//WTSQueryUserToken		:	win32 error
#define SR_SWHEX_ERR_DUP_TOKEN_FAIL			0x10300007	//DuplicateTokenEx		:	win32 error
#define SR_SWHEX_ERR_GET_ADMIN_TOKEN_FAIL	0x10300008	//GetTokenInformation	:	win32 error
#define SR_SWHEX_ERR_CANT_CREATE_PROCESS	0x10300009	//CreateProcessAsUserW	:	win32 error
														//CreateProcessW		:	win32 error
#define SR_SWHEX_ERR_SWHEX_TIMEOUT			0x1030000A	//WaitForSingleObject	:	win32 error
#define SR_SWHEX_ERR_SWHEX_EXT_ERROR		0x1030000B	//SM_EXE_FILENAME.exe	:	"GH Injector SM - XX.exe" error code, 0x30100001 - 0x30100006 (see below) or win32 exception
#define SR_SWHEX_ERR_REMOTE_TIMEOUT			0x1030000C	//internal error		:	execution time exceeded SR_REMOTE_TIMEOUT

///////////////
///QueueUserAPC
														//Source					:	error description

#define SR_QUAPC_ERR_RTLQAW64_MISSING		0x10400001	//GetProcAddress			:	win32 error
#define SR_QUAPC_ERR_CANT_ALLOC_MEM			0x10400001	//VirtualAllocEx			:	win32 error
#define SR_QUAPC_ERR_WPM_FAIL				0x10400002	//WriteProcessMemory		:	win32 error
#define SR_QUAPC_ERR_TH32_FAIL				0x10400003	//CreateToolhelp32Snapshot	:	win32 error
#define SR_QUAPC_ERR_T32FIRST_FAIL			0x10400004	//Thread32First				:	win32 error
#define SR_QUAPC_ERR_NO_APC_THREAD			0x10400005	//QueueUserAPC				:	no alertable (non worker) thread available
#define SR_QUAPC_ERR_REMOTE_TIMEOUT			0x10400006	//internal error			:	execution time exceeded SR_REMOTE_TIMEOUT
#define SR_QUAPC_ERR_RPM_TIMEOUT_FAIL		0x10400007	//ReadProcessMemory			:	win32 error
#define SR_QUAPC_ERR_GET_MODULE_HANDLE_FAIL	0x10100008	//GetModuleHandle			:	win32 error



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//File errors:
#define FILE_ERR_SUCCESS			0x00000000

												//Source				:	error description
#define FILE_ERR_CANT_OPEN_FILE		0x20000001	//std::ifstream::good	:	openening the file failed
#define FILE_ERR_INVALID_FILE_SIZE	0x20000002	//internal error		:	file isn't a valid PE
#define FILE_ERR_INVALID_FILE		0x20000003	//internal error		:	PE isn't compatible with the injection settings



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//GH Injector SM - XX.exe errors:

												//Source	:	error description

#define SM_ERR_INVALID_ARGC	0x30000001			//main		:	GH Injector SM - XX.exe was called with the wrong amount of arguments
#define SM_ERR_INVALID_ARGV	0x30000002			//main		:	GH Injector SM - XX.exe was called with invalid arguments

////////////////////////////////////////////////////////////
///GH Injector SM - XX.exe - SetWindowsHookEx specific erros:
#define SWHEX_ERR_SUCCESS			0x00000000

												//Source				:	error description

#define SWHEX_ERR_INVALID_PATH		0x30100001	//StringCchLengthW		:	path exceeds MAX_PATH * 2 chars
#define SWHEX_ERR_CANT_OPEN_FILE	0x30100002	//std::ifstream::good	:	openening the SMXX.txt failed
#define SWHEX_ERR_EMPTY_FILE		0x30100003	//internal error		:	SMXX.txt is empty
#define SWHEX_ERR_INVALID_INFO		0x30100004	//internal error		:	provided info is wrong / invalid
#define SWHEX_ERR_ENUM_WINDOWS_FAIL 0x30100005	//EnumWindows			:	API fail
#define SWHEX_ERR_NO_WINDOWS		0x30100006	//internal error		:	no compatible window found



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//Symbol errors:
#define SYMBOL_ERR_SUCCESS						0x00000000

															//Source				:	error description
#define SYMBOL_ERR_CANT_OPEN_MODULE				0x40000001	//std::ifstream::good	:	can't open the specified module
#define SYMBOL_ERR_FILE_SIZE_IS_NULL			0x40000002	//std::ifstream::tellg	:	file size of the specified module is 0
#define SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW		0x40000003	//operator new			:	can't allocate memory
#define SYMBOL_ERR_INVALID_FILE_ARCHITECTURE	0x40000004	//internal error		:	the architecture of the specified file doesn't match AMD64 or I386
#define SYMBOL_ERR_CANT_ALLOC_MEMORY			0x40000005	//VirtualAlloc			:	can't allocate memory
#define SYMBOL_ERR_NO_PDB_DEBUG_DATA			0x40000006	//internal error		:	debuge directory is emtpy or wrong type
#define SYMBOL_ERR_CANT_GET_TEMP_PATH			0x40000007	//GetTempPathA			:	can't get path to the temp directory
#define SYMBOL_ERR_CANT_CONVERT_PDB_GUID		0x40000008	//StringFromGUID2		:	conversion of the GUID to string failed
#define SYMBOL_ERR_GUID_TO_ANSI_FAILED			0x40000009	//wcstombs_s			:	conversion of GUID to ANSI string failed
#define SYMBOL_ERR_DOWNLOAD_FAILED				0x4000000A	//URLDownloadToFileA	:	downloading the pdb file failed
#define SYMBOL_ERR_CANT_ACCESS_PDB_FILE			0x4000000B	//GetFileAttributesExA	:	can't access the pdb file
#define SYMBOL_ERR_CANT_OPEN_PDB_FILE			0x4000000C	//CreateFileA			:	can't open the pdb file
#define SYMBOL_ERR_CANT_OPEN_PROCESS			0x4000000D	//OpenProcess			:	can't open handle to current process
#define SYMBOL_ERR_SYM_INIT_FAIL				0x4000000E	//SymInitialize			:	couldn't initialize pdb symbol stuff
#define SYMBOL_ERR_SYM_LOAD_TABLE				0x4000000F	//SymLoadModule64		:	couldn't load symbol table
#define SYMBOL_ERR_ALREADY_INITIALIZED			0x40000010	//internal error		:	this instance of the SYMBOL_PARSER has already been initialized
#define SYMBOL_ERR_NOT_INITIALIZED				0x40000011	//internal error		:	this isntance of the SYMBOL_PARSER hasn't benen initialized
#define SYMBOL_ERR_IVNALID_SYMBOL_NAME			0x40000012	//internal error		:	szSymbolName is NULL
#define SYMBOL_ERR_SYMBOL_SEARCH_FAILED			0x40000013	//SymFromName			:	couldn't find szSymbolName in the specified pdb
#define SYMBOL_CANT_OPEN_PROCESS				0x40000014	//OpenProcess			:	can't get PROCESS_QUERY_LIMITED_INFORMATION handle to current process



/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//Symbol errors:
#define HOOK_SCAN_ERR_SUCCESS						0x00000000

																//Source				:	error description
#define HOOK_SCAN_ERR_INVALID_PROCESS_ID			0x50000001	//internal error		:	target process identifier is 0
#define HOOK_SCAN_ERR_CANT_OPEN_PROCESS				0x50000002	//OpenProcess			:	target process identifier is 0
#define HOOK_SCAN_ERR_PLATFORM_MISMATCH				0x50000003	//internal error		:	wow64 injector can't scan x64 process
#define HOOK_SCAN_ERR_GETPROCADDRESS_FAILED			0x50000004	//GetProcAddress		:	GetProcAddress failed internally
#define HOOK_SCAN_ERR_READ_PROCESS_MEMORY_FAILED	0x50000005	//ReadProcessMemory		:	ReadProcessMemory failed while reading the bytes of the target function
#define HOOK_SCAN_ERR_CANT_GET_OWN_MODULE_PATH		0x50000006	//GetOwnModulePath		:	unable to obtain path to the GH Injector directory
#define HOOK_SCAN_ERR_CREATE_EVENT_FAILED			0x50000007	//CreateEventEx			:	win32 error
#define HOOK_SCAN_ERR_CREATE_PROCESS_FAILED			0x50000008	//CreateProcessW		:	win32 error
#define HOOK_SCAN_ERR_WAIT_FAILED					0x50000009	//WaitForSingleObject	:	win32 error
#define HOOK_SCAN_ERR_WAIT_TIMEOUT					0x5000000A	//WaitForSingleObject	:	waiting timed out