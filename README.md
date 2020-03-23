## GH Injector Library

A feature-rich DLL injection library which supports x86, WOW64 and x64.

----

### Injection methods

- LoadLibraryExW
- LdrLoadDll
- LdrpLoadDll
- ManualMapping

### Shellcode execution methods

- NtCreateThreadEx
- Thread hijacking
- SetWindowsHookEx
- QueueUserAPC

### Additional features
- Various cloaking options
	- PEB unlinking
	- PE header cloaking
	- Thread cloaking
- Fully customizable ManualMapping
- Handle hijacking
- Hook scanning/restoring

----

### Getting started

You can easily use mapper by including the compiled binaries in your project. Check the provided Injection.h header for more information.
Make sure you have the compiled binaries in the working directory of your program.

```cpp

#include "Injection.h"

HINSTANCE hInjectionMod = LoadLibrary(GH_INJ_MOD_NAME);
	
auto InjectA = (f_InjectA)GetProcAddress(hInjectionMod, "InjectA");

DWORD TargetProcessId;

INJECTIONDATAA data =
{
	0,
	"",
	TargetProcessId;,
	INJECTION_MODE::IM_LoadLibraryExW,
	LAUNCH_METHOD::LM_NtCreateThreadEx,
	NULL,
	0,
	NULL
};

strcpy(data.szDllPath, DllPathToInject);

InjectA(&data);

```
