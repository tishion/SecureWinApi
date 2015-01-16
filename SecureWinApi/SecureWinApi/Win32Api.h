

BOOL WINAPI thread_next(HANDLE hSnapShot, LPTHREADENTRY32 lpte, BOOL first);
BOOL WINAPI process_next(HANDLE hSnapShot, LPPROCESSENTRY32W lppe,BOOL first, BOOL unicode);
BOOL WINAPI module_nextW(HANDLE hSnapShot, LPMODULEENTRY32W lpme, BOOL first);
BOOL WINAPI module_nextA(HANDLE handle, LPMODULEENTRY32 lpme, BOOL first);

namespace Win32Api
{
	HANDLE WINAPI GetCurrentProcess()
	{
		return (HANDLE)0xffffffff;
	}


	HANDLE WINAPI GetCurrentThread()
	{
		return (HANDLE)0xfffffffe;
	}

	DWORD WINAPI GetCurrentProcessId()
	{
#ifdef _M_IX86
		return *((DWORD_PTR *) __readfsdword(0x18) + 0x20 / sizeof(DWORD_PTR));
#elif _M_IX64
		return *((DWORD_PTR *) __readgsqword(0x30) + 0x40 / sizeof(DWORD_PTR));
#endif
	}

	DWORD WINAPI GetCurrentThreadId()
	{
		return (DWORD)WinNtApi::NtCurrentTeb()->Cid.UniqueThread;
	}

	HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
	{
		LONG				status;
		HANDLE              handle;
		OBJECT_ATTRIBUTES   attr;
		CLIENT_ID           cid;

		cid.UniqueProcess = (HANDLE)dwThreadId;
		cid.UniqueThread = 0;

		attr.Length = sizeof(OBJECT_ATTRIBUTES);
		attr.RootDirectory = NULL;
		attr.Attributes = bInheritHandle ? OBJ_INHERIT : 0;
		attr.SecurityDescriptor = NULL;
		attr.SecurityQualityOfService = NULL;
		attr.ObjectName = NULL;

		if (Win32Api::GetVersion() & 0x80000000) dwDesiredAccess = PROCESS_ALL_ACCESS;

		status = WinNtApi::NtOpenProcess(&handle, dwDesiredAccess, &attr, &cid);

		if (status != STATUS_SUCCESS)
		{
			return NULL;
		}
		return handle;
	}

	HANDLE WINAPI OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
	{
		HANDLE ThreadHandle;
		NTSTATUS ErrorCode;
		CLIENT_ID CliId;
		OBJECT_ATTRIBUTES ObjAtt={0};

		CliId.UniqueProcess = 0;
		CliId.UniqueThread = (PVOID) dwThreadId;

		if (!bInheritHandle)
			ObjAtt.Attributes = 0;
		else
			ObjAtt.Attributes = 2;

		ObjAtt.Length = 0x18;
		ObjAtt.ObjectName = 0;

		if ((ErrorCode = WinNtApi::NtOpenThread(&ThreadHandle, dwDesiredAccess, &ObjAtt, &CliId)) == 0)
			return(ThreadHandle);
		else
			return((HANDLE) ErrorCode);
	}

	BOOL WINAPI GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
	{
		return WinNtApi::NtGetContextThread(hThread, lpContext);
	}

	BOOL WINAPI SetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
	{
		return WinNtApi::NtSetContextThread(hThread, lpContext);
	}

	BOOL WINAPI TerminateProcess(HANDLE hThread, UINT uExitCode)
	{
		NTSTATUS status = WinNtApi::NtTerminateProcess(hThread, uExitCode);
		return !status;
	}

	VOID WINAPI ExitProcess(UINT uExitCode)
	{
		WinNtApi::NtTerminateProcess((HANDLE)0xFFFFFFFF, uExitCode);
	}

	BOOL WINAPI Thread32First(HANDLE hSnapShot, LPTHREADENTRY32 lpte)
	{
		return thread_next(hSnapShot, lpte, TRUE);
	}

	BOOL WINAPI Thread32Next(HANDLE hSnapShot, LPTHREADENTRY32 lpte)
	{
		return thread_next(hSnapShot, lpte, FALSE);
	}

	BOOL WINAPI Process32FirstA(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
	{
		return process_next(hSnapshot, (PROCESSENTRY32W*)lppe, TRUE, FALSE);
	}

	BOOL WINAPI Process32NextA(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
	{
		return process_next(hSnapshot, (PROCESSENTRY32W*)lppe, FALSE, FALSE);
	}

	BOOL WINAPI Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
	{
		return process_next(hSnapshot, lppe, TRUE, TRUE);
	}

	BOOL WINAPI Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
	{
		return process_next(hSnapshot, lppe, FALSE, TRUE);
	}

	BOOL WINAPI Module32FirstA(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
	{
		return module_nextA(hSnapshot, lpme, TRUE);
	}

	BOOL WINAPI Module32NextA(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
	{
		return module_nextA(hSnapshot, lpme, FALSE);
	}

	BOOL WINAPI Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
	{
		return module_nextW(hSnapshot, lpme, TRUE);
	}

	BOOL WINAPI Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
	{
		return module_nextW(hSnapshot, lpme, FALSE);
	}

	BOOL WINAPI Toolhelp32ReadProcessMemory(DWORD th32ProcessID, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T cbRead, SIZE_T* lpNumberOfBytesRead)
	{
		HANDLE h;
		BOOL   ret = FALSE;

		h = (th32ProcessID) ? Win32Api::OpenProcess(PROCESS_VM_READ, FALSE, th32ProcessID) : Win32Api::GetCurrentProcess();
		if (h != NULL)
		{
			ret = Win32Api::ReadProcessMemory(h, lpBaseAddress, lpBuffer, cbRead, lpNumberOfBytesRead);
			if (th32ProcessID) Win32Api::CloseHandle(h);
		}
		return ret;
	}

	BOOL WINAPI ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
	{
		return WinNtApi::NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}

	BOOL WINAPI WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
	{
		return WinNtApi::NtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}

	LPVOID WINAPI VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
	{
		WinNtApi::NtAllocateVirtualMemory(hProcess, &lpAddress, 0, &dwSize, flAllocationType, flProtect);
		return lpAddress;
	}

	LPVOID WINAPI VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
	{
		return Win32Api::VirtualAllocEx(GetCurrentProcess(), lpAddress, dwSize, flAllocationType, flProtect);
	}

	SIZE_T WINAPI VirtualQuery(LPVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer , SIZE_T dwLength)
	{
		return Win32Api::VirtualQueryEx(Win32Api::GetCurrentProcess(), lpAddress, lpBuffer, dwLength);
	}

	SIZE_T WINAPI VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
	{
		SIZE_T nRetLen;
		NTSTATUS status;

		if ((status = WinNtApi::NtQueryVirtualMemory(hProcess, (PVOID)lpAddress, MemoryBasicInformation, lpBuffer, dwLength, &nRetLen)))
		{
			nRetLen = 0;
		}
		return nRetLen;
	}

	BOOL WINAPI VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
	{
		return Win32Api::VirtualFreeEx(Win32Api::GetCurrentProcess(), lpAddress, dwSize, dwFreeType);
	}

	BOOL WINAPI VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
	{
		NTSTATUS status = WinNtApi::NtFreeVirtualMemory(hProcess, &lpAddress, &dwSize, dwFreeType);
		return !status;
	}

	BOOL WINAPI VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect , LPDWORD lpflOldProtect)
	{
		return Win32Api::VirtualProtectEx(Win32Api::GetCurrentProcess(), lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}

	BOOL WINAPI VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,DWORD flNewProtect, LPDWORD lpflOldProtect)
	{
		NTSTATUS status = WinNtApi::NtProtectVirtualMemory(hProcess, &lpAddress, &dwSize, flNewProtect, lpflOldProtect);
		return !status;
	}

	HANDLE WINAPI GetProcessHeap()
	{
		return WinNtApi::NtCurrentTeb()->Peb->ProcessHeap;
	}

	LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwSize)
	{
		return WinNtApi::RtlAllocateHeap(hHeap, dwFlags, dwSize);
	}

	LPVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwSize)
	{
		return WinNtApi::RtlReAllocateHeap(hHeap, dwFlags, lpMem, dwSize);
	}

	BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
	{
		return WinNtApi::RtlFreeHeap(hHeap, dwFlags, lpMem);
	}

	LPVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess , DWORD dwFileOffsetHigh , DWORD dwFileOffsetLow , SIZE_T dwNumberOfBytesToMap)
	{
		return Win32Api::MapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, NULL);
	}

	LPVOID WINAPI MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess , DWORD dwFileOffsetHigh , DWORD dwFileOffsetLow , SIZE_T dwNumberOfBytesToMap , LPVOID lpBaseAddress)
	{
		NTSTATUS status;
		LARGE_INTEGER offset;
		ULONG protect;

		offset.u.LowPart  = dwFileOffsetHigh;
		offset.u.HighPart = dwFileOffsetLow;

		if (dwDesiredAccess & FILE_MAP_WRITE) 
			protect = PAGE_READWRITE;
		else if (dwDesiredAccess & FILE_MAP_READ) 
			protect = PAGE_READONLY;
		else if (dwDesiredAccess & FILE_MAP_COPY) 
			protect = PAGE_WRITECOPY;
		else 
			protect = PAGE_NOACCESS;

		if ((status = WinNtApi::NtMapViewOfSection(hFileMappingObject, Win32Api::GetCurrentProcess(), &lpBaseAddress, 0, 0, &offset, &dwNumberOfBytesToMap, ViewShare, 0, protect)))
		{
			lpBaseAddress = NULL;
		}
		return lpBaseAddress;
	}

	BOOL WINAPI UnmapViewOfFile(LPVOID lpBaseAddress)
	{
		NTSTATUS status = WinNtApi::NtUnmapViewOfSection(Win32Api::GetCurrentProcess(), lpBaseAddress);
		return !status;
	}

	DWORD WINAPI GetVersion()
	{
		ULONG OSMajorVersion = WinNtApi::NtCurrentTeb()->Peb->OSMajorVersion;
		ULONG OSMinorVersion = WinNtApi::NtCurrentTeb()->Peb->OSMinorVersion;
		ULONG OSPlatformId = WinNtApi::NtCurrentTeb()->Peb->OSPlatformId;

		DWORD result = MAKELONG(MAKEWORD(OSMajorVersion, OSMinorVersion), (OSPlatformId ^ 2) << 14);
		if (OSPlatformId == VER_PLATFORM_WIN32_NT)
		{
			ULONG OSBuildNumber = WinNtApi::NtCurrentTeb()->Peb->OSBuildNumber;
			result |= LOWORD(OSBuildNumber) << 16;
		}

		return result;
	}

	HMODULE WINAPI LoadLibraryA(LPCSTR lpModuleName)
	{
		ANSI_STRING asModuleName;
		UNICODE_STRING usModuleName;
		HMODULE hModule;

		asModuleName.Buffer = (PCHAR)lpModuleName;
		asModuleName.Length = WinNtApi::strlen(lpModuleName);
		asModuleName.MaximumLength = asModuleName.Length;

		if (!NT_SUCCESS(WinNtApi::RtlAnsiStringToUnicodeString(&usModuleName, &asModuleName, TRUE)))
			return NULL;

		if (!NT_SUCCESS(WinNtApi::LdrLoadDll(NULL, 0, &usModuleName, &hModule)))
		{
			WinNtApi::RtlFreeUnicodeString(&usModuleName);
			return NULL;
		}

		WinNtApi::RtlFreeUnicodeString(&usModuleName);

		return (HMODULE)hModule;
	}

	HMODULE WINAPI LoadLibraryW(LPCWSTR lpModuleName)
	{
		UNICODE_STRING usModuleName;
		HMODULE hModule;

		usModuleName.Buffer = (PWCHAR)lpModuleName;
		usModuleName.Length = WinNtApi::wcslen(lpModuleName);
		usModuleName.MaximumLength = usModuleName.Length;

		if (!NT_SUCCESS(WinNtApi::LdrLoadDll(NULL, 0, &usModuleName, &hModule)))
		{
			return NULL;
		}

		return hModule;
	}

	HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName)
	{
		PLIST_ENTRY fModule, fMark;
		PLDR_MODULE pMod;

		ANSI_STRING asModuleName;
		UNICODE_STRING usModuleName;

		asModuleName.Buffer = (PCHAR)lpModuleName;
		asModuleName.Length = WinNtApi::strlen(lpModuleName);
		asModuleName.MaximumLength = asModuleName.Length;

		if (!NT_SUCCESS(WinNtApi::RtlAnsiStringToUnicodeString(&usModuleName, &asModuleName, TRUE)))
			return NULL;

		fMark = &WinNtApi::NtCurrentTeb()->Peb->LoaderData->InLoadOrderModuleList;

		for(fModule = fMark->Flink; fModule != fMark; fModule = fModule->Flink)
		{
			pMod = (PLDR_MODULE)fModule;
			if (WinNtApi::RtlCompareUnicodeString(&pMod->BaseDllName, &usModuleName, FALSE) == 0)
			{
				WinNtApi::RtlFreeUnicodeString(&usModuleName);
				return (HMODULE)pMod->BaseAddress;
			}
		}

		WinNtApi::RtlFreeUnicodeString(&usModuleName);

		return NULL;
	}

	HMODULE WINAPI GetModuleHandleW(LPCWSTR ModuleName)
	{
		PLIST_ENTRY pebModuleHeader, ModuleLoop;
		PLDR_MODULE lclModule;
		PPEB_LDR_DATA pebModuleLdr;
		DWORD BadModuleCount = 0;

#if _M_IX86
		pebModuleLdr = (PPEB_LDR_DATA) *((DWORD_PTR *) __readfsdword(0x30) + 12 / sizeof(DWORD_PTR));
#elif _M_X64
		pebModuleLdr = (PPEB_LDR_DATA) *((DWORD_PTR *) __readgsqword(0x60) + 24 / sizeof(DWORD_PTR));
#endif

		pebModuleHeader = (PLIST_ENTRY) &pebModuleLdr->InLoadOrderModuleList;

		lclModule = (PLDR_MODULE) pebModuleHeader->Flink;
		ModuleLoop = pebModuleHeader->Flink;
		do
		{
			if (!WinNtApi::wcscmp(ModuleName, lclModule->BaseDllName.Buffer))
			{
				return((HMODULE) lclModule->BaseAddress);
			}
			lclModule = (PLDR_MODULE) ModuleLoop->Flink;
			ModuleLoop = ModuleLoop->Flink;
		} while(pebModuleHeader != ModuleLoop);

		return(0);
	}

	DWORD WINAPI GetModuleSize(HMODULE hModule)
	{
		if (hModule == NULL) return 0;
		PBYTE pbImageBase = (PBYTE)hModule;
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pbImageBase;
		PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)(pbImageBase + DosHeader->e_lfanew);

		return NTHeaders->OptionalHeader.SizeOfImage;
	}

	LPCWSTR WINAPI GetModuleFileNameW(HMODULE handle)
	{
		PLIST_ENTRY fModule,fMark;
		PLDR_MODULE pMod;

		fMark = &WinNtApi::NtCurrentTeb()->Peb->LoaderData->InLoadOrderModuleList;

		for(fModule = fMark->Flink; fModule != fMark; fModule = fModule->Flink)
		{
			pMod = (PLDR_MODULE)fModule;
			if (pMod->BaseAddress == handle)
			{
				return pMod->BaseDllName.Buffer;
			}
		}

		return NULL;
	}

	LPCWSTR WINAPI GetModuleFullFileNameW(HMODULE handle)
	{
		PLIST_ENTRY fModule,fMark;
		PLDR_MODULE pMod;

		fMark = &WinNtApi::NtCurrentTeb()->Peb->LoaderData->InLoadOrderModuleList;

		for(fModule = fMark->Flink; fModule != fMark; fModule = fModule->Flink)
		{
			pMod = (PLDR_MODULE)fModule;
			if (pMod->BaseAddress == handle)
			{
				return pMod->FullDllName.Buffer;
			}
		}

		return NULL;
	}

	FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
	{
		if (!hModule)
			return(0);

		PIMAGE_NT_HEADERS ModuleHeader = (PIMAGE_NT_HEADERS)((PCHAR) hModule + ((PIMAGE_DOS_HEADER) hModule)->e_lfanew);
		if (ModuleHeader->Signature != IMAGE_NT_SIGNATURE)
			return(0);

		PIMAGE_DATA_DIRECTORY data_dir = &ModuleHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!data_dir->VirtualAddress)
			return(0);

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) (data_dir->VirtualAddress + (ULONG) hModule);
		if (!ExportDirectory)
			return(0);

		PCHAR *Name = (PCHAR *) (ExportDirectory->AddressOfNames + (ULONG) hModule);
		if (!Name)
			return(0);

		for(ULONG FunctionIndex = 0; FunctionIndex < ExportDirectory->NumberOfNames; FunctionIndex++)
		{
			if (!WinNtApi::strcmp((PCHAR) *Name + (ULONG) hModule, lpProcName))
			{
				PULONG FunctionAddress = (PULONG) (ExportDirectory->AddressOfFunctions + (ULONG) hModule);
				PUSHORT Ordinals =  (PUSHORT) (ExportDirectory->AddressOfNameOrdinals + (ULONG) hModule);

				if (!Ordinals || !FunctionAddress || !lpProcName)
					return(0);
				else
					return((FARPROC) (FunctionAddress[Ordinals[FunctionIndex]] + (ULONG) hModule));
			}
			Name++;
		}
		return(0);
	}


	BOOL WINAPI IsBadReadPtr(CONST VOID* lp,UINT ucb)
	{
		MEMORY_BASIC_INFORMATION MemoryInformation;

		if (ucb == 0) return TRUE;
		Win32Api::VirtualQuery((LPVOID)lp, &MemoryInformation, sizeof(MEMORY_BASIC_INFORMATION));

		if (MemoryInformation.State != MEM_COMMIT) return TRUE;
		if (MemoryInformation.RegionSize < ucb) return TRUE;
		if (MemoryInformation.Protect == PAGE_EXECUTE) return TRUE;
		if (MemoryInformation.Protect == PAGE_NOACCESS)return TRUE;

		return FALSE;
	}

	BOOL WINAPI IsBadWritePtr(LPVOID lp, UINT ucb)
	{
		MEMORY_BASIC_INFORMATION MemoryInformation;

		if (ucb == 0)return TRUE;
		Win32Api::VirtualQuery((LPVOID)lp, &MemoryInformation, sizeof(MEMORY_BASIC_INFORMATION));

		if (MemoryInformation.State != MEM_COMMIT) return TRUE;
		if (MemoryInformation.RegionSize < ucb) return TRUE;
		if (MemoryInformation.Protect == PAGE_READONLY) return TRUE;
		if ((MemoryInformation.Protect == PAGE_EXECUTE)
			|| (MemoryInformation.Protect == PAGE_EXECUTE_READ))return TRUE;
		if (MemoryInformation.Protect == PAGE_NOACCESS)return TRUE;

		return FALSE;
	}

	BOOL WINAPI CloseHandle(HANDLE Object)
	{
		return WinNtApi::NtClose(Object);
	}

	void WINAPI SetLastError(DWORD error)
	{
		WinNtApi::NtCurrentTeb()->LastErrorValue = error;
	}

	HANDLE WINAPI CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
	{
		return INVALID_HANDLE_VALUE;
	}

	HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
	{
		return INVALID_HANDLE_VALUE;
	}

	HANDLE WINAPI CreateFileMappingA(HANDLE hFile, SECURITY_ATTRIBUTES *sa, DWORD protect, DWORD size_high, DWORD size_low, LPCSTR name)
	{
		return NULL;
	}

	HANDLE WINAPI CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES sa, DWORD protect, DWORD size_high, DWORD size_low, LPCWSTR name)
	{
		static const int sec_flags = SEC_FILE | SEC_IMAGE | SEC_RESERVE | SEC_COMMIT | SEC_NOCACHE;

		HANDLE ret;
		NTSTATUS status;
		DWORD access, sec_type;
		LARGE_INTEGER size;

		sec_type = protect & sec_flags;
		protect &= ~sec_flags;
		if (!sec_type) sec_type = SEC_COMMIT;

		/* Win9x compatibility */
		if (!protect && (Win32Api::GetVersion() & 0x80000000)) protect = PAGE_READONLY;

		switch(protect)
		{
		case PAGE_READONLY:
		case PAGE_WRITECOPY:
			access = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ;
			break;
		case PAGE_READWRITE:
			access = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE;
			break;
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_WRITECOPY:
			access = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_EXECUTE;
			break;
		case PAGE_EXECUTE_READWRITE:
			access = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;
			break;
		default:
			Win32Api::SetLastError(ERROR_INVALID_PARAMETER);
			return 0;
		}

		if (hFile == INVALID_HANDLE_VALUE)
		{
			hFile = 0;
			if (!size_low && !size_high)
			{
				Win32Api::SetLastError(ERROR_INVALID_PARAMETER);
				return 0;
			}
		}

		size.u.LowPart  = size_low;
		size.u.HighPart = size_high;

		if (sa || name)
		{
			__asm int 3;
		}
		else status = WinNtApi::NtCreateSection(&ret, access, NULL, &size, protect, sec_type, hFile);

		return ret;
	}

	int WINAPI WideCharToMultiByte(
		UINT CodePage, 
		DWORD dwFlags, 
		LPCWSTR lpWideCharStr, 
		int cchWideChar,
		LPSTR lpMultiByteStr, 
		int cbMultiByte,
		LPCSTR lpDefaultChar,
		LPBOOL lpUsedDefaultChar)
	{
		WCHAR wcsKernel32[] = {'K', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0'};
		CHAR szProcName[] = {'W', 'i', 'd', 'e', 'C', 'h', 'a', 'r', 'T', 'o', 'M', 'u', 'l', 't', 'i', 'B', 'y', 't', 'e', '\0'};
		Type_WideCharToMultiByte pfn = (Type_WideCharToMultiByte)(Win32Api::GetProcAddress(
			Win32Api::GetModuleHandleW(wcsKernel32),
			szProcName));

		return pfn(
			CodePage, 
			dwFlags, 
			lpWideCharStr, 
			cchWideChar, 
			lpMultiByteStr, 
			cbMultiByte, 
			lpDefaultChar, 
			lpUsedDefaultChar);
	}
}


//////////////////////////////////////////////////////////////////////////
// some util functions	
BOOL WINAPI thread_next(HANDLE hSnapShot, LPTHREADENTRY32 lpte, BOOL first)
{
	struct snapshot*    snap;
	BOOL                ret = FALSE;

	if (lpte->dwSize < sizeof(THREADENTRY32))
	{
		return FALSE;
	}
	if ((snap = (struct snapshot*)Win32Api::MapViewOfFile(hSnapShot, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
	{
		if (first) snap->thread_pos = 0;
		if (snap->thread_pos < snap->thread_count)
		{
			LPTHREADENTRY32 te = (THREADENTRY32*)&snap->data[snap->thread_offset];
			*lpte = te[snap->thread_pos++];
			ret = TRUE;
		}
		Win32Api::UnmapViewOfFile(snap);
	}
	return ret;
}

BOOL WINAPI process_next(HANDLE hSnapShot, LPPROCESSENTRY32W lppe,BOOL first, BOOL unicode)
{
	struct snapshot*    snap;
	BOOL                ret = FALSE;
	DWORD               sz = unicode ? sizeof(PROCESSENTRY32W) : sizeof(PROCESSENTRY32);

	if (lppe->dwSize < sz)
	{
		return FALSE;
	}

	if ((snap = (struct snapshot*)Win32Api::MapViewOfFile(hSnapShot, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
	{
		if (first) snap->process_pos = 0;
		if (snap->process_pos < snap->process_count)
		{
			LPPROCESSENTRY32W pe = (PROCESSENTRY32W*)&snap->data[snap->process_offset];
			if (unicode)
				*lppe = pe[snap->process_pos];
			else
			{
				lppe->cntUsage = pe[snap->process_pos].cntUsage;
				lppe->th32ProcessID = pe[snap->process_pos].th32ProcessID;
				lppe->th32DefaultHeapID = pe[snap->process_pos].th32DefaultHeapID;
				lppe->th32ModuleID = pe[snap->process_pos].th32ModuleID;
				lppe->cntThreads = pe[snap->process_pos].cntThreads;
				lppe->th32ParentProcessID = pe[snap->process_pos].th32ParentProcessID;
				lppe->pcPriClassBase = pe[snap->process_pos].pcPriClassBase;
				lppe->dwFlags = pe[snap->process_pos].dwFlags;

				Win32Api::WideCharToMultiByte(CP_ACP, 0, pe[snap->process_pos].szExeFile, -1,
					(char*)lppe->szExeFile, sizeof(lppe->szExeFile), 0, 0);
			}
			snap->process_pos++;
			ret = TRUE;
		}
		Win32Api::UnmapViewOfFile(snap);
	}

	return ret;
}

BOOL WINAPI module_nextA(HANDLE handle, LPMODULEENTRY32 lpme, BOOL first)
{
	BOOL ret;
	MODULEENTRY32W mew;

	if (lpme->dwSize < sizeof(MODULEENTRY32))
	{
		return FALSE;
	}

	mew.dwSize = sizeof(mew);
	if ((ret = module_nextW(handle, &mew, first)))
	{
		lpme->th32ModuleID  = mew.th32ModuleID;
		lpme->th32ProcessID = mew.th32ProcessID;
		lpme->GlblcntUsage  = mew.GlblcntUsage;
		lpme->ProccntUsage  = mew.ProccntUsage;
		lpme->modBaseAddr   = mew.modBaseAddr;
		lpme->modBaseSize   = mew.modBaseSize;
		lpme->hModule       = mew.hModule;
		Win32Api::WideCharToMultiByte(CP_ACP, 0, mew.szModule, -1, lpme->szModule, sizeof(lpme->szModule), NULL, NULL);
		Win32Api::WideCharToMultiByte(CP_ACP, 0, mew.szExePath, -1, lpme->szExePath, sizeof(lpme->szExePath), NULL, NULL);
	}
	return ret;
}


BOOL WINAPI module_nextW(HANDLE hSnapShot, LPMODULEENTRY32W lpme, BOOL first)
{
	struct snapshot*    snap;
	BOOL                ret = FALSE;

	if (lpme->dwSize < sizeof (MODULEENTRY32W))
	{
		return FALSE;
	}
	if ((snap = (struct snapshot*)Win32Api::MapViewOfFile(hSnapShot, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
	{
		if (first) snap->module_pos = 0;
		if (snap->module_pos < snap->module_count)
		{
			LPMODULEENTRY32W pe = (MODULEENTRY32W*)&snap->data[snap->module_offset];
			*lpme = pe[snap->module_pos++];
			ret = TRUE;
		}
		Win32Api::UnmapViewOfFile(snap);
	}

	return ret;
}
