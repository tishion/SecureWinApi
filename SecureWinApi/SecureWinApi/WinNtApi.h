
namespace Util
{
	PVOID InterlockedCompareAndExchangePointer(
		PVOID volatile* Destination, 
		PVOID Exchange,
		PVOID Comparand)
	{
		PVOID pRet = *Destination;
		if (Destination)
		{
			__asm mov eax, Comparand;
			__asm mov ecx, Destination;
			__asm mov edx, Exchange;
			__asm lock cmpxchg dword ptr [ecx], edx;
		}
		return pRet;
	}

	#define IfFalseGoExit(x) { br=(x); if (!br) goto _ErrorExit; }
	#define MakePointer(t, p, offset) ((t)((ULONG)(p) + offset))

	typedef NTSTATUS (WINAPI * Type_LdrGetProcedureAddress)(PVOID, PANSI_STRING, ULONG, PVOID*);
	typedef NTSTATUS (WINAPI * Type_LdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
	typedef NTSTATUS (WINAPI * Type_ZwAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PULONG, ULONG, ULONG);
	typedef NTSTATUS (WINAPI * Type_ZwProtectVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
	typedef NTSTATUS (WINAPI * Type_ZwFreeVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG);
	typedef BOOL	 (WINAPI * Type_DllMain)(HMODULE, DWORD, LPVOID);
	
	HMODULE LoadMemModule(LPVOID pMemModuleBuffer, BOOL bCallEntry)
	{
		if (NULL == pMemModuleBuffer)
		{
			return NULL;
		}

		BOOL br = FALSE;

		PIMAGE_DOS_HEADER pImageDosHeader = NULL;
		PIMAGE_NT_HEADERS32 pImageNtHeader = NULL;
		LPVOID pImageBase = NULL;

		LPVOID pVirutalMemoryBase = NULL;
		ULONG ulVirtuallMemorySize = 0;
		NTSTATUS status;

		////// 1.校验内存中的数据是否合法的PE文件映射
		//////////////////////////////////////////////////////////////////////////
		pImageDosHeader = (PIMAGE_DOS_HEADER)pMemModuleBuffer;

		// 对比MZ签名
		IfFalseGoExit(IMAGE_DOS_SIGNATURE == pImageDosHeader->e_magic);

		// 对比PE签名
		DWORD dwE_lfanew = pImageDosHeader->e_lfanew;
		PDWORD pdwPESignature = MakePointer(PDWORD, pImageDosHeader, dwE_lfanew);
		IfFalseGoExit(IMAGE_NT_SIGNATURE == *pdwPESignature);

		// 获取IMAGE_FILE_HEADER，然后判断目标平台CPU类型
		PIMAGE_FILE_HEADER pImageFileHeader = 
			MakePointer(PIMAGE_FILE_HEADER, pdwPESignature, sizeof(IMAGE_NT_SIGNATURE));

		IfFalseGoExit(IMAGE_FILE_MACHINE_I386 == pImageFileHeader->Machine);

		pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS32, pdwPESignature, 0);

		IfFalseGoExit(
			IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader->OptionalHeader.Magic);

		////// 2.按照节表映射PE文件到正确的虚拟内存中
		//////////////////////////////////////////////////////////////////////////
		pVirutalMemoryBase = (LPVOID)(pImageNtHeader->OptionalHeader.ImageBase);
		ulVirtuallMemorySize = pImageNtHeader->OptionalHeader.SizeOfImage;
		status = WinNtApi::NtAllocateVirtualMemory(
			(HANDLE)(-1),
			&pVirutalMemoryBase,
			0,
			&ulVirtuallMemorySize, 
			MEM_RESERVE | MEM_COMMIT, 
			PAGE_READWRITE);

		// 无法加载到ImageBase指定的地址，让系统选择
		if (FALSE == SUCCEEDED(status))
		{
			pVirutalMemoryBase = NULL;
			ulVirtuallMemorySize = pImageNtHeader->OptionalHeader.SizeOfImage;
			status = WinNtApi::NtAllocateVirtualMemory(
				(HANDLE)(-1),
				&pVirutalMemoryBase,
				0,
				&ulVirtuallMemorySize, 
				MEM_RESERVE | MEM_COMMIT, 
				PAGE_READWRITE);
		}

		// 仍然失败，说明内存无法满足要求
		IfFalseGoExit(NULL != pVirutalMemoryBase);

		pImageBase = pVirutalMemoryBase;

		//把PE头部拷贝到目标位置
		//memmove(
		//	pImageBase, 
		//	pMemModuleBuffer, 
		//	pImageNtHeader->OptionalHeader.SizeOfHeaders);
		{
			PBYTE pSrc = (PBYTE)pMemModuleBuffer;
			PBYTE pDest = (PBYTE)pImageBase;
			SIZE_T cb = pImageNtHeader->OptionalHeader.SizeOfHeaders;
			if ((DWORD)pSrc < (DWORD)pDest)
			{
				pSrc = pSrc + cb - 1;
				pDest = pDest + cb - 1;
				for (; cb; cb--)
				{
					*pDest-- = *pSrc--;
				}
			}
			else if((DWORD)pMemModuleBuffer > (DWORD)pImageBase)
			{
				for (; cb; cb--)
				{
					*pDest++ = *pSrc++;
				}
			}
		}

		// 开始复制所有有效Section
		int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(
			PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS32));

		for (int i = 0; i < nNumberOfSections; ++ i)
		{
			if (0 != pImageSectionHeader[i].VirtualAddress && 0 != pImageSectionHeader[i].SizeOfRawData)
			{
				DWORD dwSectionBase = (DWORD)pImageBase + pImageSectionHeader[i].VirtualAddress;

				// 计算该Section的内存保护属性
				DWORD dwSectionCharacteristics = pImageSectionHeader[i].Characteristics;
				if (dwSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
				{
					// 修改内存页保护属性
					pVirutalMemoryBase = (LPVOID)dwSectionBase;
					ulVirtuallMemorySize = pImageSectionHeader[i].SizeOfRawData;
					ULONG ulOldProtect = 0;
					status = WinNtApi::NtProtectVirtualMemory(
						(HANDLE)(-1),
						&pVirutalMemoryBase,
						&ulVirtuallMemorySize,
						PAGE_EXECUTE_READWRITE,
						&ulOldProtect);
					IfFalseGoExit(SUCCEEDED(status));
				}

				// 拷贝一个Section到指定位置
				//memmove(
				//	(LPVOID)dwSectionBase, 
				//	(LPVOID)((DWORD)pMemModuleBuffer + pImageSectionHeader[i].PointerToRawData), 
				//	pImageSectionHeader[i].SizeOfRawData);
				{
					PBYTE pSrc = (PBYTE)((DWORD)pMemModuleBuffer + pImageSectionHeader[i].PointerToRawData);
					PBYTE pDest = (PBYTE)dwSectionBase;
					SIZE_T cb = pImageSectionHeader[i].SizeOfRawData;
					if ((DWORD)pSrc < (DWORD)pDest)
					{
						pSrc = pSrc + cb - 1;
						pDest = pDest + cb - 1;
						for (; cb; cb--)
						{
							*pDest-- = *pSrc--;
						}
					}
					else if((DWORD)pMemModuleBuffer > (DWORD)pImageBase)
					{
						for (; cb; cb--)
						{
							*pDest++ = *pSrc++;
						}
					}
				}
			}
		}

		////// 3.重定位
		//////////////////////////////////////////////////////////////////////////
		DWORD dwDelta = (DWORD)pImageBase - pImageNtHeader->OptionalHeader.ImageBase;

		// 说明该模块被加载到了默认基址上，无需进行重定位
		if (0 != dwDelta)
		{
			if (0 != pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
				&& 0 != pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			{
				PIMAGE_BASE_RELOCATION pImageBaseRelocation = MakePointer(
					PIMAGE_BASE_RELOCATION, 
					pImageBase, 
					pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

				if (NULL != pImageBaseRelocation)
				{
					while(0 != (pImageBaseRelocation->VirtualAddress + pImageBaseRelocation->SizeOfBlock))
					{
						PWORD pRelocationData = MakePointer(PWORD, pImageBaseRelocation, sizeof(IMAGE_BASE_RELOCATION));

						int NumberOfRelocationData = (pImageBaseRelocation->SizeOfBlock 
							- sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

						for (int i=0 ; i < NumberOfRelocationData; i++)
						{
							if (/*0x00003000*/IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12))
							{
								PDWORD pAddress = (PDWORD)((DWORD)pImageBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
								*pAddress += dwDelta;
							}
						}

						pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBaseRelocation + pImageBaseRelocation->SizeOfBlock);
					}
				}
			}
		}

		////// 4.解析导入表
		//////////////////////////////////////////////////////////////////////////
		if (0 != pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
			&& 0 != pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = MakePointer(
				PIMAGE_IMPORT_DESCRIPTOR, 
				pImageBase, 
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			// 从PEB中获取DllPath
			PPEB pPeb = NULL;
			__asm
			{
				push eax;
				mov eax, fs:[0x30];
				mov pPeb, eax;
				pop eax;
			}
			IfFalseGoExit(NULL != pPeb);

			PRTL_USER_PROCESS_PARAMETERS pUserProcessParameters 
				= (PRTL_USER_PROCESS_PARAMETERS)pPeb->ProcessParameters;

			IfFalseGoExit(NULL != pUserProcessParameters);

			PUNICODE_STRING pustrDllSearchPath = &(pUserProcessParameters->DllPath);
			// 在windows 8 系统中 
			// RTL_USER_PROCESS_PARAMETERS.DllPath为一个空的UNICODE_STRING
			// 所以此处不能根据这个判断直接返回失败，
			// 如果是Windows 8 系统就直接传入空的UNICODE_STRING
			// tishion modifed @ 2014年3月18日 18:16:12
			// IfFalseGoExit(NULL != pustrDllSearchPath->Buffer);

			while (pImageImportDescriptor->OriginalFirstThunk)
			{
				LPSTR pDllNameA = MakePointer(PCHAR, pImageBase, pImageImportDescriptor->Name);

				// 1.c-style string转为Unicode string
				UNICODE_STRING ustrDllName;
				WCHAR ustrBuffer[MAX_PATH];
				ustrDllName.Buffer = ustrBuffer;
				ustrDllName.MaximumLength = sizeof(ustrBuffer);

				// char->wchar 转换并复制
				int nLen = 0;
				PUCHAR pStr = (PUCHAR)pDllNameA;
				for (PUCHAR p=pStr; ustrBuffer[nLen] = (WCHAR)(*p), *p++; nLen++);
				ustrDllName.Length = nLen * sizeof(WCHAR);

				// 调用LdrLoadDll加载模块
				PWCHAR pDllSearchPath = pustrDllSearchPath->Buffer;
				PVOID pDllHanlde = NULL;
				status = WinNtApi::LdrLoadDll(
					pDllSearchPath, NULL, &ustrDllName, (HMODULE*)&pDllHanlde);

				if (SUCCEEDED(status)
					&& NULL != pDllHanlde)
				{
					DWORD OriginalFirstThunk = pImageImportDescriptor->OriginalFirstThunk;
					DWORD FirstThunk = pImageImportDescriptor->FirstThunk;

					PIMAGE_THUNK_DATA32 pOrgItemEntry = MakePointer(PIMAGE_THUNK_DATA32, pImageBase, OriginalFirstThunk);

					PIMAGE_THUNK_DATA32 pIatItemEntry = MakePointer(PIMAGE_THUNK_DATA32, pImageBase, FirstThunk);

					while (0 != pOrgItemEntry->u1.AddressOfData)
					{
						PVOID pProcedureAddress = NULL;
						if (pOrgItemEntry->u1.AddressOfData & IMAGE_ORDINAL_FLAG32) 
						{
							// 通过Ordinal获取目标函数地址
							ULONG ulProcedureNumber = (IMAGE_ORDINAL32(pOrgItemEntry->u1.Ordinal));
							status =  WinNtApi::LdrGetProcedureAddress(
								(HMODULE)pDllHanlde, NULL, ulProcedureNumber, &pProcedureAddress);
						}
						else
						{
							PIMAGE_IMPORT_BY_NAME pImageImportByName = MakePointer(
								PIMAGE_IMPORT_BY_NAME, pImageBase, pOrgItemEntry->u1.AddressOfData);

							// 计算string length
							int nLen = 0;
							PUCHAR pStr = pImageImportByName->Name;
							for (PUCHAR p=pStr; *p++; nLen++);

							ANSI_STRING astrProcedureName;
							astrProcedureName.Buffer = (PCHAR)pStr;
							astrProcedureName.Length = nLen;
							astrProcedureName.MaximumLength = nLen + 1;
							// 通过Name获取目标函数地址
							status =  WinNtApi::LdrGetProcedureAddress(
								(HMODULE)pDllHanlde, &astrProcedureName, 0, &pProcedureAddress);
						}

						// 写入IAT
						pIatItemEntry->u1.Function = (DWORD)pProcedureAddress;

						pOrgItemEntry = MakePointer(PIMAGE_THUNK_DATA32, pOrgItemEntry, sizeof(DWORD));
						pIatItemEntry = MakePointer(PIMAGE_THUNK_DATA32, pIatItemEntry, sizeof(DWORD));
					}
				}
				else
				{
					IfFalseGoExit(FALSE);
				}

				pImageImportDescriptor = MakePointer(
					PIMAGE_IMPORT_DESCRIPTOR, 
					pImageImportDescriptor, 
					sizeof(IMAGE_IMPORT_DESCRIPTOR));
			}
		}

		if (bCallEntry)
		{
			Type_DllMain pfnModuleEntry = NULL;

			pfnModuleEntry = MakePointer(
				Type_DllMain, 
				pImageBase, 
				pImageNtHeader->OptionalHeader.AddressOfEntryPoint);
			IfFalseGoExit(NULL != pfnModuleEntry);
			IfFalseGoExit(pfnModuleEntry((HMODULE)pImageBase, DLL_PROCESS_ATTACH, NULL));
		}

		return (HMODULE)pImageBase;

_ErrorExit:
		if (FALSE == br 
			&& NULL != pImageBase)
		{
			WinNtApi::NtFreeVirtualMemory((HANDLE)(-1), &pImageBase, NULL, MEM_RELEASE);
		}
		return NULL;
	}
}

namespace WinNtApi
{
	HMODULE OriginalNtdllHanlde()
	{
		PLIST_ENTRY pebModuleHeader, ModuleLoop;
		PLDR_MODULE lclModule;
		PPEB_LDR_DATA pebModuleLdr;
		DWORD BadModuleCount = 0;
		WCHAR wcsNtdll[] = {'n', 'T', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0'};

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
			if (!WinNtApi::wcscmpi(wcsNtdll, lclModule->BaseDllName.Buffer))
			{
				return((HMODULE) lclModule->BaseAddress);
			}
			lclModule = (PLDR_MODULE) ModuleLoop->Flink;
			ModuleLoop = ModuleLoop->Flink;
		} while(pebModuleHeader != ModuleLoop);

		return(0);
	}

	/* 
	 * This funciton load the ntdll.dll from disk file image.
	 * Then return the base address of it and convert it to HMODULE
	 */ 
	HMODULE NtdllModuleHandle()
	{
		HMODULE * phNtdllMod = NULL;
	
		/* 
		 * When this call instruction executed the offset of hNtdllValue
		 * will be pushed on to the stack
		 */ 
		_asm call NtdllModuleHandle_Start;
//hNtdllValue:
		_asm _emit 0x00;
		_asm _emit 0x00;
		_asm _emit 0x00;
		_asm _emit 0x00;

		_asm _emit 0x00;
		_asm _emit 0x00;
		_asm _emit 0x00;
		_asm _emit 0x00;

NtdllModuleHandle_Start:
		/* Get the absolute address of hNtdllValue */
		_asm pop phNtdllMod;

		if (*phNtdllMod)
		{
			return *phNtdllMod;
		}

		/* Put string into stack */
		HMODULE hMod =  WinNtApi::OriginalNtdllHanlde();
		
		/* 
		 * Failed to get the module handle of NTDLL.DLL. 
		 * We can do nothing, so trigger the soft break.
		 */
		if (NULL == hMod)
		{
			_asm int 3;
		}

		PVOID BaseAddress = (PVOID)phNtdllMod;
		ULONG ulOldProtect = 0;
		ULONG ulProtectSize = sizeof(DWORD);
		CHAR szProcName[] = {'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtProtectVirtualMemory pfnNtProtectVirtualMemory = (Type_NtProtectVirtualMemory)Win32Api::GetProcAddress(hMod, szProcName);
		if (NULL == pfnNtProtectVirtualMemory)
		{
			_asm int 3;
		}

		/* 
		 * Failed to modify the protect flags of the hNtdllValue. 
		 * We can do nothing, so trigger the soft break.
		 */
		if (0 != pfnNtProtectVirtualMemory(Win32Api::GetCurrentProcess(), &BaseAddress, &ulProtectSize, PAGE_EXECUTE_READWRITE, &ulOldProtect))
		{
			_asm int 3;
		}

		if (NULL != Util::InterlockedCompareAndExchangePointer((PVOID*)phNtdllMod, hMod, NULL))
		{
			return *phNtdllMod;
		}

		LPCWSTR pNtdllPath = Win32Api::GetModuleFullFileNameW(hMod);
		if (NULL == pNtdllPath)
		{
			_asm int 3;
		}

		HANDLE hFile = INVALID_HANDLE_VALUE;
		HANDLE hMap = NULL;
		LPVOID pBuf = NULL;

		//hFile = ::CreateFile(
		//	pNtdllPath, 
		//	GENERIC_READ, 
		//	FILE_SHARE_READ, 
		//	NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);

		DWORD dwDesireAccess = 0;
		UNICODE_STRING FileName;
		WCHAR FileNameBuffer[MAX_PATH+16];
		FileNameBuffer[0] = '\\';
		FileNameBuffer[1] = '?';
		FileNameBuffer[2] = '?';
		FileNameBuffer[3] = '\\';
		FileNameBuffer[4] = '\0';
		WinNtApi::wcscat_s(FileNameBuffer, MAX_PATH, pNtdllPath);
		WinNtApi::RtlInitUnicodeString(&FileName, FileNameBuffer);

		OBJECT_ATTRIBUTES objAttr;
		IO_STATUS_BLOCK IoStatusBlock;
		SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;

		SecurityQualityOfService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
		SecurityQualityOfService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
		SecurityQualityOfService.ImpersonationLevel = SecurityImpersonation;
		SecurityQualityOfService.EffectiveOnly = TRUE;

		objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
		objAttr.RootDirectory = NULL;
		objAttr.Attributes = OBJ_CASE_INSENSITIVE;
		objAttr.ObjectName = &FileName;
		objAttr.SecurityDescriptor = NULL;
		objAttr.SecurityQualityOfService = &SecurityQualityOfService;

		if (0 != WinNtApi::NtCreateFile(
			&hFile, 
			GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES, 
			&objAttr, 
			&IoStatusBlock, 0, 
			FILE_ATTRIBUTE_SYSTEM, 
			FILE_SHARE_READ, 
			FILE_OPEN, 
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
			NULL, 0))
		{
			hFile = INVALID_HANDLE_VALUE;
			goto _Exit;
		}

		if (INVALID_HANDLE_VALUE == hFile)
		{
			// return immediately since hNtdllMod is hMod
			goto _Exit;
		}

		hMap = Win32Api::CreateFileMappingW(
			hFile, 0, PAGE_READONLY, 0, 0, NULL);
		if (NULL == hMap)
		{
			// return immediately since hNtdllMod is hMod
			goto _Exit;
		}

		pBuf = Win32Api::MapViewOfFile(
			hMap, FILE_MAP_READ, 0, 0, 0);

		if (pBuf)
		{
			*phNtdllMod = Util::LoadMemModule(pBuf, FALSE);

			if (NULL == *phNtdllMod)
			{
				Util::InterlockedCompareAndExchangePointer((PVOID*)phNtdllMod, hMod, NULL);
			}
		}

_Exit:
		if (pBuf)
		{
			Win32Api::UnmapViewOfFile(pBuf);
		}
		if (hMap)
		{
			Win32Api::CloseHandle(hMap);
		}
		if (INVALID_HANDLE_VALUE != hFile)
		{
			Win32Api::CloseHandle(hFile);
		}

		return *phNtdllMod;
	}

	PTEB NtCurrentTeb(void)
	{
#ifdef _M_IX86
		return (PTEB) __readfsdword(0x18);
#elif _M_IX64
		return (PTEB) __readgsqword(0x30);
#endif
	};

	NTSTATUS WINAPI LdrLoadDll(
		LPCWSTR path_name, 
		DWORD flags, 
		const UNICODE_STRING* libname, 
		HMODULE* phModule)
	{
		CHAR szProcName[] = {'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'l', 'l', '\0'};
		// LdrLoadDll函数不能在未初始化的Ntdll.dll模块中执行
		// 所以这里只能使用原始Ntdll.dll中的函数来完成
		Type_LdrLoadDll pfn = (Type_LdrLoadDll)(Win32Api::GetProcAddress(
			OriginalNtdllHanlde(),
			szProcName));

		return pfn(
			path_name, 
			flags, 
			libname, 
			phModule);
	}

	NTSTATUS WINAPI LdrGetProcedureAddress(
		HMODULE module, 
		const ANSI_STRING *name,
		ULONG ord, 
		PVOID *address)
	{
		CHAR szProcName[] = {'L', 'd', 'r', 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 'd', 'u', 'r', 'e', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0'};
		Type_LdrGetProcedureAddress pfn = (Type_LdrGetProcedureAddress)(Win32Api::GetProcAddress(
			OriginalNtdllHanlde(),
			szProcName));

		return pfn(
			module, 
			name, 
			ord, 
			address);
	}

	NTSTATUS WINAPI NtAcceptConnectPort(
		PHANDLE PortHandle, 
		ULONG PortIdentifier, 
		PVOID Message, 
		BOOLEAN Accept, 
		PVOID ServerView, 
		PVOID ClientView)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'c', 'c', 'e', 'p', 't', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'P', 'o', 'r', 't', '\0'};
		Type_NtAcceptConnectPort pfn = (Type_NtAcceptConnectPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			PortIdentifier, 
			Message, 
			Accept, 
			ServerView, 
			ClientView);
	}

	NTSTATUS WINAPI NtAccessCheck(
		PSECURITY_DESCRIPTOR SecurityDescriptor, 
		HANDLE TokenHandle, 
		ACCESS_MASK DesiredAccess, 
		PGENERIC_MAPPING GenericMapping, 
		PPRIVILEGE_SET PrivilegeSet, 
		PULONG PrivilegeSetLength, 
		PULONG GrantedAccess, 
		NTSTATUS* AccessStatus)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'c', 'c', 'e', 's', 's', 'C', 'h', 'e', 'c', 'k', '\0'};
		Type_NtAccessCheck pfn = (Type_NtAccessCheck)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SecurityDescriptor, 
			TokenHandle, 
			DesiredAccess, 
			GenericMapping, 
			PrivilegeSet, 
			PrivilegeSetLength, 
			GrantedAccess, 
			AccessStatus);
	}

	NTSTATUS WINAPI NtAccessCheckAndAuditAlarm(
		PUNICODE_STRING SubsystemName, 
		HANDLE HandleId, 
		PUNICODE_STRING ObjectTypeName, 
		PUNICODE_STRING ObjectName, 
		PSECURITY_DESCRIPTOR SecurityDescriptor, 
		ACCESS_MASK DesiredAccess, 
		PGENERIC_MAPPING GenericMapping, 
		BOOLEAN ObjectCreation, 
		PACCESS_MASK GrantedAccess, 
		PBOOLEAN AccessStatus, 
		PBOOLEAN GenerateOnClose)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'c', 'c', 'e', 's', 's', 'C', 'h', 'e', 'c', 'k', 'A', 'n', 'd', 'A', 'u', 'd', 'i', 't', 'A', 'l', 'a', 'r', 'm', '\0'};
		Type_NtAccessCheckAndAuditAlarm pfn = (Type_NtAccessCheckAndAuditAlarm)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SubsystemName, 
			HandleId, 
			ObjectTypeName, 
			ObjectName, 
			SecurityDescriptor, 
			DesiredAccess, 
			GenericMapping, 
			ObjectCreation, 
			GrantedAccess, 
			AccessStatus, 
			GenerateOnClose);
	}

	NTSTATUS WINAPI NtAddAtom(
		const WCHAR* String, 
		ULONG StringLength, 
		PVOID Atom)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'd', 'd', 'A', 't', 'o', 'm', '\0'};
		Type_NtAddAtom pfn = (Type_NtAddAtom)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			String, 
			StringLength, 
			Atom);
	}

	NTSTATUS WINAPI NtAdjustGroupsToken(
		HANDLE TokenHandle, 
		BOOLEAN ResetToDefault, 
		PTOKEN_GROUPS NewState, 
		ULONG BufferLength, 
		PTOKEN_GROUPS PreviousState, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'd', 'j', 'u', 's', 't', 'G', 'r', 'o', 'u', 'p', 's', 'T', 'o', 'k', 'e', 'n', '\0'};
		Type_NtAdjustGroupsToken pfn = (Type_NtAdjustGroupsToken)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TokenHandle, 
			ResetToDefault, 
			NewState, 
			BufferLength, 
			PreviousState, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtAdjustPrivilegesToken(
		HANDLE TokenHandle, 
		BOOLEAN DisableAllPrivileges, 
		PTOKEN_PRIVILEGES NewState, 
		DWORD BufferLength, 
		PTOKEN_PRIVILEGES PreviousState, 
		PDWORD ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'd', 'j', 'u', 's', 't', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 's', 'T', 'o', 'k', 'e', 'n', '\0'};
		Type_NtAdjustPrivilegesToken pfn = (Type_NtAdjustPrivilegesToken)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TokenHandle, 
			DisableAllPrivileges, 
			NewState, 
			BufferLength, 
			PreviousState, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtAlertResumeThread(
		HANDLE ThreadHandle, 
		PULONG PreviousSuspendCount)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'l', 'e', 'r', 't', 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtAlertResumeThread pfn = (Type_NtAlertResumeThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			PreviousSuspendCount);
	}

	NTSTATUS WINAPI NtAlertThread(
		HANDLE ThreadHandle)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'l', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtAlertThread pfn = (Type_NtAlertThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle);
	}

	NTSTATUS WINAPI NtAllocateLocallyUniqueId(
		PLUID Luid)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'L', 'o', 'c', 'a', 'l', 'l', 'y', 'U', 'n', 'i', 'q', 'u', 'e', 'I', 'd', '\0'};
		Type_NtAllocateLocallyUniqueId pfn = (Type_NtAllocateLocallyUniqueId)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Luid);
	}

	NTSTATUS WINAPI NtAllocateVirtualMemory(
		HANDLE ProcessHandle, 
		PVOID* BaseAddress, 
		ULONG ZeroBits, 
		SIZE_T* AllocationSize, 
		ULONG AllocationType, 
		ULONG Protect)
	{
		CHAR szProcName[] = {'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtAllocateVirtualMemory pfn = (Type_NtAllocateVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			ZeroBits, 
			AllocationSize, 
			AllocationType, 
			Protect);
	}

	NTSTATUS WINAPI NtCallbackReturn(
		PVOID Result, 
		ULONG ResultLength, 
		NTSTATUS Status)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'a', 'l', 'l', 'b', 'a', 'c', 'k', 'R', 'e', 't', 'u', 'r', 'n', '\0'};
		Type_NtCallbackReturn pfn = (Type_NtCallbackReturn)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Result, 
			ResultLength, 
			Status);
	}

	NTSTATUS WINAPI NtCancelIoFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'a', 'n', 'c', 'e', 'l', 'I', 'o', 'F', 'i', 'l', 'e', '\0'};
		Type_NtCancelIoFile pfn = (Type_NtCancelIoFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock);
	}

	NTSTATUS WINAPI NtCancelTimer(
		HANDLE TimerHandle, 
		BOOLEAN* PreviousState)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'a', 'n', 'c', 'e', 'l', 'T', 'i', 'm', 'e', 'r', '\0'};
		Type_NtCancelTimer pfn = (Type_NtCancelTimer)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TimerHandle, 
			PreviousState);
	}

	NTSTATUS WINAPI NtClearEvent(
		HANDLE EventHandle)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'l', 'e', 'a', 'r', 'E', 'v', 'e', 'n', 't', '\0'};
		Type_NtClearEvent pfn = (Type_NtClearEvent)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventHandle);
	}

	NTSTATUS WINAPI NtClose(
		HANDLE Handle)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'l', 'o', 's', 'e', '\0'};
		Type_NtClose pfn = (Type_NtClose)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Handle);
	}

	NTSTATUS WINAPI NtCloseObjectAuditAlarm(
		PUNICODE_STRING SubsystemName, 
		HANDLE Id, 
		BOOLEAN GenerateOnClose)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'l', 'o', 's', 'e', 'O', 'b', 'j', 'e', 'c', 't', 'A', 'u', 'd', 'i', 't', 'A', 'l', 'a', 'r', 'm', '\0'};
		Type_NtCloseObjectAuditAlarm pfn = (Type_NtCloseObjectAuditAlarm)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SubsystemName, 
			Id, 
			GenerateOnClose);
	}

	NTSTATUS WINAPI NtCompleteConnectPort(
		HANDLE PortHandle)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'o', 'm', 'p', 'l', 'e', 't', 'e', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'P', 'o', 'r', 't', '\0'};
		Type_NtCompleteConnectPort pfn = (Type_NtCompleteConnectPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle);
	}

	NTSTATUS WINAPI NtConnectPort(
		PHANDLE PortHandle, 
		PUNICODE_STRING PortName, 
		PSECURITY_QUALITY_OF_SERVICE SecurityQos, 
		PVOID ClientView, 
		PVOID ServerView, 
		PULONG MaxMessageLength, 
		PVOID ConnectInformation, 
		PULONG ConnectInformationLength)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'P', 'o', 'r', 't', '\0'};
		Type_NtConnectPort pfn = (Type_NtConnectPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			PortName, 
			SecurityQos, 
			ClientView, 
			ServerView, 
			MaxMessageLength, 
			ConnectInformation, 
			ConnectInformationLength);
	}

	NTSTATUS WINAPI NtContinue(
		PCONTEXT Context, 
		BOOLEAN TestAlert)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'o', 'n', 't', 'i', 'n', 'u', 'e', '\0'};
		Type_NtContinue pfn = (Type_NtContinue)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Context, 
			TestAlert);
	}

	NTSTATUS WINAPI NtCreateDirectoryObject(
		PHANDLE DirectoryHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtCreateDirectoryObject pfn = (Type_NtCreateDirectoryObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			DirectoryHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtCreateEvent(
		PHANDLE EventHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		PVOID EventType, 
		BOOLEAN InitialState)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'E', 'v', 'e', 'n', 't', '\0'};
		Type_NtCreateEvent pfn = (Type_NtCreateEvent)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			EventType, 
			InitialState);
	}

	NTSTATUS WINAPI NtCreateEventPair(
		PHANDLE EventPairHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'E', 'v', 'e', 'n', 't', 'P', 'a', 'i', 'r', '\0'};
		Type_NtCreateEventPair pfn = (Type_NtCreateEventPair)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventPairHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtCreateFile(
		PHANDLE FileHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PLARGE_INTEGER AllocationSize, 
		ULONG FileAttributes, 
		ULONG ShareAccess, 
		ULONG CreateDisposition, 
		ULONG CreateOptions, 
		PVOID EaBuffer, 
		ULONG EaLength)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', '\0'};
		Type_NtCreateFile pfn = (Type_NtCreateFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			IoStatusBlock, 
			AllocationSize, 
			FileAttributes, 
			ShareAccess, 
			CreateDisposition, 
			CreateOptions, 
			EaBuffer, 
			EaLength);
	}

	NTSTATUS WINAPI NtCreateIoCompletion(
		PHANDLE IoCompletionHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		ULONG NumberOfConcurrentThreads)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'I', 'o', 'C', 'o', 'm', 'p', 'l', 'e', 't', 'i', 'o', 'n', '\0'};
		Type_NtCreateIoCompletion pfn = (Type_NtCreateIoCompletion)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			IoCompletionHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			NumberOfConcurrentThreads);
	}

	NTSTATUS WINAPI NtCreateKey(
		PHANDLE KeyHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		ULONG TitleIndex, 
		const UNICODE_STRING* Class, 
		ULONG CreateOptions, 
		PULONG Disposition)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'K', 'e', 'y', '\0'};
		Type_NtCreateKey pfn = (Type_NtCreateKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			TitleIndex, 
			Class, 
			CreateOptions, 
			Disposition);
	}

	NTSTATUS WINAPI NtCreateMailslotFile(
		PHANDLE FileHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		ULONG CreateOptions, 
		ULONG InBufferSize, 
		ULONG MaxMessageSize, 
		PLARGE_INTEGER ReadTime)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'M', 'a', 'i', 'l', 's', 'l', 'o', 't', 'F', 'i', 'l', 'e', '\0'};
		Type_NtCreateMailslotFile pfn = (Type_NtCreateMailslotFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			IoStatusBlock, 
			CreateOptions, 
			InBufferSize, 
			MaxMessageSize, 
			ReadTime);
	}

	NTSTATUS WINAPI NtCreateMutant(
		HANDLE* MutantHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		BOOLEAN InitialOwner)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'M', 'u', 't', 'a', 'n', 't', '\0'};
		Type_NtCreateMutant pfn = (Type_NtCreateMutant)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			MutantHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			InitialOwner);
	}

	NTSTATUS WINAPI NtCreateNamedPipeFile(
		PHANDLE FileHandle, 
		ULONG DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		ULONG ShareAccess, 
		ULONG CreateDisposition, 
		ULONG CreateOptions, 
		ULONG TypeMessage, 
		ULONG ReadmodeMessage, 
		ULONG Nonblocking, 
		ULONG MaxInstances, 
		ULONG InBufferSize, 
		ULONG OutBufferSize, 
		PLARGE_INTEGER DefaultTime)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'N', 'a', 'm', 'e', 'd', 'P', 'i', 'p', 'e', 'F', 'i', 'l', 'e', '\0'};
		Type_NtCreateNamedPipeFile pfn = (Type_NtCreateNamedPipeFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			IoStatusBlock, 
			ShareAccess, 
			CreateDisposition, 
			CreateOptions, 
			TypeMessage, 
			ReadmodeMessage, 
			Nonblocking, 
			MaxInstances, 
			InBufferSize, 
			OutBufferSize, 
			DefaultTime);
	}

	NTSTATUS WINAPI NtCreatePagingFile(
		PUNICODE_STRING FileName, 
		PLARGE_INTEGER InitialSize, 
		PLARGE_INTEGER MaximumSize, 
		PLARGE_INTEGER Priority)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'a', 'g', 'i', 'n', 'g', 'F', 'i', 'l', 'e', '\0'};
		Type_NtCreatePagingFile pfn = (Type_NtCreatePagingFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileName, 
			InitialSize, 
			MaximumSize, 
			Priority);
	}

	NTSTATUS WINAPI NtCreatePort(
		PHANDLE PortHandle, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		ULONG MaxConnectionInfoLength, 
		ULONG MaxMessageLength, 
		PULONG MaxPoolUsage)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'o', 'r', 't', '\0'};
		Type_NtCreatePort pfn = (Type_NtCreatePort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			ObjectAttributes, 
			MaxConnectionInfoLength, 
			MaxMessageLength, 
			MaxPoolUsage);
	}

	NTSTATUS WINAPI NtCreateProcess(
		PHANDLE ProcessHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		HANDLE InheritFromProcessHandle, 
		BOOLEAN InheritHandles, 
		HANDLE SectionHandle, 
		HANDLE DebugPort, 
		HANDLE ExceptionPort)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0'};
		Type_NtCreateProcess pfn = (Type_NtCreateProcess)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			InheritFromProcessHandle, 
			InheritHandles, 
			SectionHandle, 
			DebugPort, 
			ExceptionPort);
	}

	NTSTATUS WINAPI NtCreateProfile(
		PHANDLE ProfileHandle, 
		HANDLE ProcessHandle, 
		PVOID Base, 
		ULONG Size, 
		ULONG BucketShift, 
		PVOID Buffer, 
		ULONG BufferLength, 
		PVOID Source, 
		KAFFINITY ProcessorMask)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'f', 'i', 'l', 'e', '\0'};
		Type_NtCreateProfile pfn = (Type_NtCreateProfile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProfileHandle, 
			ProcessHandle, 
			Base, 
			Size, 
			BucketShift, 
			Buffer, 
			BufferLength, 
			Source, 
			ProcessorMask);
	}

	NTSTATUS WINAPI NtCreateSection(
		HANDLE* SectionHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		const LARGE_INTEGER* SectionSize, 
		ULONG Protect, 
		ULONG Attributes, 
		HANDLE FileHandle)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0'};
		Type_NtCreateSection pfn = (Type_NtCreateSection)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SectionHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			SectionSize, 
			Protect, 
			Attributes, 
			FileHandle);
	}

	NTSTATUS WINAPI NtCreateSemaphore(
		PHANDLE SemaphoreHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		LONG InitialCount, 
		LONG MaximumCount)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'm', 'a', 'p', 'h', 'o', 'r', 'e', '\0'};
		Type_NtCreateSemaphore pfn = (Type_NtCreateSemaphore)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SemaphoreHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			InitialCount, 
			MaximumCount);
	}

	NTSTATUS WINAPI NtCreateSymbolicLinkObject(
		PHANDLE SymbolicLinkHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		PUNICODE_STRING TargetName)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'y', 'm', 'b', 'o', 'l', 'i', 'c', 'L', 'i', 'n', 'k', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtCreateSymbolicLinkObject pfn = (Type_NtCreateSymbolicLinkObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SymbolicLinkHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			TargetName);
	}

	NTSTATUS WINAPI NtCreateThread(
		PHANDLE ThreadHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		HANDLE ProcessHandle, 
		PCLIENT_ID ClientId, 
		PCONTEXT ThreadContext, 
		PVOID UserStack, 
		BOOLEAN CreateSuspended)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtCreateThread pfn = (Type_NtCreateThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			ProcessHandle, 
			ClientId, 
			ThreadContext, 
			UserStack, 
			CreateSuspended);
	}

	NTSTATUS WINAPI NtCreateTimer(
		HANDLE* TimerHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		PVOID TimerType)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'i', 'm', 'e', 'r', '\0'};
		Type_NtCreateTimer pfn = (Type_NtCreateTimer)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TimerHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			TimerType);
	}

	NTSTATUS WINAPI NtCreateToken(
		PHANDLE TokenHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		TOKEN_TYPE Type, 
		PLUID AuthenticationId, 
		PLARGE_INTEGER ExpirationTime, 
		PTOKEN_USER User, 
		PTOKEN_GROUPS Groups, 
		PTOKEN_PRIVILEGES Privileges, 
		PTOKEN_OWNER Owner, 
		PTOKEN_PRIMARY_GROUP PrimaryGroup, 
		PTOKEN_DEFAULT_DACL DefaultDacl, 
		PTOKEN_SOURCE Source)
	{
		CHAR szProcName[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'k', 'e', 'n', '\0'};
		Type_NtCreateToken pfn = (Type_NtCreateToken)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TokenHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			Type, 
			AuthenticationId, 
			ExpirationTime, 
			User, 
			Groups, 
			Privileges, 
			Owner, 
			PrimaryGroup, 
			DefaultDacl, 
			Source);
	}

	NTSTATUS WINAPI NtDelayExecution(
		BOOLEAN Alertable, 
		const LARGE_INTEGER* Interval)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', '\0'};
		Type_NtDelayExecution pfn = (Type_NtDelayExecution)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Alertable, 
			Interval);
	}

	NTSTATUS WINAPI NtDeleteAtom(
		PVOID Atom)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'e', 'l', 'e', 't', 'e', 'A', 't', 'o', 'm', '\0'};
		Type_NtDeleteAtom pfn = (Type_NtDeleteAtom)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Atom);
	}

	NTSTATUS WINAPI NtDeleteFile(
		POBJECT_ATTRIBUTES ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'e', 'l', 'e', 't', 'e', 'F', 'i', 'l', 'e', '\0'};
		Type_NtDeleteFile pfn = (Type_NtDeleteFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtDeleteKey(
		HANDLE KeyHandle)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'e', 'l', 'e', 't', 'e', 'K', 'e', 'y', '\0'};
		Type_NtDeleteKey pfn = (Type_NtDeleteKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle);
	}

	NTSTATUS WINAPI NtDeleteValueKey(
		HANDLE KeyHandle, 
		const UNICODE_STRING* ValueName)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'e', 'l', 'e', 't', 'e', 'V', 'a', 'l', 'u', 'e', 'K', 'e', 'y', '\0'};
		Type_NtDeleteValueKey pfn = (Type_NtDeleteValueKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			ValueName);
	}

	NTSTATUS WINAPI NtDeviceIoControlFile(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		ULONG IoControlCode, 
		PVOID InputBuffer, 
		ULONG InputBufferLength, 
		PVOID OutputBuffer, 
		ULONG OutputBufferLength)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'e', 'v', 'i', 'c', 'e', 'I', 'o', 'C', 'o', 'n', 't', 'r', 'o', 'l', 'F', 'i', 'l', 'e', '\0'};
		Type_NtDeviceIoControlFile pfn = (Type_NtDeviceIoControlFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			IoControlCode, 
			InputBuffer, 
			InputBufferLength, 
			OutputBuffer, 
			OutputBufferLength);
	}

	NTSTATUS WINAPI NtDisplayString(
		PUNICODE_STRING String)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'i', 's', 'p', 'l', 'a', 'y', 'S', 't', 'r', 'i', 'n', 'g', '\0'};
		Type_NtDisplayString pfn = (Type_NtDisplayString)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			String);
	}

	NTSTATUS WINAPI NtDuplicateObject(
		HANDLE SourceProcessHandle, 
		HANDLE SourceHandle, 
		HANDLE TargetProcessHandle, 
		PHANDLE TargetHandle, 
		ACCESS_MASK DesiredAccess, 
		ULONG Attributes, 
		ULONG Options)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'u', 'p', 'l', 'i', 'c', 'a', 't', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtDuplicateObject pfn = (Type_NtDuplicateObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SourceProcessHandle, 
			SourceHandle, 
			TargetProcessHandle, 
			TargetHandle, 
			DesiredAccess, 
			Attributes, 
			Options);
	}

	NTSTATUS WINAPI NtDuplicateToken(
		HANDLE ExistingTokenHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		SECURITY_IMPERSONATION_LEVEL EffectiveOnly, 
		TOKEN_TYPE TokenType, 
		PHANDLE NewTokenHandle)
	{
		CHAR szProcName[] = {'N', 't', 'D', 'u', 'p', 'l', 'i', 'c', 'a', 't', 'e', 'T', 'o', 'k', 'e', 'n', '\0'};
		Type_NtDuplicateToken pfn = (Type_NtDuplicateToken)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ExistingTokenHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			EffectiveOnly, 
			TokenType, 
			NewTokenHandle);
	}

	NTSTATUS WINAPI NtEnumerateKey(
		HANDLE KeyHandle, 
		ULONG Index, 
		PVOID KeyInformationClass, 
		void* KeyInformation, 
		DWORD KeyInformationLength, 
		DWORD* ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'E', 'n', 'u', 'm', 'e', 'r', 'a', 't', 'e', 'K', 'e', 'y', '\0'};
		Type_NtEnumerateKey pfn = (Type_NtEnumerateKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			Index, 
			KeyInformationClass, 
			KeyInformation, 
			KeyInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtEnumerateValueKey(
		HANDLE KeyHandle, 
		ULONG Index, 
		PVOID KeyValueInformationClass, 
		PVOID KeyValueInformation, 
		ULONG KeyValueInformationLength, 
		PULONG ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'E', 'n', 'u', 'm', 'e', 'r', 'a', 't', 'e', 'V', 'a', 'l', 'u', 'e', 'K', 'e', 'y', '\0'};
		Type_NtEnumerateValueKey pfn = (Type_NtEnumerateValueKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			Index, 
			KeyValueInformationClass, 
			KeyValueInformation, 
			KeyValueInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtExtendSection(
		HANDLE SectionHandle, 
		PLARGE_INTEGER SectionSize)
	{
		CHAR szProcName[] = {'N', 't', 'E', 'x', 't', 'e', 'n', 'd', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0'};
		Type_NtExtendSection pfn = (Type_NtExtendSection)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SectionHandle, 
			SectionSize);
	}

	NTSTATUS WINAPI NtFindAtom(
		const WCHAR* String, 
		ULONG StringLength, 
		PVOID* Atom)
	{
		CHAR szProcName[] = {'N', 't', 'F', 'i', 'n', 'd', 'A', 't', 'o', 'm', '\0'};
		Type_NtFindAtom pfn = (Type_NtFindAtom)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			String, 
			StringLength, 
			Atom);
	}

	NTSTATUS WINAPI NtFlushBuffersFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock)
	{
		CHAR szProcName[] = {'N', 't', 'F', 'l', 'u', 's', 'h', 'B', 'u', 'f', 'f', 'e', 'r', 's', 'F', 'i', 'l', 'e', '\0'};
		Type_NtFlushBuffersFile pfn = (Type_NtFlushBuffersFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock);
	}

	NTSTATUS WINAPI NtFlushInstructionCache(
		HANDLE ProcessHandle, 
		LPCVOID BaseAddress, 
		SIZE_T FlushSize)
	{
		CHAR szProcName[] = {'N', 't', 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e', '\0'};
		Type_NtFlushInstructionCache pfn = (Type_NtFlushInstructionCache)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			FlushSize);
	}

	NTSTATUS WINAPI NtFlushKey(
		HANDLE KeyHandle)
	{
		CHAR szProcName[] = {'N', 't', 'F', 'l', 'u', 's', 'h', 'K', 'e', 'y', '\0'};
		Type_NtFlushKey pfn = (Type_NtFlushKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle);
	}

	NTSTATUS WINAPI NtFlushVirtualMemory(
		HANDLE ProcessHandle, 
		LPCVOID* BaseAddress, 
		SIZE_T* FlushSize, 
		ULONG IoStatusBlock)
	{
		CHAR szProcName[] = {'N', 't', 'F', 'l', 'u', 's', 'h', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtFlushVirtualMemory pfn = (Type_NtFlushVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			FlushSize, 
			IoStatusBlock);
	}

	NTSTATUS WINAPI NtFlushWriteBuffer()
	{
		CHAR szProcName[] = {'N', 't', 'F', 'l', 'u', 's', 'h', 'W', 'r', 'i', 't', 'e', 'B', 'u', 'f', 'f', 'e', 'r', '\0'};
		Type_NtFlushWriteBuffer pfn = (Type_NtFlushWriteBuffer)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn();
	}

	NTSTATUS WINAPI NtFreeVirtualMemory(
		HANDLE ProcessHandle, 
		PVOID* BaseAddress, 
		SIZE_T* FreeSize, 
		ULONG FreeType)
	{
		CHAR szProcName[] = {'N', 't', 'F', 'r', 'e', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtFreeVirtualMemory pfn = (Type_NtFreeVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			FreeSize, 
			FreeType);
	}

	NTSTATUS WINAPI NtFsControlFile(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		ULONG FsControlCode, 
		PVOID InputBuffer, 
		ULONG InputBufferLength, 
		PVOID OutputBuffer, 
		ULONG OutputBufferLength)
	{
		CHAR szProcName[] = {'N', 't', 'F', 's', 'C', 'o', 'n', 't', 'r', 'o', 'l', 'F', 'i', 'l', 'e', '\0'};
		Type_NtFsControlFile pfn = (Type_NtFsControlFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			FsControlCode, 
			InputBuffer, 
			InputBufferLength, 
			OutputBuffer, 
			OutputBufferLength);
	}

	NTSTATUS WINAPI NtGetContextThread(
		HANDLE ThreadHandle, 
		CONTEXT* Context)
	{
		CHAR szProcName[] = {'N', 't', 'G', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtGetContextThread pfn = (Type_NtGetContextThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			Context);
	}

	NTSTATUS WINAPI NtGetPlugPlayEvent(
		ULONG Reserved1, 
		ULONG Reserved2, 
		PVOID Buffer, 
		ULONG BufferLength)
	{
		CHAR szProcName[] = {'N', 't', 'G', 'e', 't', 'P', 'l', 'u', 'g', 'P', 'l', 'a', 'y', 'E', 'v', 'e', 'n', 't', '\0'};
		Type_NtGetPlugPlayEvent pfn = (Type_NtGetPlugPlayEvent)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Reserved1, 
			Reserved2, 
			Buffer, 
			BufferLength);
	}

	NTSTATUS WINAPI NtImpersonateClientOfPort(
		HANDLE PortHandle, 
		PVOID Message)
	{
		CHAR szProcName[] = {'N', 't', 'I', 'm', 'p', 'e', 'r', 's', 'o', 'n', 'a', 't', 'e', 'C', 'l', 'i', 'e', 'n', 't', 'O', 'f', 'P', 'o', 'r', 't', '\0'};
		Type_NtImpersonateClientOfPort pfn = (Type_NtImpersonateClientOfPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			Message);
	}

	NTSTATUS WINAPI NtImpersonateThread(
		HANDLE ThreadHandle, 
		HANDLE TargetThreadHandle, 
		PSECURITY_QUALITY_OF_SERVICE SecurityQos)
	{
		CHAR szProcName[] = {'N', 't', 'I', 'm', 'p', 'e', 'r', 's', 'o', 'n', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtImpersonateThread pfn = (Type_NtImpersonateThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			TargetThreadHandle, 
			SecurityQos);
	}

	NTSTATUS WINAPI NtInitializeRegistry(
		BOOLEAN Setup)
	{
		CHAR szProcName[] = {'N', 't', 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'R', 'e', 'g', 'i', 's', 't', 'r', 'y', '\0'};
		Type_NtInitializeRegistry pfn = (Type_NtInitializeRegistry)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Setup);
	}

	NTSTATUS WINAPI NtListenPort(
		HANDLE PortHandle, 
		PVOID Message)
	{
		CHAR szProcName[] = {'N', 't', 'L', 'i', 's', 't', 'e', 'n', 'P', 'o', 'r', 't', '\0'};
		Type_NtListenPort pfn = (Type_NtListenPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			Message);
	}

	NTSTATUS WINAPI NtLoadDriver(
		const UNICODE_STRING* DriverServiceName)
	{
		CHAR szProcName[] = {'N', 't', 'L', 'o', 'a', 'd', 'D', 'r', 'i', 'v', 'e', 'r', '\0'};
		Type_NtLoadDriver pfn = (Type_NtLoadDriver)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			DriverServiceName);
	}

	NTSTATUS WINAPI NtLoadKey(
		const OBJECT_ATTRIBUTES* KeyObjectAttributes, 
		OBJECT_ATTRIBUTES* FileObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'L', 'o', 'a', 'd', 'K', 'e', 'y', '\0'};
		Type_NtLoadKey pfn = (Type_NtLoadKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyObjectAttributes, 
			FileObjectAttributes);
	}

	NTSTATUS WINAPI NtLockFile(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		void* ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PLARGE_INTEGER LockOffset, 
		PLARGE_INTEGER LockLength, 
		ULONG* Key, 
		BOOLEAN FailImmediately, 
		BOOLEAN ExclusiveLock)
	{
		CHAR szProcName[] = {'N', 't', 'L', 'o', 'c', 'k', 'F', 'i', 'l', 'e', '\0'};
		Type_NtLockFile pfn = (Type_NtLockFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			LockOffset, 
			LockLength, 
			Key, 
			FailImmediately, 
			ExclusiveLock);
	}

	NTSTATUS WINAPI NtLockVirtualMemory(
		HANDLE ProcessHandle, 
		PVOID* BaseAddress, 
		SIZE_T* LockSize, 
		ULONG LockType)
	{
		CHAR szProcName[] = {'N', 't', 'L', 'o', 'c', 'k', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtLockVirtualMemory pfn = (Type_NtLockVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			LockSize, 
			LockType);
	}

	NTSTATUS WINAPI NtMapViewOfSection(
		HANDLE SectionHandle, 
		HANDLE ProcessHandle, 
		PVOID* BaseAddress, 
		ULONG ZeroBits, 
		SIZE_T CommitSize, 
		const LARGE_INTEGER* SectionOffset, 
		SIZE_T* ViewSize, 
		SECTION_INHERIT InheritDisposition, 
		ULONG AllocationType, 
		ULONG Protect)
	{
		CHAR szProcName[] = {'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0'};
		Type_NtMapViewOfSection pfn = (Type_NtMapViewOfSection)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SectionHandle, 
			ProcessHandle, 
			BaseAddress, 
			ZeroBits, 
			CommitSize, 
			SectionOffset, 
			ViewSize, 
			InheritDisposition, 
			AllocationType, 
			Protect);
	}

	NTSTATUS WINAPI NtNotifyChangeDirectoryFile(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID Buffer, 
		ULONG BufferLength, 
		ULONG NotifyFilter, 
		BOOLEAN WatchSubtree)
	{
		CHAR szProcName[] = {'N', 't', 'N', 'o', 't', 'i', 'f', 'y', 'C', 'h', 'a', 'n', 'g', 'e', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'F', 'i', 'l', 'e', '\0'};
		Type_NtNotifyChangeDirectoryFile pfn = (Type_NtNotifyChangeDirectoryFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			Buffer, 
			BufferLength, 
			NotifyFilter, 
			WatchSubtree);
	}

	NTSTATUS WINAPI NtNotifyChangeKey(
		HANDLE KeyHandle, 
		HANDLE EventHandle, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		ULONG NotifyFilter, 
		BOOLEAN WatchSubtree, 
		PVOID Buffer, 
		ULONG BufferLength, 
		BOOLEAN Asynchronous)
	{
		CHAR szProcName[] = {'N', 't', 'N', 'o', 't', 'i', 'f', 'y', 'C', 'h', 'a', 'n', 'g', 'e', 'K', 'e', 'y', '\0'};
		Type_NtNotifyChangeKey pfn = (Type_NtNotifyChangeKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			EventHandle, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			NotifyFilter, 
			WatchSubtree, 
			Buffer, 
			BufferLength, 
			Asynchronous);
	}

	NTSTATUS WINAPI NtOpenDirectoryObject(
		PHANDLE DirectoryHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtOpenDirectoryObject pfn = (Type_NtOpenDirectoryObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			DirectoryHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenEvent(
		PHANDLE EventHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'E', 'v', 'e', 'n', 't', '\0'};
		Type_NtOpenEvent pfn = (Type_NtOpenEvent)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenEventPair(
		PHANDLE EventPairHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'E', 'v', 'e', 'n', 't', 'P', 'a', 'i', 'r', '\0'};
		Type_NtOpenEventPair pfn = (Type_NtOpenEventPair)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventPairHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenFile(
		PHANDLE FileHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		ULONG ShareAccess, 
		ULONG OpenOptions)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'F', 'i', 'l', 'e', '\0'};
		Type_NtOpenFile pfn = (Type_NtOpenFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			IoStatusBlock, 
			ShareAccess, 
			OpenOptions);
	}

	NTSTATUS WINAPI NtOpenIoCompletion(
		PHANDLE IoCompletionHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'I', 'o', 'C', 'o', 'm', 'p', 'l', 'e', 't', 'i', 'o', 'n', '\0'};
		Type_NtOpenIoCompletion pfn = (Type_NtOpenIoCompletion)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			IoCompletionHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenKey(
		PHANDLE KeyHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'K', 'e', 'y', '\0'};
		Type_NtOpenKey pfn = (Type_NtOpenKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenMutant(
		PHANDLE MutantHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'M', 'u', 't', 'a', 'n', 't', '\0'};
		Type_NtOpenMutant pfn = (Type_NtOpenMutant)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			MutantHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenObjectAuditAlarm(
		PUNICODE_STRING SubsystemName, 
		PHANDLE HandleId, 
		PUNICODE_STRING ObjectTypeName, 
		PUNICODE_STRING ObjectName, 
		PSECURITY_DESCRIPTOR SecurityDescriptor, 
		HANDLE TokenHandle, 
		ACCESS_MASK DesiredAccess, 
		ACCESS_MASK GrantedAccess, 
		PPRIVILEGE_SET Privileges, 
		BOOLEAN ObjectCreation, 
		BOOLEAN AccessGranted, 
		PBOOLEAN GenerateOnClose)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'O', 'b', 'j', 'e', 'c', 't', 'A', 'u', 'd', 'i', 't', 'A', 'l', 'a', 'r', 'm', '\0'};
		Type_NtOpenObjectAuditAlarm pfn = (Type_NtOpenObjectAuditAlarm)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SubsystemName, 
			HandleId, 
			ObjectTypeName, 
			ObjectName, 
			SecurityDescriptor, 
			TokenHandle, 
			DesiredAccess, 
			GrantedAccess, 
			Privileges, 
			ObjectCreation, 
			AccessGranted, 
			GenerateOnClose);
	}

	NTSTATUS WINAPI NtOpenProcess(
		PHANDLE ProcessHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		const CLIENT_ID* ClientId)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0'};
		Type_NtOpenProcess pfn = (Type_NtOpenProcess)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			ClientId);
	}

	NTSTATUS WINAPI NtOpenProcessToken(
		HANDLE ProcessHandle, 
		DWORD DesiredAccess, 
		HANDLE* TokenHandle)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 'T', 'o', 'k', 'e', 'n', '\0'};
		Type_NtOpenProcessToken pfn = (Type_NtOpenProcessToken)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			DesiredAccess, 
			TokenHandle);
	}

	NTSTATUS WINAPI NtOpenSection(
		HANDLE* SectionHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0'};
		Type_NtOpenSection pfn = (Type_NtOpenSection)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SectionHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenSemaphore(
		PHANDLE SemaphoreHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'S', 'e', 'm', 'a', 'p', 'h', 'o', 'r', 'e', '\0'};
		Type_NtOpenSemaphore pfn = (Type_NtOpenSemaphore)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SemaphoreHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenSymbolicLinkObject(
		PHANDLE SymbolicLinkHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'S', 'y', 'm', 'b', 'o', 'l', 'i', 'c', 'L', 'i', 'n', 'k', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtOpenSymbolicLinkObject pfn = (Type_NtOpenSymbolicLinkObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SymbolicLinkHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtOpenThread(
		HANDLE* ThreadHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		const CLIENT_ID* ClientId)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtOpenThread pfn = (Type_NtOpenThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			DesiredAccess, 
			ObjectAttributes, 
			ClientId);
	}

	NTSTATUS WINAPI NtOpenThreadToken(
		HANDLE ThreadHandle, 
		DWORD DesiredAccess, 
		BOOLEAN OpenAsSelf, 
		HANDLE* TokenHandle)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'k', 'e', 'n', '\0'};
		Type_NtOpenThreadToken pfn = (Type_NtOpenThreadToken)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			DesiredAccess, 
			OpenAsSelf, 
			TokenHandle);
	}

	NTSTATUS WINAPI NtOpenTimer(
		HANDLE* TimerHandle, 
		ACCESS_MASK DesiredAccess, 
		const OBJECT_ATTRIBUTES* ObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'O', 'p', 'e', 'n', 'T', 'i', 'm', 'e', 'r', '\0'};
		Type_NtOpenTimer pfn = (Type_NtOpenTimer)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TimerHandle, 
			DesiredAccess, 
			ObjectAttributes);
	}

	NTSTATUS WINAPI NtPrivilegeCheck(
		HANDLE TokenHandle, 
		PPRIVILEGE_SET RequiredPrivileges, 
		PBOOLEAN Result)
	{
		CHAR szProcName[] = {'N', 't', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 'C', 'h', 'e', 'c', 'k', '\0'};
		Type_NtPrivilegeCheck pfn = (Type_NtPrivilegeCheck)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TokenHandle, 
			RequiredPrivileges, 
			Result);
	}

	NTSTATUS WINAPI NtPrivilegeObjectAuditAlarm(
		PUNICODE_STRING SubsystemName, 
		HANDLE Id, 
		HANDLE TokenHandle, 
		ULONG DesiredAccess, 
		PPRIVILEGE_SET Privileges, 
		BOOLEAN AccessGranted)
	{
		CHAR szProcName[] = {'N', 't', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 'O', 'b', 'j', 'e', 'c', 't', 'A', 'u', 'd', 'i', 't', 'A', 'l', 'a', 'r', 'm', '\0'};
		Type_NtPrivilegeObjectAuditAlarm pfn = (Type_NtPrivilegeObjectAuditAlarm)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SubsystemName, 
			Id, 
			TokenHandle, 
			DesiredAccess, 
			Privileges, 
			AccessGranted);
	}

	NTSTATUS WINAPI NtPrivilegedServiceAuditAlarm(
		PUNICODE_STRING SubsystemName, 
		PUNICODE_STRING ServiceName, 
		HANDLE TokenHandle, 
		PPRIVILEGE_SET Privileges, 
		BOOLEAN AccessGranted)
	{
		CHAR szProcName[] = {'N', 't', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 'd', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'A', 'u', 'd', 'i', 't', 'A', 'l', 'a', 'r', 'm', '\0'};
		Type_NtPrivilegedServiceAuditAlarm pfn = (Type_NtPrivilegedServiceAuditAlarm)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SubsystemName, 
			ServiceName, 
			TokenHandle, 
			Privileges, 
			AccessGranted);
	}

	NTSTATUS WINAPI NtProtectVirtualMemory(
		HANDLE ProcessHandle, 
		PVOID* BaseAddress, 
		PULONG ProtectSize, 
		ULONG NewProtect, 
		PULONG OldProtect)
	{
		CHAR szProcName[] = {'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtProtectVirtualMemory pfn = (Type_NtProtectVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			ProtectSize, 
			NewProtect, 
			OldProtect);
	}

	NTSTATUS WINAPI NtPulseEvent(
		HANDLE EventHandle, 
		PULONG PreviousState)
	{
		CHAR szProcName[] = {'N', 't', 'P', 'u', 'l', 's', 'e', 'E', 'v', 'e', 'n', 't', '\0'};
		Type_NtPulseEvent pfn = (Type_NtPulseEvent)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventHandle, 
			PreviousState);
	}

	NTSTATUS WINAPI NtQueryAttributesFile(
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		PVOID FileInformation)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', 'F', 'i', 'l', 'e', '\0'};
		Type_NtQueryAttributesFile pfn = (Type_NtQueryAttributesFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ObjectAttributes, 
			FileInformation);
	}

	NTSTATUS WINAPI NtQueryDefaultLocale(
		BOOLEAN ThreadOrSystem, 
		LCID* Locale)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'D', 'e', 'f', 'a', 'u', 'l', 't', 'L', 'o', 'c', 'a', 'l', 'e', '\0'};
		Type_NtQueryDefaultLocale pfn = (Type_NtQueryDefaultLocale)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadOrSystem, 
			Locale);
	}

	NTSTATUS WINAPI NtQueryDirectoryFile(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID FileInformation, 
		ULONG FileInformationLength, 
		PVOID FileInformationClass, 
		BOOLEAN ReturnSingleEntry, 
		PUNICODE_STRING FileName, 
		BOOLEAN RestartScan)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'F', 'i', 'l', 'e', '\0'};
		Type_NtQueryDirectoryFile pfn = (Type_NtQueryDirectoryFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			FileInformation, 
			FileInformationLength, 
			FileInformationClass, 
			ReturnSingleEntry, 
			FileName, 
			RestartScan);
	}

	NTSTATUS WINAPI NtQueryDirectoryObject(
		HANDLE DirectoryHandle, 
		PVOID Buffer, 
		ULONG BufferLength, 
		BOOLEAN ReturnSingleEntry, 
		BOOLEAN RestartScan, 
		PULONG Context, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtQueryDirectoryObject pfn = (Type_NtQueryDirectoryObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			DirectoryHandle, 
			Buffer, 
			BufferLength, 
			ReturnSingleEntry, 
			RestartScan, 
			Context, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryEaFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID Buffer, 
		ULONG BufferLength, 
		BOOLEAN ReturnSingleEntry, 
		PVOID EaList, 
		ULONG EaListLength, 
		PULONG EaIndex, 
		BOOLEAN RestartScan)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'E', 'a', 'F', 'i', 'l', 'e', '\0'};
		Type_NtQueryEaFile pfn = (Type_NtQueryEaFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock, 
			Buffer, 
			BufferLength, 
			ReturnSingleEntry, 
			EaList, 
			EaListLength, 
			EaIndex, 
			RestartScan);
	}

	NTSTATUS WINAPI NtQueryEvent(
		HANDLE EventHandle, 
		PVOID EventInformationClass, 
		PVOID EventInformation, 
		ULONG EventInformationLength, 
		PULONG ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'E', 'v', 'e', 'n', 't', '\0'};
		Type_NtQueryEvent pfn = (Type_NtQueryEvent)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventHandle, 
			EventInformationClass, 
			EventInformation, 
			EventInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtQueryFullAttributesFile(
		const OBJECT_ATTRIBUTES* ObjectAttributes, 
		PVOID FileInformation)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'F', 'u', 'l', 'l', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', 'F', 'i', 'l', 'e', '\0'};
		Type_NtQueryFullAttributesFile pfn = (Type_NtQueryFullAttributesFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ObjectAttributes, 
			FileInformation);
	}

	NTSTATUS WINAPI NtQueryInformationAtom(
		PVOID Atom, 
		PVOID AtomInformationClass, 
		PVOID AtomInformation, 
		ULONG AtomInformationLength, 
		ULONG* ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'A', 't', 'o', 'm', '\0'};
		Type_NtQueryInformationAtom pfn = (Type_NtQueryInformationAtom)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Atom, 
			AtomInformationClass, 
			AtomInformation, 
			AtomInformationLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryInformationFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID FileInformation, 
		LONG FileInformationLength, 
		PVOID FileInformationClass)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'F', 'i', 'l', 'e', '\0'};
		Type_NtQueryInformationFile pfn = (Type_NtQueryInformationFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock, 
			FileInformation, 
			FileInformationLength, 
			FileInformationClass);
	}

	NTSTATUS WINAPI NtQueryInformationPort(
		HANDLE PortHandle, 
		PVOID PortInformationClass, 
		PVOID PortInformation, 
		ULONG PortInformationLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'o', 'r', 't', '\0'};
		Type_NtQueryInformationPort pfn = (Type_NtQueryInformationPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			PortInformationClass, 
			PortInformation, 
			PortInformationLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryInformationProcess(
		HANDLE ProcessHandle, 
		PVOID ProcessInformationClass, 
		PVOID ProcessInformation, 
		ULONG ProcessInformationLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0'};
		Type_NtQueryInformationProcess pfn = (Type_NtQueryInformationProcess)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			ProcessInformationClass, 
			ProcessInformation, 
			ProcessInformationLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryInformationThread(
		HANDLE ThreadHandle, 
		PVOID ThreadInformationClass, 
		PVOID ThreadInformation, 
		ULONG ThreadInformationLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtQueryInformationThread pfn = (Type_NtQueryInformationThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			ThreadInformationClass, 
			ThreadInformation, 
			ThreadInformationLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryInformationToken(
		HANDLE TokenHandle, 
		TOKEN_INFORMATION_CLASS TokenInformationClass, 
		PVOID TokenInformation, 
		ULONG TokenInformationLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'T', 'o', 'k', 'e', 'n', '\0'};
		Type_NtQueryInformationToken pfn = (Type_NtQueryInformationToken)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TokenHandle, 
			TokenInformationClass, 
			TokenInformation, 
			TokenInformationLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryIntervalProfile(
		PVOID Source, 
		PULONG Interval)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 't', 'e', 'r', 'v', 'a', 'l', 'P', 'r', 'o', 'f', 'i', 'l', 'e', '\0'};
		Type_NtQueryIntervalProfile pfn = (Type_NtQueryIntervalProfile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Source, 
			Interval);
	}

	NTSTATUS WINAPI NtQueryIoCompletion(
		HANDLE IoCompletionHandle, 
		PVOID IoCompletionInformationClass, 
		PVOID IoCompletionInformation, 
		ULONG IoCompletionInformationLength, 
		PULONG ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'o', 'C', 'o', 'm', 'p', 'l', 'e', 't', 'i', 'o', 'n', '\0'};
		Type_NtQueryIoCompletion pfn = (Type_NtQueryIoCompletion)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			IoCompletionHandle, 
			IoCompletionInformationClass, 
			IoCompletionInformation, 
			IoCompletionInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtQueryKey(
		HANDLE KeyHandle, 
		PVOID KeyInformationClass, 
		void* KeyInformation, 
		DWORD KeyInformationLength, 
		DWORD* ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'K', 'e', 'y', '\0'};
		Type_NtQueryKey pfn = (Type_NtQueryKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			KeyInformationClass, 
			KeyInformation, 
			KeyInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtQueryMultipleValueKey(
		HANDLE KeyHandle, 
		PVOID ValueList, 
		ULONG NumberOfValues, 
		PVOID Buffer, 
		ULONG Length, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'M', 'u', 'l', 't', 'i', 'p', 'l', 'e', 'V', 'a', 'l', 'u', 'e', 'K', 'e', 'y', '\0'};
		Type_NtQueryMultipleValueKey pfn = (Type_NtQueryMultipleValueKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			ValueList, 
			NumberOfValues, 
			Buffer, 
			Length, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryMutant(
		HANDLE MutantHandle, 
		PVOID MutantInformationClass, 
		PVOID MutantInformation, 
		ULONG MutantInformationLength, 
		PULONG ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'M', 'u', 't', 'a', 'n', 't', '\0'};
		Type_NtQueryMutant pfn = (Type_NtQueryMutant)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			MutantHandle, 
			MutantInformationClass, 
			MutantInformation, 
			MutantInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtQueryObject(
		HANDLE ObjectHandle, 
		OBJECT_INFORMATION_CLASS ObjectInformationClass, 
		PVOID ObjectInformation, 
		ULONG ObjectInformationLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtQueryObject pfn = (Type_NtQueryObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ObjectHandle, 
			ObjectInformationClass, 
			ObjectInformation, 
			ObjectInformationLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryPerformanceCounter(
		PLARGE_INTEGER PerformanceCount, 
		PLARGE_INTEGER PerformanceFrequency)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'P', 'e', 'r', 'f', 'o', 'r', 'm', 'a', 'n', 'c', 'e', 'C', 'o', 'u', 'n', 't', 'e', 'r', '\0'};
		Type_NtQueryPerformanceCounter pfn = (Type_NtQueryPerformanceCounter)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PerformanceCount, 
			PerformanceFrequency);
	}

	NTSTATUS WINAPI NtQuerySection(
		HANDLE SectionHandle, 
		PVOID SectionInformationClass, 
		PVOID SectionInformation, 
		ULONG SectionInformationLength, 
		PULONG ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0'};
		Type_NtQuerySection pfn = (Type_NtQuerySection)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SectionHandle, 
			SectionInformationClass, 
			SectionInformation, 
			SectionInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtQuerySecurityObject(
		HANDLE Handle, 
		SECURITY_INFORMATION SecurityInformation, 
		PSECURITY_DESCRIPTOR SecurityDescriptor, 
		ULONG SecurityDescriptorLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtQuerySecurityObject pfn = (Type_NtQuerySecurityObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Handle, 
			SecurityInformation, 
			SecurityDescriptor, 
			SecurityDescriptorLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQuerySemaphore(
		HANDLE SemaphoreHandle, 
		PVOID SemaphoreInformationClass, 
		PVOID SemaphoreInformation, 
		ULONG SemaphoreInformationLength, 
		PULONG ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'e', 'm', 'a', 'p', 'h', 'o', 'r', 'e', '\0'};
		Type_NtQuerySemaphore pfn = (Type_NtQuerySemaphore)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SemaphoreHandle, 
			SemaphoreInformationClass, 
			SemaphoreInformation, 
			SemaphoreInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtQuerySymbolicLinkObject(
		HANDLE SymbolicLinkHandle, 
		PUNICODE_STRING TargetName, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 'm', 'b', 'o', 'l', 'i', 'c', 'L', 'i', 'n', 'k', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtQuerySymbolicLinkObject pfn = (Type_NtQuerySymbolicLinkObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SymbolicLinkHandle, 
			TargetName, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQuerySystemEnvironmentValue(
		PUNICODE_STRING Name, 
		PWCHAR Value, 
		ULONG ValueLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', 'V', 'a', 'l', 'u', 'e', '\0'};
		Type_NtQuerySystemEnvironmentValue pfn = (Type_NtQuerySystemEnvironmentValue)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Name, 
			Value, 
			ValueLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQuerySystemInformation(
		PVOID SystemInformationClass, 
		PVOID SystemInformation, 
		ULONG SystemInformationLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', '\0'};
		Type_NtQuerySystemInformation pfn = (Type_NtQuerySystemInformation)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SystemInformationClass, 
			SystemInformation, 
			SystemInformationLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQuerySystemTime(
		PLARGE_INTEGER CurrentTime)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'T', 'i', 'm', 'e', '\0'};
		Type_NtQuerySystemTime pfn = (Type_NtQuerySystemTime)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			CurrentTime);
	}

	NTSTATUS WINAPI NtQueryTimer(
		HANDLE TimerHandle, 
		PVOID TimerInformationClass, 
		PVOID TimerInformation, 
		ULONG TimerInformationLength, 
		PULONG ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'T', 'i', 'm', 'e', 'r', '\0'};
		Type_NtQueryTimer pfn = (Type_NtQueryTimer)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TimerHandle, 
			TimerInformationClass, 
			TimerInformation, 
			TimerInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtQueryTimerResolution(
		PULONG CoarsestResolution, 
		PULONG FinestResolution, 
		PULONG ActualResolution)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'T', 'i', 'm', 'e', 'r', 'R', 'e', 's', 'o', 'l', 'u', 't', 'i', 'o', 'n', '\0'};
		Type_NtQueryTimerResolution pfn = (Type_NtQueryTimerResolution)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			CoarsestResolution, 
			FinestResolution, 
			ActualResolution);
	}

	NTSTATUS WINAPI NtQueryValueKey(
		HANDLE KeyHandle, 
		const UNICODE_STRING* ValueName, 
		PVOID KeyValueInformationClass, 
		void* KeyValueInformation, 
		DWORD KeyValueInformationLength, 
		DWORD* ResultLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'V', 'a', 'l', 'u', 'e', 'K', 'e', 'y', '\0'};
		Type_NtQueryValueKey pfn = (Type_NtQueryValueKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			ValueName, 
			KeyValueInformationClass, 
			KeyValueInformation, 
			KeyValueInformationLength, 
			ResultLength);
	}

	NTSTATUS WINAPI NtQueryVirtualMemory(
		HANDLE ProcessHandle, 
		LPCVOID BaseAddress, 
		MEMORY_INFORMATION_CLASS MemoryInformationClass, 
		PVOID MemoryInformation, 
		SIZE_T MemoryInformationLength, 
		SIZE_T* ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtQueryVirtualMemory pfn = (Type_NtQueryVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			MemoryInformationClass, 
			MemoryInformation, 
			MemoryInformationLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtQueryVolumeInformationFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID VolumeInformation, 
		ULONG VolumeInformationLength, 
		PVOID VolumeInformationClass)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'r', 'y', 'V', 'o', 'l', 'u', 'm', 'e', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'F', 'i', 'l', 'e', '\0'};
		Type_NtQueryVolumeInformationFile pfn = (Type_NtQueryVolumeInformationFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock, 
			VolumeInformation, 
			VolumeInformationLength, 
			VolumeInformationClass);
	}

	NTSTATUS WINAPI NtQueueApcThread(
		HANDLE ThreadHandle, 
		PVOID ApcRoutine, 
		ULONG_PTR ApcContext, 
		ULONG_PTR Argument1, 
		ULONG_PTR Argument2)
	{
		CHAR szProcName[] = {'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtQueueApcThread pfn = (Type_NtQueueApcThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			ApcRoutine, 
			ApcContext, 
			Argument1, 
			Argument2);
	}

	NTSTATUS WINAPI NtRaiseException(
		PEXCEPTION_RECORD ExceptionRecord, 
		PCONTEXT Context, 
		BOOL SearchFrames)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'a', 'i', 's', 'e', 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', '\0'};
		Type_NtRaiseException pfn = (Type_NtRaiseException)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ExceptionRecord, 
			Context, 
			SearchFrames);
	}

	NTSTATUS WINAPI NtRaiseHardError(
		NTSTATUS Status, 
		ULONG NumberOfArguments, 
		PUNICODE_STRING StringArgumentsMask, 
		PVOID* Arguments, 
		PVOID ResponseOption, 
		PVOID Response)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'a', 'i', 's', 'e', 'H', 'a', 'r', 'd', 'E', 'r', 'r', 'o', 'r', '\0'};
		Type_NtRaiseHardError pfn = (Type_NtRaiseHardError)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Status, 
			NumberOfArguments, 
			StringArgumentsMask, 
			Arguments, 
			ResponseOption, 
			Response);
	}

	NTSTATUS WINAPI NtReadFile(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID Buffer, 
		ULONG Length, 
		PLARGE_INTEGER ByteOffset, 
		PULONG Key)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', '\0'};
		Type_NtReadFile pfn = (Type_NtReadFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			Buffer, 
			Length, 
			ByteOffset, 
			Key);
	}

	NTSTATUS WINAPI NtReadFileScatter(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		FILE_SEGMENT_ELEMENT* Buffer, 
		ULONG Length, 
		PLARGE_INTEGER ByteOffset, 
		PULONG Key)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 'S', 'c', 'a', 't', 't', 'e', 'r', '\0'};
		Type_NtReadFileScatter pfn = (Type_NtReadFileScatter)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			Buffer, 
			Length, 
			ByteOffset, 
			Key);
	}

	NTSTATUS WINAPI NtReadRequestData(
		HANDLE PortHandle, 
		PVOID Message, 
		ULONG Index, 
		PVOID Buffer, 
		ULONG BufferLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'a', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 'D', 'a', 't', 'a', '\0'};
		Type_NtReadRequestData pfn = (Type_NtReadRequestData)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			Message, 
			Index, 
			Buffer, 
			BufferLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtReadVirtualMemory(
		HANDLE ProcessHandle, 
		const void* BaseAddress, 
		void* Buffer, 
		SIZE_T BufferLength, 
		SIZE_T* ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtReadVirtualMemory pfn = (Type_NtReadVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			Buffer, 
			BufferLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtRegisterThreadTerminatePort(
		HANDLE PortHandle)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'P', 'o', 'r', 't', '\0'};
		Type_NtRegisterThreadTerminatePort pfn = (Type_NtRegisterThreadTerminatePort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle);
	}

	NTSTATUS WINAPI NtReleaseMutant(
		HANDLE MutantHandle, 
		PLONG PreviousState)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'M', 'u', 't', 'a', 'n', 't', '\0'};
		Type_NtReleaseMutant pfn = (Type_NtReleaseMutant)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			MutantHandle, 
			PreviousState);
	}

	NTSTATUS WINAPI NtReleaseSemaphore(
		HANDLE SemaphoreHandle, 
		ULONG ReleaseCount, 
		PULONG PPreviousCount)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'S', 'e', 'm', 'a', 'p', 'h', 'o', 'r', 'e', '\0'};
		Type_NtReleaseSemaphore pfn = (Type_NtReleaseSemaphore)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SemaphoreHandle, 
			ReleaseCount, 
			PPreviousCount);
	}

	NTSTATUS WINAPI NtRemoveIoCompletion(
		HANDLE IoCompletionHandle, 
		PULONG_PTR CompletionKey, 
		PULONG_PTR CompletionValue, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PLARGE_INTEGER Time)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'm', 'o', 'v', 'e', 'I', 'o', 'C', 'o', 'm', 'p', 'l', 'e', 't', 'i', 'o', 'n', '\0'};
		Type_NtRemoveIoCompletion pfn = (Type_NtRemoveIoCompletion)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			IoCompletionHandle, 
			CompletionKey, 
			CompletionValue, 
			IoStatusBlock, 
			Time);
	}

	NTSTATUS WINAPI NtReplaceKey(
		POBJECT_ATTRIBUTES NewFileObjectAttributes, 
		HANDLE KeyHandle, 
		POBJECT_ATTRIBUTES OldFileObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'p', 'l', 'a', 'c', 'e', 'K', 'e', 'y', '\0'};
		Type_NtReplaceKey pfn = (Type_NtReplaceKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			NewFileObjectAttributes, 
			KeyHandle, 
			OldFileObjectAttributes);
	}

	NTSTATUS WINAPI NtReplyPort(
		HANDLE PortHandle, 
		PVOID ReplyMessage)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'p', 'l', 'y', 'P', 'o', 'r', 't', '\0'};
		Type_NtReplyPort pfn = (Type_NtReplyPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			ReplyMessage);
	}

	NTSTATUS WINAPI NtReplyWaitReceivePort(
		HANDLE PortHandle, 
		PULONG PortIdentifier, 
		PVOID ReplyMessage, 
		PVOID Message)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'p', 'l', 'y', 'W', 'a', 'i', 't', 'R', 'e', 'c', 'e', 'i', 'v', 'e', 'P', 'o', 'r', 't', '\0'};
		Type_NtReplyWaitReceivePort pfn = (Type_NtReplyWaitReceivePort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			PortIdentifier, 
			ReplyMessage, 
			Message);
	}

	NTSTATUS WINAPI NtReplyWaitReplyPort(
		HANDLE PortHandle, 
		PVOID ReplyMessage)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'p', 'l', 'y', 'W', 'a', 'i', 't', 'R', 'e', 'p', 'l', 'y', 'P', 'o', 'r', 't', '\0'};
		Type_NtReplyWaitReplyPort pfn = (Type_NtReplyWaitReplyPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			ReplyMessage);
	}

	NTSTATUS WINAPI NtRequestPort(
		HANDLE PortHandle, 
		PVOID RequestMessage)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'q', 'u', 'e', 's', 't', 'P', 'o', 'r', 't', '\0'};
		Type_NtRequestPort pfn = (Type_NtRequestPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			RequestMessage);
	}

	NTSTATUS WINAPI NtRequestWaitReplyPort(
		HANDLE PortHandle, 
		PVOID RequestMessage, 
		PVOID ReplyMessage)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 'q', 'u', 'e', 's', 't', 'W', 'a', 'i', 't', 'R', 'e', 'p', 'l', 'y', 'P', 'o', 'r', 't', '\0'};
		Type_NtRequestWaitReplyPort pfn = (Type_NtRequestWaitReplyPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			RequestMessage, 
			ReplyMessage);
	}

	NTSTATUS WINAPI NtResetEvent(
		HANDLE EventHandle, 
		PULONG PreviousState)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 's', 'e', 't', 'E', 'v', 'e', 'n', 't', '\0'};
		Type_NtResetEvent pfn = (Type_NtResetEvent)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventHandle, 
			PreviousState);
	}

	NTSTATUS WINAPI NtRestoreKey(
		HANDLE KeyHandle, 
		HANDLE FileHandle, 
		ULONG Flags)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 's', 't', 'o', 'r', 'e', 'K', 'e', 'y', '\0'};
		Type_NtRestoreKey pfn = (Type_NtRestoreKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			FileHandle, 
			Flags);
	}

	NTSTATUS WINAPI NtResumeThread(
		HANDLE ThreadHandle, 
		PULONG PreviousSuspendCount)
	{
		CHAR szProcName[] = {'N', 't', 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtResumeThread pfn = (Type_NtResumeThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			PreviousSuspendCount);
	}

	NTSTATUS WINAPI NtSaveKey(
		HANDLE KeyHandle, 
		HANDLE FileHandle)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'a', 'v', 'e', 'K', 'e', 'y', '\0'};
		Type_NtSaveKey pfn = (Type_NtSaveKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			FileHandle);
	}

	NTSTATUS WINAPI NtSetContextThread(
		HANDLE ThreadHandle, 
		const CONTEXT* Context)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtSetContextThread pfn = (Type_NtSetContextThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			Context);
	}

	NTSTATUS WINAPI NtSetDefaultHardErrorPort(
		HANDLE PortHandle)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'D', 'e', 'f', 'a', 'u', 'l', 't', 'H', 'a', 'r', 'd', 'E', 'r', 'r', 'o', 'r', 'P', 'o', 'r', 't', '\0'};
		Type_NtSetDefaultHardErrorPort pfn = (Type_NtSetDefaultHardErrorPort)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle);
	}

	NTSTATUS WINAPI NtSetDefaultLocale(
		BOOLEAN ThreadOrSystem, 
		LCID Locale)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'D', 'e', 'f', 'a', 'u', 'l', 't', 'L', 'o', 'c', 'a', 'l', 'e', '\0'};
		Type_NtSetDefaultLocale pfn = (Type_NtSetDefaultLocale)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadOrSystem, 
			Locale);
	}

	NTSTATUS WINAPI NtSetEaFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID Buffer, 
		ULONG BufferLength)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'E', 'a', 'F', 'i', 'l', 'e', '\0'};
		Type_NtSetEaFile pfn = (Type_NtSetEaFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock, 
			Buffer, 
			BufferLength);
	}

	NTSTATUS WINAPI NtSetEvent(
		HANDLE EventHandle, 
		PULONG PreviousState)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'E', 'v', 'e', 'n', 't', '\0'};
		Type_NtSetEvent pfn = (Type_NtSetEvent)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventHandle, 
			PreviousState);
	}

	NTSTATUS WINAPI NtSetHighEventPair(
		HANDLE EventPairHandle)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'H', 'i', 'g', 'h', 'E', 'v', 'e', 'n', 't', 'P', 'a', 'i', 'r', '\0'};
		Type_NtSetHighEventPair pfn = (Type_NtSetHighEventPair)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventPairHandle);
	}

	NTSTATUS WINAPI NtSetHighWaitLowEventPair(
		HANDLE EventPairHandle)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'H', 'i', 'g', 'h', 'W', 'a', 'i', 't', 'L', 'o', 'w', 'E', 'v', 'e', 'n', 't', 'P', 'a', 'i', 'r', '\0'};
		Type_NtSetHighWaitLowEventPair pfn = (Type_NtSetHighWaitLowEventPair)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventPairHandle);
	}

	NTSTATUS WINAPI NtSetInformationFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID FileInformation, 
		ULONG FileInformationLength, 
		PVOID FileInformationClass)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'F', 'i', 'l', 'e', '\0'};
		Type_NtSetInformationFile pfn = (Type_NtSetInformationFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock, 
			FileInformation, 
			FileInformationLength, 
			FileInformationClass);
	}

	NTSTATUS WINAPI NtSetInformationKey(
		HANDLE KeyHandle, 
		const int KeyInformationClass, 
		PVOID KeyInformation, 
		ULONG KeyInformationLength)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'K', 'e', 'y', '\0'};
		Type_NtSetInformationKey pfn = (Type_NtSetInformationKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			KeyInformationClass, 
			KeyInformation, 
			KeyInformationLength);
	}

	NTSTATUS WINAPI NtSetInformationObject(
		HANDLE ObjectHandle, 
		OBJECT_INFORMATION_CLASS ObjectInformationClass, 
		PVOID ObjectInformation, 
		ULONG ObjectInformationLength)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtSetInformationObject pfn = (Type_NtSetInformationObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ObjectHandle, 
			ObjectInformationClass, 
			ObjectInformation, 
			ObjectInformationLength);
	}

	NTSTATUS WINAPI NtSetInformationProcess(
		HANDLE ProcessHandle, 
		PVOID ProcessInformationClass, 
		PVOID ProcessInformation, 
		ULONG ProcessInformationLength)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0'};
		Type_NtSetInformationProcess pfn = (Type_NtSetInformationProcess)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			ProcessInformationClass, 
			ProcessInformation, 
			ProcessInformationLength);
	}

	NTSTATUS WINAPI NtSetInformationThread(
		HANDLE ThreadHandle, 
		PVOID ThreadInformationClass, 
		LPCVOID ThreadInformation, 
		ULONG ThreadInformationLength)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtSetInformationThread pfn = (Type_NtSetInformationThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			ThreadInformationClass, 
			ThreadInformation, 
			ThreadInformationLength);
	}

	NTSTATUS WINAPI NtSetInformationToken(
		HANDLE TokenHandle, 
		TOKEN_INFORMATION_CLASS TokenInformationClass, 
		PVOID TokenInformation, 
		ULONG TokenInformationLength)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'T', 'o', 'k', 'e', 'n', '\0'};
		Type_NtSetInformationToken pfn = (Type_NtSetInformationToken)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TokenHandle, 
			TokenInformationClass, 
			TokenInformation, 
			TokenInformationLength);
	}

	NTSTATUS WINAPI NtSetIntervalProfile(
		ULONG Interval, 
		PVOID Source)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'I', 'n', 't', 'e', 'r', 'v', 'a', 'l', 'P', 'r', 'o', 'f', 'i', 'l', 'e', '\0'};
		Type_NtSetIntervalProfile pfn = (Type_NtSetIntervalProfile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Interval, 
			Source);
	}

	NTSTATUS WINAPI NtSetIoCompletion(
		HANDLE IoCompletionHandle, 
		ULONG_PTR CompletionKey, 
		ULONG_PTR CompletionValue, 
		NTSTATUS Status, 
		SIZE_T Information)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'I', 'o', 'C', 'o', 'm', 'p', 'l', 'e', 't', 'i', 'o', 'n', '\0'};
		Type_NtSetIoCompletion pfn = (Type_NtSetIoCompletion)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			IoCompletionHandle, 
			CompletionKey, 
			CompletionValue, 
			Status, 
			Information);
	}

	NTSTATUS WINAPI NtSetLowEventPair(
		HANDLE EventPairHandle)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'L', 'o', 'w', 'E', 'v', 'e', 'n', 't', 'P', 'a', 'i', 'r', '\0'};
		Type_NtSetLowEventPair pfn = (Type_NtSetLowEventPair)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventPairHandle);
	}

	NTSTATUS WINAPI NtSetLowWaitHighEventPair(
		HANDLE EventPairHandle)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'L', 'o', 'w', 'W', 'a', 'i', 't', 'H', 'i', 'g', 'h', 'E', 'v', 'e', 'n', 't', 'P', 'a', 'i', 'r', '\0'};
		Type_NtSetLowWaitHighEventPair pfn = (Type_NtSetLowWaitHighEventPair)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventPairHandle);
	}

	NTSTATUS WINAPI NtSetSecurityObject(
		HANDLE Handle, 
		SECURITY_INFORMATION SecurityInformation, 
		PSECURITY_DESCRIPTOR SecurityDescriptor)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtSetSecurityObject pfn = (Type_NtSetSecurityObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Handle, 
			SecurityInformation, 
			SecurityDescriptor);
	}

	NTSTATUS WINAPI NtSetSystemEnvironmentValue(
		PUNICODE_STRING Name, 
		PUNICODE_STRING Value)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', 'V', 'a', 'l', 'u', 'e', '\0'};
		Type_NtSetSystemEnvironmentValue pfn = (Type_NtSetSystemEnvironmentValue)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Name, 
			Value);
	}

	NTSTATUS WINAPI NtSetSystemInformation(
		PVOID SystemInformationClass, 
		PVOID SystemInformation, 
		ULONG SystemInformationLength)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', '\0'};
		Type_NtSetSystemInformation pfn = (Type_NtSetSystemInformation)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SystemInformationClass, 
			SystemInformation, 
			SystemInformationLength);
	}

	NTSTATUS WINAPI NtSetSystemPowerState(
		POWER_ACTION SystemAction, 
		SYSTEM_POWER_STATE MinSystemState, 
		ULONG Flags)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'P', 'o', 'w', 'e', 'r', 'S', 't', 'a', 't', 'e', '\0'};
		Type_NtSetSystemPowerState pfn = (Type_NtSetSystemPowerState)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			SystemAction, 
			MinSystemState, 
			Flags);
	}

	NTSTATUS WINAPI NtSetSystemTime(
		const LARGE_INTEGER* NewTime, 
		LARGE_INTEGER* OldTime)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'T', 'i', 'm', 'e', '\0'};
		Type_NtSetSystemTime pfn = (Type_NtSetSystemTime)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			NewTime, 
			OldTime);
	}

	NTSTATUS WINAPI NtSetTimer(
		HANDLE TimerHandle, 
		const LARGE_INTEGER* DueTime, 
		PVOID TimerApcRoutine, 
		PVOID TimerContext, 
		BOOLEAN Resume, 
		ULONG Period, 
		BOOLEAN* PreviousState)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'T', 'i', 'm', 'e', 'r', '\0'};
		Type_NtSetTimer pfn = (Type_NtSetTimer)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			TimerHandle, 
			DueTime, 
			TimerApcRoutine, 
			TimerContext, 
			Resume, 
			Period, 
			PreviousState);
	}

	NTSTATUS WINAPI NtSetTimerResolution(
		ULONG RequestedResolution, 
		BOOLEAN Set, 
		PULONG ActualResolution)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'T', 'i', 'm', 'e', 'r', 'R', 'e', 's', 'o', 'l', 'u', 't', 'i', 'o', 'n', '\0'};
		Type_NtSetTimerResolution pfn = (Type_NtSetTimerResolution)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			RequestedResolution, 
			Set, 
			ActualResolution);
	}

	NTSTATUS WINAPI NtSetValueKey(
		HANDLE KeyHandle, 
		const UNICODE_STRING* ValueName, 
		ULONG TitleIndex, 
		ULONG Type, 
		const void* Data, 
		ULONG DataSize)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'V', 'a', 'l', 'u', 'e', 'K', 'e', 'y', '\0'};
		Type_NtSetValueKey pfn = (Type_NtSetValueKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyHandle, 
			ValueName, 
			TitleIndex, 
			Type, 
			Data, 
			DataSize);
	}

	NTSTATUS WINAPI NtSetVolumeInformationFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PVOID Buffer, 
		ULONG BufferLength, 
		PVOID VolumeInformationClass)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'e', 't', 'V', 'o', 'l', 'u', 'm', 'e', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'F', 'i', 'l', 'e', '\0'};
		Type_NtSetVolumeInformationFile pfn = (Type_NtSetVolumeInformationFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock, 
			Buffer, 
			BufferLength, 
			VolumeInformationClass);
	}

	NTSTATUS WINAPI NtShutdownSystem(
		PVOID Action)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'h', 'u', 't', 'd', 'o', 'w', 'n', 'S', 'y', 's', 't', 'e', 'm', '\0'};
		Type_NtShutdownSystem pfn = (Type_NtShutdownSystem)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Action);
	}

	NTSTATUS WINAPI NtSignalAndWaitForSingleObject(
		HANDLE HandleToSignal, 
		HANDLE HandleToWait, 
		BOOLEAN Alertable, 
		const LARGE_INTEGER* Time)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'i', 'g', 'n', 'a', 'l', 'A', 'n', 'd', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtSignalAndWaitForSingleObject pfn = (Type_NtSignalAndWaitForSingleObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			HandleToSignal, 
			HandleToWait, 
			Alertable, 
			Time);
	}

	NTSTATUS WINAPI NtStartProfile(
		HANDLE ProfileHandle)
	{
		CHAR szProcName[] = {'N', 't', 'S', 't', 'a', 'r', 't', 'P', 'r', 'o', 'f', 'i', 'l', 'e', '\0'};
		Type_NtStartProfile pfn = (Type_NtStartProfile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProfileHandle);
	}

	NTSTATUS WINAPI NtStopProfile(
		HANDLE ProfileHandle)
	{
		CHAR szProcName[] = {'N', 't', 'S', 't', 'o', 'p', 'P', 'r', 'o', 'f', 'i', 'l', 'e', '\0'};
		Type_NtStopProfile pfn = (Type_NtStopProfile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProfileHandle);
	}

	NTSTATUS WINAPI NtSuspendThread(
		HANDLE ThreadHandle, 
		PULONG PreviousSuspendCount)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'u', 's', 'p', 'e', 'n', 'd', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtSuspendThread pfn = (Type_NtSuspendThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			PreviousSuspendCount);
	}

	NTSTATUS WINAPI NtSystemDebugControl(
		PVOID ControlCode, 
		PVOID InputBuffer, 
		ULONG InputBufferLength, 
		PVOID OutputBuffer, 
		ULONG OutputBufferLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'S', 'y', 's', 't', 'e', 'm', 'D', 'e', 'b', 'u', 'g', 'C', 'o', 'n', 't', 'r', 'o', 'l', '\0'};
		Type_NtSystemDebugControl pfn = (Type_NtSystemDebugControl)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ControlCode, 
			InputBuffer, 
			InputBufferLength, 
			OutputBuffer, 
			OutputBufferLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtTerminateProcess(
		HANDLE ProcessHandle, 
		LONG ExitStatus)
	{
		CHAR szProcName[] = {'N', 't', 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0'};
		Type_NtTerminateProcess pfn = (Type_NtTerminateProcess)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			ExitStatus);
	}

	NTSTATUS WINAPI NtTerminateThread(
		HANDLE ThreadHandle, 
		LONG ExitStatus)
	{
		CHAR szProcName[] = {'N', 't', 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
		Type_NtTerminateThread pfn = (Type_NtTerminateThread)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ThreadHandle, 
			ExitStatus);
	}

	NTSTATUS WINAPI NtTestAlert()
	{
		CHAR szProcName[] = {'N', 't', 'T', 'e', 's', 't', 'A', 'l', 'e', 'r', 't', '\0'};
		Type_NtTestAlert pfn = (Type_NtTestAlert)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn();
	}

	NTSTATUS WINAPI NtUnloadDriver(
		const UNICODE_STRING* DriverServiceName)
	{
		CHAR szProcName[] = {'N', 't', 'U', 'n', 'l', 'o', 'a', 'd', 'D', 'r', 'i', 'v', 'e', 'r', '\0'};
		Type_NtUnloadDriver pfn = (Type_NtUnloadDriver)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			DriverServiceName);
	}

	NTSTATUS WINAPI NtUnloadKey(
		POBJECT_ATTRIBUTES KeyObjectAttributes)
	{
		CHAR szProcName[] = {'N', 't', 'U', 'n', 'l', 'o', 'a', 'd', 'K', 'e', 'y', '\0'};
		Type_NtUnloadKey pfn = (Type_NtUnloadKey)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			KeyObjectAttributes);
	}

	NTSTATUS WINAPI NtUnlockFile(
		HANDLE FileHandle, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		PLARGE_INTEGER LockOffset, 
		PLARGE_INTEGER LockLength, 
		PULONG Key)
	{
		CHAR szProcName[] = {'N', 't', 'U', 'n', 'l', 'o', 'c', 'k', 'F', 'i', 'l', 'e', '\0'};
		Type_NtUnlockFile pfn = (Type_NtUnlockFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			IoStatusBlock, 
			LockOffset, 
			LockLength, 
			Key);
	}

	NTSTATUS WINAPI NtUnlockVirtualMemory(
		HANDLE ProcessHandle, 
		PVOID* BaseAddress, 
		SIZE_T* LockSize, 
		ULONG LockType)
	{
		CHAR szProcName[] = {'N', 't', 'U', 'n', 'l', 'o', 'c', 'k', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtUnlockVirtualMemory pfn = (Type_NtUnlockVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			LockSize, 
			LockType);
	}

	NTSTATUS WINAPI NtUnmapViewOfSection(
		HANDLE ProcessHandle, 
		PVOID BaseAddress)
	{
		CHAR szProcName[] = {'N', 't', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0'};
		Type_NtUnmapViewOfSection pfn = (Type_NtUnmapViewOfSection)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress);
	}

	NTSTATUS WINAPI NtWaitForMultipleObjects(
		ULONG HandleCount, 
		const HANDLE* Handles, 
		BOOLEAN WaitType, 
		BOOLEAN Alertable, 
		const LARGE_INTEGER* Time)
	{
		CHAR szProcName[] = {'N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'M', 'u', 'l', 't', 'i', 'p', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 's', '\0'};
		Type_NtWaitForMultipleObjects pfn = (Type_NtWaitForMultipleObjects)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			HandleCount, 
			Handles, 
			WaitType, 
			Alertable, 
			Time);
	}

	NTSTATUS WINAPI NtWaitForSingleObject(
		HANDLE Handle, 
		BOOLEAN Alertable, 
		const LARGE_INTEGER* Time)
	{
		CHAR szProcName[] = {'N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
		Type_NtWaitForSingleObject pfn = (Type_NtWaitForSingleObject)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			Handle, 
			Alertable, 
			Time);
	}

	NTSTATUS WINAPI NtWaitHighEventPair(
		HANDLE EventPairHandle)
	{
		CHAR szProcName[] = {'N', 't', 'W', 'a', 'i', 't', 'H', 'i', 'g', 'h', 'E', 'v', 'e', 'n', 't', 'P', 'a', 'i', 'r', '\0'};
		Type_NtWaitHighEventPair pfn = (Type_NtWaitHighEventPair)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventPairHandle);
	}

	NTSTATUS WINAPI NtWaitLowEventPair(
		HANDLE EventPairHandle)
	{
		CHAR szProcName[] = {'N', 't', 'W', 'a', 'i', 't', 'L', 'o', 'w', 'E', 'v', 'e', 'n', 't', 'P', 'a', 'i', 'r', '\0'};
		Type_NtWaitLowEventPair pfn = (Type_NtWaitLowEventPair)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			EventPairHandle);
	}

	NTSTATUS WINAPI NtWriteFile(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		const void* Buffer, 
		ULONG Length, 
		PLARGE_INTEGER ByteOffset, 
		PULONG Key)
	{
		CHAR szProcName[] = {'N', 't', 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', '\0'};
		Type_NtWriteFile pfn = (Type_NtWriteFile)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			Buffer, 
			Length, 
			ByteOffset, 
			Key);
	}

	NTSTATUS WINAPI NtWriteFileGather(
		HANDLE FileHandle, 
		HANDLE Event, 
		PVOID ApcRoutine, 
		PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, 
		FILE_SEGMENT_ELEMENT* Buffer, 
		ULONG Length, 
		PLARGE_INTEGER ByteOffset, 
		PULONG Key)
	{
		CHAR szProcName[] = {'N', 't', 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 'G', 'a', 't', 'h', 'e', 'r', '\0'};
		Type_NtWriteFileGather pfn = (Type_NtWriteFileGather)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			FileHandle, 
			Event, 
			ApcRoutine, 
			ApcContext, 
			IoStatusBlock, 
			Buffer, 
			Length, 
			ByteOffset, 
			Key);
	}

	NTSTATUS WINAPI NtWriteRequestData(
		HANDLE PortHandle, 
		PVOID Message, 
		ULONG Index, 
		PVOID Buffer, 
		ULONG BufferLength, 
		PULONG ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'W', 'r', 'i', 't', 'e', 'R', 'e', 'q', 'u', 'e', 's', 't', 'D', 'a', 't', 'a', '\0'};
		Type_NtWriteRequestData pfn = (Type_NtWriteRequestData)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			PortHandle, 
			Message, 
			Index, 
			Buffer, 
			BufferLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtWriteVirtualMemory(
		HANDLE ProcessHandle, 
		void* BaseAddress, 
		const void* Buffer, 
		SIZE_T BufferLength, 
		SIZE_T* ReturnLength)
	{
		CHAR szProcName[] = {'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
		Type_NtWriteVirtualMemory pfn = (Type_NtWriteVirtualMemory)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			ProcessHandle, 
			BaseAddress, 
			Buffer, 
			BufferLength, 
			ReturnLength);
	}

	NTSTATUS WINAPI NtYieldExecution()
	{
		CHAR szProcName[] = {'N', 't', 'Y', 'i', 'e', 'l', 'd', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', '\0'};
		Type_NtYieldExecution pfn = (Type_NtYieldExecution)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn();
	}

	LPVOID WINAPI RtlAllocateHeap(
		PVOID heap, 
		ULONG flags, 
		ULONG size)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'H', 'e', 'a', 'p', '\0'};
		Type_RtlAllocateHeap pfn = (Type_RtlAllocateHeap)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			heap, 
			flags, 
			size);
	}

	LPVOID WINAPI RtlReAllocateHeap(
		PVOID heap, 
		ULONG flags, 
		PVOID ptr, 
		ULONG size)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'R', 'e', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'H', 'e', 'a', 'p', '\0'};
		Type_RtlReAllocateHeap pfn = (Type_RtlReAllocateHeap)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			heap, 
			flags, 
			ptr, 
			size);
	}

	BOOL WINAPI RtlFreeHeap(
		PVOID heap, 
		ULONG flags, 
		PVOID ptr)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'F', 'r', 'e', 'e', 'H', 'e', 'a', 'p', '\0'};
		Type_RtlFreeHeap pfn = (Type_RtlFreeHeap)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			heap, 
			flags, 
			ptr);
	}

	VOID WINAPI RtlInitUnicodeString(
		PUNICODE_STRING target, 
		PCWSTR source)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'I', 'n', 'i', 't', 'U', 'n', 'i', 'c', 'o', 'd', 'e', 'S', 't', 'r', 'i', 'n', 'g', '\0'};
		Type_RtlInitUnicodeString pfn = (Type_RtlInitUnicodeString)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		pfn(
			target, 
			source);
	}

	VOID WINAPI RtlInitAnsiString(
		PANSI_STRING target, 
		PCSTR source)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'I', 'n', 'i', 't', 'A', 'n', 's', 'i', 'S', 't', 'r', 'i', 'n', 'g', '\0'};
		Type_RtlInitAnsiString pfn = (Type_RtlInitAnsiString)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			target, 
			source);
	}

	NTSTATUS WINAPI RtlAnsiStringToUnicodeString(
		PUNICODE_STRING dst, 
		PANSI_STRING src, 
		BOOLEAN doalloc)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'A', 'n', 's', 'i', 'S', 't', 'r', 'i', 'n', 'g', 'T', 'o', 'U', 'n', 'i', 'c', 'o', 'd', 'e', 'S', 't', 'r', 'i', 'n', 'g', '\0'};
		Type_RtlAnsiStringToUnicodeString pfn = (Type_RtlAnsiStringToUnicodeString)(Win32Api::GetProcAddress(
			OriginalNtdllHanlde(),
			szProcName));

		return pfn(
			dst, 
			src, 
			doalloc);
	}

	VOID WINAPI RtlFreeUnicodeString(
		PUNICODE_STRING str)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'F', 'r', 'e', 'e', 'U', 'n', 'i', 'c', 'o', 'd', 'e', 'S', 't', 'r', 'i', 'n', 'g', '\0'};
		Type_RtlFreeUnicodeString pfn = (Type_RtlFreeUnicodeString)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			str);
	}

	VOID WINAPI RtlFreeAnsiString(
		PANSI_STRING str)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'F', 'r', 'e', 'e', 'A', 'n', 's', 'i', 'S', 't', 'r', 'i', 'n', 'g', '\0'};
		Type_RtlFreeAnsiString pfn = (Type_RtlFreeAnsiString)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		pfn(
			str);
	}

	LONG WINAPI RtlCompareUnicodeString(
		const UNICODE_STRING *s1, 
		const UNICODE_STRING *s2,
		BOOLEAN CaseInsensitive)
	{
		CHAR szProcName[] = {'R', 't', 'l', 'C', 'o', 'm', 'p', 'a', 'r', 'e', 'U', 'n', 'i', 'c', 'o', 'd', 'e', 'S', 't', 'r', 'i', 'n', 'g', '\0'};
		Type_RtlCompareUnicodeString pfn = (Type_RtlCompareUnicodeString)(Win32Api::GetProcAddress(
			NtdllModuleHandle(),
			szProcName));

		return pfn(
			s1, 
			s2, 
			CaseInsensitive);
	}

	#define MSVCRT_EPERM   1
	#define MSVCRT_ENOENT  2
	#define MSVCRT_ESRCH   3
	#define MSVCRT_EINTR   4
	#define MSVCRT_EIO     5
	#define MSVCRT_ENXIO   6
	#define MSVCRT_E2BIG   7
	#define MSVCRT_ENOEXEC 8
	#define MSVCRT_EBADF   9
	#define MSVCRT_ECHILD  10
	#define MSVCRT_EAGAIN  11
	#define MSVCRT_ENOMEM  12
	#define MSVCRT_EACCES  13
	#define MSVCRT_EFAULT  14
	#define MSVCRT_EBUSY   16
	#define MSVCRT_EEXIST  17
	#define MSVCRT_EXDEV   18
	#define MSVCRT_ENODEV  19
	#define MSVCRT_ENOTDIR 20
	#define MSVCRT_EISDIR  21
	#define MSVCRT_EINVAL  22
	#define MSVCRT_ENFILE  23
	#define MSVCRT_EMFILE  24
	#define MSVCRT_ENOTTY  25
	#define MSVCRT_EFBIG   27
	#define MSVCRT_ENOSPC  28
	#define MSVCRT_ESPIPE  29
	#define MSVCRT_EROFS   30
	#define MSVCRT_EMLINK  31
	#define MSVCRT_EPIPE   32
	#define MSVCRT_EDOM    33
	#define MSVCRT_ERANGE  34
	#define MSVCRT_EDEADLK 36
	#define MSVCRT_EDEADLOCK MSVCRT_EDEADLK
	#define MSVCRT_ENAMETOOLONG 38
	#define MSVCRT_ENOLCK  39
	#define MSVCRT_ENOSYS  40
	#define MSVCRT_ENOTEMPTY 41
	#define MSVCRT_EILSEQ    42
	#define MSVCRT_STRUNCATE 80

	#define MSVCRT__TRUNCATE ((int)-1)

	errno_t wcsncpy_s(
		wchar_t *strDest,
		size_t numberOfElements,
		const wchar_t *strSource,
		size_t count)
	{
		//Type_wcsncpy_s pfn = (Type_wcsncpy_s)(Win32Api::GetProcAddress(
		//	NtdllModuleHandle(),
		//	"wcsncpy_s"));

		//return pfn(
		//	strDest, 
		//	numberOfElements, 
		//	strSource, 
		//	count);

		WCHAR *p = strDest;
		BOOL truncate = (count == MSVCRT__TRUNCATE);

		if(!strDest && !numberOfElements && !count)
			return 0;

		if (!strDest || !numberOfElements)
			return MSVCRT_EINVAL;

		if (!strSource)
		{
			*strDest = 0;
			return count ? MSVCRT_EINVAL : 0;
		}

		while (numberOfElements && count && *strSource)
		{
			*p++ = *strSource++;
			numberOfElements--;
			count--;
		}
		if (!numberOfElements && truncate)
		{
			*(p-1) = 0;
			return MSVCRT_STRUNCATE;
		}
		else if (!numberOfElements)
		{
			*strDest = 0;
			return MSVCRT_ERANGE;
		}

		*p = 0;
		return 0;
	}
	

	errno_t wcscat_s(
		wchar_t *strDestination,
		size_t numberOfElements,
		const wchar_t *strSource)
	{
		//Type_wcscat_s pfn = (Type_wcscat_s)(Win32Api::GetProcAddress(
		//	NtdllModuleHandle(),
		//	"wcscat_s"));

		//return pfn(
		//	strDestination, 
		//	numberOfElements, 
		//	strSource);

		wchar_t* ptr = strDestination;

		if (!strDestination || numberOfElements == 0) return MSVCRT_EINVAL;
		if (!strSource)
		{
			strDestination[0] = L'\0';
			return MSVCRT_EINVAL;
		}

		/* seek to end of dst string (or elem if no end of string is found */
		while (ptr < strDestination + numberOfElements && *ptr != '\0') ptr++;
		while (ptr < strDestination + numberOfElements)
		{
			if ((*ptr++ = *strSource++) == L'\0') return 0;
		}
		/* not enough space */
		strDestination[0] = L'\0';
		return MSVCRT_ERANGE;
	}

	size_t CDECL strlen(
		const char *str)
	{
		//Type_strlen pfn = (Type_strlen)(Win32Api::GetProcAddress(
		//	NtdllModuleHandle(),
		//	"strlen"));

		//return pfn(
		//	str);

		const CHAR *s = str;
		while (*s) s++;
		return s - str;
	}

	size_t CDECL wcslen(
		const wchar_t *str)
	{
		//Type_wcslen pfn = (Type_wcslen)(Win32Api::GetProcAddress(
		//	NtdllModuleHandle(),
		//	"wcslen"));

		//return pfn(
		//	str);

		const WCHAR *s = str;
		while (*s) s++;
		return s - str;
	}

	int CDECL strcmp(
		const char *string1,
		const char *string2)
	{
		//Type_strcmp pfn = (Type_strcmp)(Win32Api::GetProcAddress(
		//	NtdllModuleHandle(),
		//	"strcmp"));

		//return pfn(
		//	string1,
		//	string2);

		if ((string1 == NULL) && (string2 == NULL)) return 0;
		if (string1 == NULL) return -1;
		if (string2 == NULL) return 1;

		while (*string1 && *string2 && (*string1 == *string2))
		{
			string1 ++;
			string2 ++;
		}
		return *string1 - *string2;
	}

	int CDECL wcscmp(
		const wchar_t *string1,
		const wchar_t *string2)
	{
		//Type_wcscmp pfn = (Type_wcscmp)(Win32Api::GetProcAddress(
		//	NtdllModuleHandle(),
		//	"wcscmp"));

		//return pfn(
		//	string1,
		//	string2);

		if ((string1 == NULL) && (string2 == NULL)) return 0;
		if (string1 == NULL) return -1;
		if (string2 == NULL) return 1;

		while (*string1 && *string2 && (*string1 == *string2))
		{
			string1 ++;
			string2 ++;
		}
		return *string1 - *string2;
	}

	int CDECL wcscmpi(
		const wchar_t *string1,
		const wchar_t *string2)
	{
		if ((string1 == NULL) && (string2 == NULL)) return 0;
		if (string1 == NULL) return -1;
		if (string2 == NULL) return 1;

		while (*string1 
			&& *string2 
			&& (WinNtApi::towlower(*string1) == WinNtApi::towlower(*string2)))
		{
			string1 ++;
			string2 ++;
		}
		return WinNtApi::towlower(*string1) - WinNtApi::towlower(*string2);
	}

	wchar_t towlower(
		wchar_t c)
	{
		if (c >= 'A' && c <= 'Z')
		{
			c = c + 0x20;
		}
		return c;
	}
}