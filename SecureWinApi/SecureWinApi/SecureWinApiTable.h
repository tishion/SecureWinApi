
#if defined(SECURE_WIN_API_GENERATOR)

#define API_TABLE_START void __declspec(naked) g_ApiTable() {

#define API_THUNK(ns, api, hash, argcount) __asm jmp ns##::##api	\
	__asm mov edi, hash	\
	__asm mov edi, argcount

#define API_TABLE_END }

#else

#define API_TABLE_START enum SecureWinApiIndex {

#define API_THUNK(ns, api, hash, argcount) i_##api##,

#define API_TABLE_END };

#pragma pack(push, 1)
typedef struct _WINAPI_THUNK_DATA {
	union 
	{
		UCHAR jmp_thunk[5];
		struct   
		{
			UCHAR op_jmp;
			DWORD op_offset;
		};
	};

	UCHAR r1;
	DWORD Hash;
	UCHAR r2;
	DWORD ArgCount;
}WINAPI_THUNK_DATA, *PWINAPI_THUNK_DATA;
#pragma pack(pop)

#define SECURE_WIN_API_TABLE PWINAPI_THUNK_DATA
#endif


// When SECURE_WIN_API_GENERATOR is defined, the code will be parsed as follows:
// 
// void __declspec(naked) g_ApiTable() {
//
//	__asm jmp Win32Api, GetCurrentProcess
//  __asm mov edi, 0x000000
//  __asm mov edi, 0x000000
//  
//	__asm jmp Win32Api, GetCurrentProcessId
//  __asm mov edi, 0x000000
//  __asm mov edi, 0x000000
//  
//		............
// }
//
// When SECURE_WIN_API_GENERATOR is not defined, the code will parsed as follows:
// 
// enum SecureWinApiIndex {
//		i_GetCurrentProcess,
//		i_GetCurrentProcessId,
//		
//		..................
// }

API_TABLE_START
	// Win32Apis
	API_THUNK(Win32Api, GetCurrentProcess, 0xBC85D1F6, 0x00000000)
	API_THUNK(Win32Api, GetCurrentThread, 0xE25BEC90, 0x00000000)
	API_THUNK(Win32Api, GetCurrentProcessId, 0x91CBF6C1, 0x00000000)
	API_THUNK(Win32Api, GetCurrentThreadId, 0xFA04282F, 0x00000000)
	API_THUNK(Win32Api, OpenProcess, 0x24D73A92, 0x00000003)
	API_THUNK(Win32Api, OpenThread, 0x629034D2, 0x00000003)
	API_THUNK(Win32Api, GetThreadContext, 0x55125DCF, 0x00000002)
	API_THUNK(Win32Api, SetThreadContext, 0x437FBCAD, 0x00000002)
	API_THUNK(Win32Api, TerminateProcess, 0x0B81BD02, 0x00000002)
	API_THUNK(Win32Api, ExitProcess, 0xC91F6309, 0x00000001)
	API_THUNK(Win32Api, Thread32First, 0xEBB22164, 0x00000002)
	API_THUNK(Win32Api, Thread32Next, 0x00abcdef, 0x00000002)
	API_THUNK(Win32Api, Process32FirstA, 0xE432ADB0, 0x00000002)
	API_THUNK(Win32Api, Process32NextA, 0x81662D33, 0x00000002)
	API_THUNK(Win32Api, Process32FirstW, 0x9F55D75A, 0x00000002)
	API_THUNK(Win32Api, Process32NextW, 0x5EBC16C8, 0x00000002)
	API_THUNK(Win32Api, Module32FirstA, 0x3C0E6822, 0x00000002)
	API_THUNK(Win32Api, Module32FirstW, 0xE3D453D9, 0x00000002)
	API_THUNK(Win32Api, Module32NextA, 0xDC0D19FD, 0x00000002)
	API_THUNK(Win32Api, Module32NextW, 0x03D72206, 0x00000002)
	API_THUNK(Win32Api, Toolhelp32ReadProcessMemory, 0x3EEAA09D, 0x00000005)
	API_THUNK(Win32Api, ReadProcessMemory, 0x9AE5BC7E, 0x00000005)
	API_THUNK(Win32Api, WriteProcessMemory, 0x546DB682, 0x00000005)
	API_THUNK(Win32Api, VirtualAlloc, 0x9C4D6422, 0x00000004)
	API_THUNK(Win32Api, VirtualAllocEx, 0x9F5CC0FA, 0x00000005)
	API_THUNK(Win32Api, VirtualQuery, 0x2908E9A7, 0x00000003)
	API_THUNK(Win32Api, VirtualQueryEx, 0x4AA1E62C, 0x00000004)
	API_THUNK(Win32Api, VirtualFree, 0xF44FFBAC, 0x00000003)
	API_THUNK(Win32Api, VirtualFreeEx, 0x5AEC93E8, 0x00000004) 
	API_THUNK(Win32Api, VirtualProtect, 0x436E824D, 0x00000004)
	API_THUNK(Win32Api, VirtualProtectEx, 0x34502FFC, 0x00000005)
	API_THUNK(Win32Api, GetProcessHeap, 0xAB3DC953, 0x00000000)
	API_THUNK(Win32Api, HeapAlloc, 0xE2213943, 0x00000003)
	API_THUNK(Win32Api, HeapReAlloc, 0x6BF78147, 0x00000004)
	API_THUNK(Win32Api, HeapFree, 0x296E27A1, 0x00000003)
	API_THUNK(Win32Api, MapViewOfFile, 0x636DA884, 0x00000005)	
	API_THUNK(Win32Api, MapViewOfFileEx, 0xF5D3AA2E, 0x00000006)
	API_THUNK(Win32Api, UnmapViewOfFile, 0x5336CB91, 0x00000001)
	API_THUNK(Win32Api, GetVersion, 0x7F862CCD, 0x00000000)
	API_THUNK(Win32Api, LoadLibraryA, 0x34B3D920, 0x00000003)
	API_THUNK(Win32Api, LoadLibraryW, 0xEB69E2DB, 0x00000003)
	API_THUNK(Win32Api, GetModuleHandleA, 0x8DBD9218, 0x00000001)
	API_THUNK(Win32Api, GetModuleHandleW, 0x5267A9E3, 0x00000001)
	API_THUNK(Win32Api, GetModuleFileNameW, 0xA722F917, 0x00000003)
	API_THUNK(Win32Api, GetProcAddress, 0x874717F5, 0x00000002)
	API_THUNK(Win32Api, IsBadReadPtr, 0x366D5D9B, 0x00000002)
	API_THUNK(Win32Api, IsBadWritePtr, 0xFE091BE6, 0x00000002)
	API_THUNK(Win32Api, CloseHandle, 0x017C1E0C, 0x00000001)
	API_THUNK(Win32Api, SetLastError, 0x6F226FD0, 0x00000001)
	API_THUNK(Win32Api, CreateFileA, 0xC100651F, 0x00000007)
	API_THUNK(Win32Api, CreateFileW, 0x1EDA5EE4, 0x00000007)
	API_THUNK(Win32Api, CreateFileMappingW, 0x041F7EC0, 0x00000006)
	API_THUNK(Win32Api, CreateFileMappingA, 0xDBC5453B, 0x00000006)
	API_THUNK(Win32Api, WideCharToMultiByte, 0x4B636C68, 0x00000008)

	// WinNtApis
	API_THUNK(WinNtApi, LdrGetProcedureAddress, 0xDDA0FB84, 0x00000004)
	API_THUNK(WinNtApi, LdrLoadDll, 0x24E99BFC, 0x00000004)
	API_THUNK(WinNtApi, NtAcceptConnectPort, 0x5969A20D, 0x00000006)
	API_THUNK(WinNtApi, NtAccessCheck, 0x336B4200, 0x00000008)
	API_THUNK(WinNtApi, NtAccessCheckAndAuditAlarm, 0x908DFDC4, 0x0000000B)
	API_THUNK(WinNtApi, NtAddAtom, 0x3522D0CA, 0x00000003)
	API_THUNK(WinNtApi, NtAdjustGroupsToken, 0xA6B96A8F, 0x00000006)
	API_THUNK(WinNtApi, NtAdjustPrivilegesToken, 0xE93040C8, 0x00000006)
	API_THUNK(WinNtApi, NtAlertResumeThread, 0x83F59376, 0x00000002)
	API_THUNK(WinNtApi, NtAlertThread, 0x2382A4AE, 0x00000001)
	API_THUNK(WinNtApi, NtAllocateLocallyUniqueId, 0x298CEB83, 0x00000001)
	API_THUNK(WinNtApi, NtAllocateVirtualMemory, 0xE639191D, 0x00000006)
	API_THUNK(WinNtApi, NtCallbackReturn, 0x72E22936, 0x00000003)
	API_THUNK(WinNtApi, NtCancelIoFile, 0x4BE4D524, 0x00000002)
	API_THUNK(WinNtApi, NtCancelTimer, 0xB0F5AF66, 0x00000002)
	API_THUNK(WinNtApi, NtClearEvent, 0xBDC376AF, 0x00000001)
	API_THUNK(WinNtApi, NtClose, 0xBE6C1D90, 0x00000001)
	API_THUNK(WinNtApi, NtCloseObjectAuditAlarm, 0x7CD060E3, 0x00000003)
	API_THUNK(WinNtApi, NtCompleteConnectPort, 0xFEF7A12D, 0x00000001)
	API_THUNK(WinNtApi, NtConnectPort, 0x22FC56FA, 0x00000008)
	API_THUNK(WinNtApi, NtContinue, 0x4907D7EC, 0x00000002)
	API_THUNK(WinNtApi, NtCreateDirectoryObject, 0xD06EEF81, 0x00000003)
	API_THUNK(WinNtApi, NtCreateEvent, 0x3311CA68, 0x00000005)
	API_THUNK(WinNtApi, NtCreateEventPair, 0xF161867D, 0x00000003)
	API_THUNK(WinNtApi, NtCreateFile, 0x017735CB, 0x0000000B)
	API_THUNK(WinNtApi, NtCreateIoCompletion, 0xD09FD7C1, 0x00000004)
	API_THUNK(WinNtApi, NtCreateKey, 0x0CDAB90F, 0x00000007)
	API_THUNK(WinNtApi, NtCreateMailslotFile, 0x55E4256A, 0x00000008)
	API_THUNK(WinNtApi, NtCreateMutant, 0x864DB378, 0x00000004)
	API_THUNK(WinNtApi, NtCreateNamedPipeFile, 0xB04D1C27, 0x0000000E)
	API_THUNK(WinNtApi, NtCreatePagingFile, 0x90C93B7D, 0x00000004)
	API_THUNK(WinNtApi, NtCreatePort, 0x883B50FD, 0x00000005)
	API_THUNK(WinNtApi, NtCreateProcess, 0xE6DDF878, 0x00000008)
	API_THUNK(WinNtApi, NtCreateProfile, 0x7D1BFC31, 0x00000009)
	API_THUNK(WinNtApi, NtCreateSection, 0x7CE2EFA2, 0x00000007)
	API_THUNK(WinNtApi, NtCreateSemaphore, 0x80F30ED8, 0x00000005)
	API_THUNK(WinNtApi, NtCreateSymbolicLinkObject, 0xF6CD3297, 0x00000004)
	API_THUNK(WinNtApi, NtCreateThread, 0xBFAD796E, 0x00000008)
	API_THUNK(WinNtApi, NtCreateTimer, 0x1535A482, 0x00000004)
	API_THUNK(WinNtApi, NtCreateToken, 0x58497A44, 0x0000000D)
	API_THUNK(WinNtApi, NtCurrentTeb, 0xF0C8F067, 0x00000000)
	API_THUNK(WinNtApi, NtDelayExecution, 0x19DBEBAB, 0x00000002)
	API_THUNK(WinNtApi, NtDeleteAtom, 0xC188C87C, 0x00000001)
	API_THUNK(WinNtApi, NtDeleteFile, 0x809DB124, 0x00000001)
	API_THUNK(WinNtApi, NtDeleteKey, 0x58489BDB, 0x00000001)
	API_THUNK(WinNtApi, NtDeleteValueKey, 0x50206FEF, 0x00000002)
	API_THUNK(WinNtApi, NtDeviceIoControlFile, 0xD451F2CC, 0x0000000A)
	API_THUNK(WinNtApi, NtDisplayString, 0x74588DAE, 0x00000001)
	API_THUNK(WinNtApi, NtDuplicateObject, 0x0CFF301C, 0x00000007)
	API_THUNK(WinNtApi, NtDuplicateToken, 0x93FBEB87, 0x00000006)
	API_THUNK(WinNtApi, NtEnumerateKey, 0x1D5454C3, 0x00000006)
	API_THUNK(WinNtApi, NtEnumerateValueKey, 0xB6ACACA8, 0x00000006)
	API_THUNK(WinNtApi, NtExtendSection, 0x99D7F1BB, 0x00000002)
	API_THUNK(WinNtApi, NtFindAtom, 0x7C93FAA2, 0x00000003)
	API_THUNK(WinNtApi, NtFlushBuffersFile, 0x873CB9B0, 0x00000002)
	API_THUNK(WinNtApi, NtFlushInstructionCache, 0x279936D5, 0x00000003)
	API_THUNK(WinNtApi, NtFlushKey, 0x77EE3E2D, 0x00000001)
	API_THUNK(WinNtApi, NtFlushVirtualMemory, 0x667148AC, 0x00000004)
	API_THUNK(WinNtApi, NtFlushWriteBuffer, 0x58919D69, 0x00000000)
	API_THUNK(WinNtApi, NtFreeVirtualMemory, 0xCC6B26EB, 0x00000004)
	API_THUNK(WinNtApi, NtFsControlFile, 0x0EE8B2F9, 0x0000000A)
	API_THUNK(WinNtApi, NtGetContextThread, 0x6FF2ADDE, 0x00000002)
	API_THUNK(WinNtApi, NtGetPlugPlayEvent, 0xD59F441A, 0x00000004)
	API_THUNK(WinNtApi, NtImpersonateClientOfPort, 0x8DFEE7F3, 0x00000002)
	API_THUNK(WinNtApi, NtImpersonateThread, 0x0E16B412, 0x00000003)
	API_THUNK(WinNtApi, NtInitializeRegistry, 0xB431D3D3, 0x00000001)
	API_THUNK(WinNtApi, NtListenPort, 0x02B86DF5, 0x00000002)
	API_THUNK(WinNtApi, NtLoadDriver, 0x14ECCD00, 0x00000001)
	API_THUNK(WinNtApi, NtLoadKey, 0x4635BABE, 0x00000002)
	API_THUNK(WinNtApi, NtLockFile, 0x7B45484A, 0x0000000A)
	API_THUNK(WinNtApi, NtLockVirtualMemory, 0x133B2500, 0x00000004)
	API_THUNK(WinNtApi, NtMapViewOfSection, 0x4C92A2D7, 0x0000000A)
	API_THUNK(WinNtApi, NtNotifyChangeDirectoryFile, 0xFD0ED9AF, 0x00000009)
	API_THUNK(WinNtApi, NtNotifyChangeKey, 0xBF7372EA, 0x0000000A) 
	API_THUNK(WinNtApi, NtOpenDirectoryObject, 0x4F35D905, 0x00000003)
	API_THUNK(WinNtApi, NtOpenEvent, 0x34DAF31C, 0x00000003)
	API_THUNK(WinNtApi, NtOpenEventPair, 0x88ECF48F, 0x00000003)
	API_THUNK(WinNtApi, NtOpenFile, 0xA78A58CF, 0x00000006)
	API_THUNK(WinNtApi, NtOpenIoCompletion, 0xE8DF94EF, 0x00000003)
	API_THUNK(WinNtApi, NtOpenKey, 0x4DE0DAAA, 0x00000003)
	API_THUNK(WinNtApi, NtOpenMutant, 0xD122CD64, 0x00000003)
	API_THUNK(WinNtApi, NtOpenObjectAuditAlarm, 0xC047FB26, 0x0000000C)
	API_THUNK(WinNtApi, NtOpenProcess, 0xF28BCB49, 0x00000004)
	API_THUNK(WinNtApi, NtOpenProcessToken, 0xBA08F99C, 0x00000003)
	API_THUNK(WinNtApi, NtOpenSection, 0x68B4DC93, 0x00000003)
	API_THUNK(WinNtApi, NtOpenSemaphore, 0xF97E7C2A, 0x00000003)
	API_THUNK(WinNtApi, NtOpenSymbolicLinkObject, 0x6554985D, 0x00000003)
	API_THUNK(WinNtApi, NtOpenThread, 0xE8C20772, 0x00000004)
	API_THUNK(WinNtApi, NtOpenThreadToken, 0x9F046D21, 0x00000004)
	API_THUNK(WinNtApi, NtOpenTimer, 0x12FE9DF6, 0x00000003)
	API_THUNK(WinNtApi, NtPrivilegeCheck, 0x96D80F56, 0x00000003)
	API_THUNK(WinNtApi, NtPrivilegeObjectAuditAlarm, 0x50FAAE3A, 0x00000006)
	API_THUNK(WinNtApi, NtPrivilegedServiceAuditAlarm, 0xAA4AA0E2, 0x00000005)
	API_THUNK(WinNtApi, NtProtectVirtualMemory, 0x5AEB376D, 0x00000005)
	API_THUNK(WinNtApi, NtPulseEvent, 0x3DE15CD9, 0x00000002)
	API_THUNK(WinNtApi, NtQueryAttributesFile, 0x9D80628C, 0x00000002)
	API_THUNK(WinNtApi, NtQueryDefaultLocale, 0x3EF0BCC7, 0x00000002)
	API_THUNK(WinNtApi, NtQueryDirectoryFile, 0xED7DF349, 0x0000000B)
	API_THUNK(WinNtApi, NtQueryDirectoryObject, 0x75EB60C1, 0x00000007)
	API_THUNK(WinNtApi, NtQueryEaFile, 0x99F67EE0, 0x00000009)
	API_THUNK(WinNtApi, NtQueryEvent, 0xFA74924F, 0x00000005)
	API_THUNK(WinNtApi, NtQueryFullAttributesFile, 0x4FDA19FD, 0x00000002)
	API_THUNK(WinNtApi, NtQueryInformationAtom, 0x8A21A069, 0x00000005)
	API_THUNK(WinNtApi, NtQueryInformationFile, 0xCB34D931, 0x00000005)
	API_THUNK(WinNtApi, NtQueryInformationPort, 0x4278BC07, 0x00000005)
	API_THUNK(WinNtApi, NtQueryInformationProcess, 0x4390A27E, 0x00000005)
	API_THUNK(WinNtApi, NtQueryInformationThread, 0xF8421449, 0x00000005)
	API_THUNK(WinNtApi, NtQueryInformationToken, 0x05EB22AA, 0x00000005)
	API_THUNK(WinNtApi, NtQueryIntervalProfile, 0xDB7B1CCD, 0x00000002)
	API_THUNK(WinNtApi, NtQueryIoCompletion, 0x60CF03F8, 0x00000005)
	API_THUNK(WinNtApi, NtQueryKey, 0x72B9349C, 0x00000005)
	API_THUNK(WinNtApi, NtQueryMultipleValueKey, 0xB5541499, 0x00000006)
	API_THUNK(WinNtApi, NtQueryMutant, 0x238E634B, 0x00000005)
	API_THUNK(WinNtApi, NtQueryObject, 0xAB9AC1B4, 0x00000005)
	API_THUNK(WinNtApi, NtQueryPerformanceCounter, 0x857B5D3D, 0x00000002)
	API_THUNK(WinNtApi, NtQuerySection, 0xC3974D64, 0x00000005)
	API_THUNK(WinNtApi, NtQuerySecurityObject, 0x9A6EFA2E, 0x00000005)
	API_THUNK(WinNtApi, NtQuerySemaphore, 0x258B03A1, 0x00000005)
	API_THUNK(WinNtApi, NtQuerySymbolicLinkObject, 0xA79E4CD9, 0x00000003)
	API_THUNK(WinNtApi, NtQuerySystemEnvironmentValue, 0x19B139E4, 0x00000004)
	API_THUNK(WinNtApi, NtQuerySystemInformation, 0xFB1A9D57, 0x00000004)
	API_THUNK(WinNtApi, NtQuerySystemTime, 0x528E5BA5, 0x00000001)
	API_THUNK(WinNtApi, NtQueryTimer, 0xDC50FCA5, 0x00000005)
	API_THUNK(WinNtApi, NtQueryTimerResolution, 0xAABEB818, 0x00000003)
	API_THUNK(WinNtApi, NtQueryValueKey, 0x7496372A, 0x00000006)
	API_THUNK(WinNtApi, NtQueryVirtualMemory, 0x9FB0F74D, 0x00000006)
	API_THUNK(WinNtApi, NtQueryVolumeInformationFile, 0x4C4DDEFF, 0x00000005)
	API_THUNK(WinNtApi, NtQueueApcThread, 0xF19C7360, 0x00000005)
	API_THUNK(WinNtApi, NtRaiseException, 0x69151B70, 0x00000003)
	API_THUNK(WinNtApi, NtRaiseHardError, 0x122924C5, 0x00000006)
	API_THUNK(WinNtApi, NtReadFile, 0x1CF1ECF1, 0x00000009)
	API_THUNK(WinNtApi, NtReadFileScatter, 0x6D693CDF, 0x00000009)
	API_THUNK(WinNtApi, NtReadRequestData, 0xDF1CE1A5, 0x00000006)
	API_THUNK(WinNtApi, NtReadVirtualMemory, 0x36C6C667, 0x00000005)
	API_THUNK(WinNtApi, NtRegisterThreadTerminatePort, 0x0FA38473, 0x00000001)
	API_THUNK(WinNtApi, NtReleaseMutant, 0x42913368, 0x00000002)
	API_THUNK(WinNtApi, NtReleaseSemaphore, 0x2833ABD8, 0x00000003)
	API_THUNK(WinNtApi, NtRemoveIoCompletion, 0x1AB9358A, 0x00000005)
	API_THUNK(WinNtApi, NtReplaceKey, 0xD27F83ED, 0x00000003)
	API_THUNK(WinNtApi, NtReplyPort, 0x8E32DCBC, 0x00000002)
	API_THUNK(WinNtApi, NtReplyWaitReceivePort, 0x4A7F2847, 0x00000004)
	API_THUNK(WinNtApi, NtReplyWaitReplyPort, 0x2B85992B, 0x00000002)
	API_THUNK(WinNtApi, NtRequestPort, 0xFF44ABC0, 0x00000002)
	API_THUNK(WinNtApi, NtRequestWaitReplyPort, 0xD4410A16, 0x00000003)
	API_THUNK(WinNtApi, NtResetEvent, 0xDA8C6124, 0x00000002)
	API_THUNK(WinNtApi, NtRestoreKey, 0xD2564E08, 0x00000003)
	API_THUNK(WinNtApi, NtResumeThread, 0x1CAA3723, 0x00000002)
	API_THUNK(WinNtApi, NtSaveKey, 0xCF955F01, 0x00000002)
	API_THUNK(WinNtApi, NtSetContextThread, 0x799F4CBC, 0x00000002)
	API_THUNK(WinNtApi, NtSetDefaultHardErrorPort, 0xFC1F942C, 0x00000001)
	API_THUNK(WinNtApi, NtSetDefaultLocale, 0x4CABC824, 0x00000002)
	API_THUNK(WinNtApi, NtSetEaFile, 0x8792E585, 0x00000004)
	API_THUNK(WinNtApi, NtSetEvent, 0x9F1D9FDD, 0x00000002)
	API_THUNK(WinNtApi, NtSetHighEventPair, 0x6373AE21, 0x00000001)
	API_THUNK(WinNtApi, NtSetHighWaitLowEventPair, 0xB223BD3E, 0x00000001)
	API_THUNK(WinNtApi, NtSetInformationFile, 0xE90FBE60, 0x00000005)
	API_THUNK(WinNtApi, NtSetInformationKey, 0xCC852148, 0x00000004)
	API_THUNK(WinNtApi, NtSetInformationObject, 0x39C0C675, 0x00000004)
	API_THUNK(WinNtApi, NtSetInformationProcess, 0xB559F29F, 0x00000004)
	API_THUNK(WinNtApi, NtSetInformationThread, 0x8834AE9C, 0x00000004)
	API_THUNK(WinNtApi, NtSetInformationToken, 0x19A578AF, 0x00000004)
	API_THUNK(WinNtApi, NtSetIntervalProfile, 0xF9407B9C, 0x00000002)
	API_THUNK(WinNtApi, NtSetIoCompletion, 0x3CDC653E, 0x00000005)
	API_THUNK(WinNtApi, NtSetLowEventPair, 0xD66C2459, 0x00000001)
	API_THUNK(WinNtApi, NtSetLowWaitHighEventPair, 0xC9B51DF0, 0x00000001)
	API_THUNK(WinNtApi, NtSetSecurityObject, 0xA31F1298, 0x00000003)
	API_THUNK(WinNtApi, NtSetSystemEnvironmentValue, 0x55280A27, 0x00000002)
	API_THUNK(WinNtApi, NtSetSystemInformation, 0x8B6C2782, 0x00000003)
	API_THUNK(WinNtApi, NtSetSystemPowerState, 0x97296466, 0x00000003)
	API_THUNK(WinNtApi, NtSetSystemTime, 0x54AE9845, 0x00000002)
	API_THUNK(WinNtApi, NtSetTimer, 0xB939F137, 0x00000007)
	API_THUNK(WinNtApi, NtSetTimerResolution, 0x8885DF49, 0x00000003)
	API_THUNK(WinNtApi, NtSetValueKey, 0x0BC1FC60, 0x00000006)
	API_THUNK(WinNtApi, NtSetVolumeInformationFile, 0xBC6E43DE, 0x00000005)
	API_THUNK(WinNtApi, NtShutdownSystem, 0xD7366F0C, 0x00000001)
	API_THUNK(WinNtApi, NtSignalAndWaitForSingleObject, 0xD9E09880, 0x00000004)
	API_THUNK(WinNtApi, NtStartProfile, 0xDDA03D7C, 0x00000001)
	API_THUNK(WinNtApi, NtStopProfile, 0x65E72407, 0x00000001)
	API_THUNK(WinNtApi, NtSuspendThread, 0xBB77C11E, 0x00000002)
	API_THUNK(WinNtApi, NtSystemDebugControl, 0xE0C0BB15, 0x00000006)
	API_THUNK(WinNtApi, NtTerminateProcess, 0x79BA37C5, 0x00000002)
	API_THUNK(WinNtApi, NtTerminateThread, 0x67866128, 0x00000002)
	API_THUNK(WinNtApi, NtTestAlert, 0xC3663ED4, 0x00000000)
	API_THUNK(WinNtApi, NtUnloadDriver, 0xC02430C1, 0x00000001)
	API_THUNK(WinNtApi, NtUnloadKey, 0x72DE6165, 0x00000001)
	API_THUNK(WinNtApi, NtUnlockFile, 0x6A70A8CD, 0x00000005)
	API_THUNK(WinNtApi, NtUnlockVirtualMemory, 0xA00E362C, 0x00000004)
	API_THUNK(WinNtApi, NtUnmapViewOfSection, 0x1FFBA02F, 0x00000002)
	API_THUNK(WinNtApi, NtWaitForMultipleObjects, 0xF30251F4, 0x00000005)
	API_THUNK(WinNtApi, NtWaitForSingleObject, 0xBC08D384, 0x00000003)
	API_THUNK(WinNtApi, NtWaitHighEventPair, 0x2620A625, 0x00000001)
	API_THUNK(WinNtApi, NtWaitLowEventPair, 0x5A385574, 0x00000001)
	API_THUNK(WinNtApi, NtWriteFile, 0xA14826B6, 0x00000009)
	API_THUNK(WinNtApi, NtWriteFileGather, 0x661B7B91, 0x00000009)
	API_THUNK(WinNtApi, NtWriteRequestData, 0x1C0C6BA2, 0x00000006)
	API_THUNK(WinNtApi, NtWriteVirtualMemory, 0x74EAF98E, 0x00000005)
	API_THUNK(WinNtApi, NtYieldExecution, 0x677293DF, 0x00000000)
	API_THUNK(WinNtApi, RtlAllocateHeap, 0x71127369, 0x00000003)
	API_THUNK(WinNtApi, RtlAnsiStringToUnicodeString, 0xFA592AAD, 0x00000003)
	API_THUNK(WinNtApi, RtlCompareUnicodeString, 0xDF6026A2, 0x00000003)
	API_THUNK(WinNtApi, RtlFreeAnsiString, 0x7BA791DC, 0x00000001)
	API_THUNK(WinNtApi, RtlFreeHeap, 0x6A3B92DE, 0x00000003)
	API_THUNK(WinNtApi, RtlFreeUnicodeString, 0x54ECB2BA, 0x00000001)
	API_THUNK(WinNtApi, RtlInitAnsiString, 0xCC441004, 0x00000002)
	API_THUNK(WinNtApi, RtlInitUnicodeString, 0xCCEDCC4D, 0x00000002)
	API_THUNK(WinNtApi, RtlReAllocateHeap, 0x2AD321F7, 0x00000004)
API_TABLE_END
