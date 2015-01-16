#include "stdafx.h"

#define NO_CRT

#include "..\SecureWinApi\SecureWinApi\SecureWinApi.h"
#ifdef _DEBUG
#pragma comment( lib, "..\\Bin-Debug\\SecureWinApi.lib")
#else
#pragma comment( lib, "..\\Bin-Release\\SecureWinApi.lib")
#endif // _DEBUG

#ifdef NO_CRT
#pragma comment( linker, "/SUBSYSTEM:WINDOWS" )
#pragma comment( linker, "/ENTRY:main" )
//#define _tprintf __noop
//#define _tsystem __noop
#endif


DWORD GetThreadStartAddress( HANDLE ThreadHandle )
{
	DWORD StartAddress = 0;

	WinNtApi::NtQueryInformationThread( ThreadHandle, (PVOID)9, &StartAddress, sizeof( DWORD ), 0 );

	if( !StartAddress )
		WinNtApi::NtQueryInformationThread( ThreadHandle, (PVOID)8, &StartAddress, sizeof( DWORD ), 0 );

	return( StartAddress );
}

// Checking the instruction pointer is removed temporarily,
// because imports are made to MSVCR functions when using a CONTEXT variable.
DWORD EnumerateThreads( DWORD ProcessId )
{
	PVOID *SysProcess = ( PVOID * ) 0;
	HANDLE ThreadHandle = 0;


	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;

	DWORD BadThreadCount = 0;
	DWORD ThreadStartAddress = 0;
	DWORD ThreadIP = 0;

	SYSTEM_PROCESS_INFORMATION *CurrProcess;

	SysProcess = (PVOID *)Win32Api::VirtualAlloc(NULL, 0x100000, 0x1000, 0x04 );

	NTSTATUS status = WinNtApi::NtQuerySystemInformation((PVOID)SystemProcessInformation, SysProcess, 0x100000,0);
	if (status != STATUS_SUCCESS)
	{
		Win32Api::VirtualFree(SysProcess,0, MEM_RELEASE);
		return 0;
	}

	CurrProcess = ( SYSTEM_PROCESS_INFORMATION * ) &SysProcess[0];
	while( CurrProcess->NextEntryDelta && ( DWORD ) CurrProcess->ProcessId != ProcessId )
	{
		CurrProcess = ( SYSTEM_PROCESS_INFORMATION * ) ( ( DWORD ) CurrProcess + ( DWORD ) CurrProcess->NextEntryDelta );
	}

	for( unsigned int i = 0; i < CurrProcess->ThreadCount; i++ )
	{
		ThreadHandle = Win32Api::OpenThread( 0x48, FALSE, ( DWORD ) CurrProcess->Threads[i].ClientId.UniqueThread );
		ThreadStartAddress = GetThreadStartAddress( ThreadHandle );

		Win32Api::GetThreadContext( ThreadHandle, &ctx );

#ifdef _M_IX86
		ThreadIP = ctx.Eip;
#elif _M_IX64
		ThreadIP = ctx.Rip;
#endif

		//_tprintf(_T("Thread [0x%08X]: StartAddress: 0x%08X\r\n"), CurrProcess->Threads[i].ClientId, ThreadStartAddress);

		Win32Api::CloseHandle( ThreadHandle );
	}
	Win32Api::VirtualFree(SysProcess,0, MEM_RELEASE);
	return 0;
	return( BadThreadCount );
}

DWORD EnumerateModules( )
{
	PLIST_ENTRY pebModuleHeader, ModuleLoop;
	PLDR_MODULE lclModule;
	PPEB_LDR_DATA pebModuleLdr;
	DWORD BadModuleCount = 0;

#if _M_IX86
	pebModuleLdr = ( PPEB_LDR_DATA ) *( ( DWORD_PTR * ) __readfsdword( 0x30 ) + 12 / sizeof( DWORD_PTR ) );
#elif _M_X64
	pebModuleLdr = ( PPEB_LDR_DATA ) *( ( DWORD_PTR * ) __readgsqword( 0x60 ) + 24 / sizeof( DWORD_PTR ) );
#endif

	pebModuleHeader = ( PLIST_ENTRY ) &pebModuleLdr->InLoadOrderModuleList;

	lclModule = ( PLDR_MODULE ) pebModuleHeader->Flink;
	ModuleLoop = pebModuleHeader->Flink;
	while( pebModuleHeader != ModuleLoop)
	{
		//_tprintf(_T("Module [%s]:\r\n")
		//	_T("\tBaseName: %s\r\n")
		//	_T("\tEntryPoint: 0x%08X\r\n") 
		//	_T("\tBase: 0x%08X\r\n") 
		//	_T("\tSize: 0x%08X\r\n"), 
		//	lclModule->FullDllName.Buffer,
		//	lclModule->BaseDllName.Buffer,
		//	lclModule->EntryPoint,
		//	lclModule->BaseAddress,
		//	lclModule->SizeOfImage);

		lclModule = ( PLDR_MODULE ) ModuleLoop->Flink;
		ModuleLoop = ModuleLoop->Flink;
	}
	return( BadModuleCount );
}

DWORD EnumerateRegions( )
{
	DWORD BadSegmentCount = 0;
	MEMORY_BASIC_INFORMATION pe, text, rdata, data, rsrc, reloc;

	Win32Api::VirtualQuery( ( void * ) 0x00400000, &pe, sizeof( MEMORY_BASIC_INFORMATION ) );
	Win32Api::VirtualQuery( ( void * ) 0x00401000, &text, sizeof( MEMORY_BASIC_INFORMATION ) );
	Win32Api::VirtualQuery( ( void * ) 0x00402000, &rdata, sizeof( MEMORY_BASIC_INFORMATION ) );
	Win32Api::VirtualQuery( ( void * ) 0x00403000, &data, sizeof( MEMORY_BASIC_INFORMATION ) );
	Win32Api::VirtualQuery( ( void * ) 0x00405000, &rsrc, sizeof( MEMORY_BASIC_INFORMATION ) );
	Win32Api::VirtualQuery( ( void * ) 0x00406000, &reloc, sizeof( MEMORY_BASIC_INFORMATION ) );

	//_tprintf(_T("MemRegion [0x00400000]:")
	//	_T("\tBaseAddress: 0x%08X\r\n")
	//	_T("\tAllocationBase: 0x%08X\r\n")
	//	_T("\tAllocationProtect: 0x%08X\r\n")
	//	_T("\tRegionSize: 0x%08X\r\n")
	//	_T("\tState: 0x%08X\r\n")
	//	_T("\tProtect: 0x%08X\r\n")
	//	_T("\tType: 0x%08X\r\n"),
	//	pe.BaseAddress,
	//	pe.AllocationBase,
	//	pe.AllocationProtect,
	//	pe.RegionSize,
	//	pe.State,
	//	pe.Protect,
	//	pe.Type);

	return( BadSegmentCount );
}

void main( )
{
	//_tprintf(_T("EnumerateThreads:\r\n"));

	HANDLE hMod = Win32Api::LoadLibraryA("CalleeMaze.dll");

	if (hMod)
	{
		_tprintf(_T("LoadLibraryW success!\r\n"));
	}
	else
	{
		_tprintf(_T("LoadLibraryW failed!\r\n"));
	}

	if( EnumerateThreads( Win32Api::GetCurrentProcessId( ) ) != 0 )
		Win32Api::ExitProcess( -1 );

	//_tprintf(_T("\r\n"));
	//_tprintf(_T("EnumerateModules:\r\n"));
	if( EnumerateModules( ) != 0 )
		Win32Api::ExitProcess( -3 );

	//_tprintf(_T("\r\n"));
	//_tprintf(_T("EnumerateRegions:\r\n"));
	if( EnumerateRegions( ) != 0 )
		Win32Api::ExitProcess( -4 );

	//_tsystem(_T("PAUSE"));
	Win32Api::ExitProcess( 0 );
}