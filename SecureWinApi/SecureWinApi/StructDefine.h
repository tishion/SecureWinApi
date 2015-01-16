//#include <windows.h>

#pragma once

#define SystemProcessInformation 5

#ifndef _WINDOWS_
#define TRUE 1
#define FALSE 0

#define WINAPI __stdcall
#define NT_SUCCESS( status ) ( status >= 0 )

#define VOID void
#define CONST const
#define CALLBACK __stdcall

#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1

typedef int BOOL;
typedef __w64 unsigned long ULONG_PTR;
typedef ULONG_PTR DWORD_PTR;
typedef void *HANDLE;
typedef unsigned long DWORD, *PDWORD;
typedef signed short WORD, *PWORD;
typedef unsigned long ULONG, *PULONG;
typedef long LONG, *PLONG;
typedef short SHORT, *PSHORT;
typedef unsigned short USHORT, *PUSHORT;
typedef long long LONGLONG;
typedef unsigned int UINT;
typedef void *LPVOID, *LPCVOID, *PVOID;
typedef char *PCHAR, CHAR, BYTE, *PBYTE;
typedef unsigned char *PUCHAR, UCHAR;
typedef DWORD *PDWORD;
typedef ULONG_PTR SIZE_T;
typedef LONG NTSTATUS;
typedef unsigned short USHORT, *PUSHORT;
typedef wchar_t WCHAR;
typedef WCHAR *PWSTR;

typedef PVOID HANDLE;
typedef HANDLE HINSTANCE;
typedef HINSTANCE HMODULE;
typedef __nullterminated CONST CHAR *LPCSTR;

typedef int ( CALLBACK* FARPROC )( );

typedef struct _IMAGE_DATA_DIRECTORY
{
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _FLOATING_SAVE_AREA
{
	DWORD ControlWord;
	DWORD StatusWord;
	DWORD TagWord;
	DWORD ErrorOffset;
	DWORD ErrorSelector;
	DWORD DataOffset;
	DWORD DataSelector;
	BYTE RegisterArea[80];
	DWORD Cr0NpxState;
} FLOATING_SAVE_AREA;

typedef struct _IMAGE_FILE_HEADER
{
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER
{
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	DWORD BaseOfData;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_DOS_HEADER
{
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_NT_HEADERS
{
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions;
	DWORD NumberOfNames;
	DWORD AddressOfFunctions;
	DWORD AddressOfNames;
	DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#ifdef _M_IX86
#define CONTEXT_i386 0x00010000

#define CONTEXT_CONTROL (CONTEXT_i386 | 0x00000001L)
#define CONTEXT_INTEGER (CONTEXT_i386 | 0x00000002L)
#define CONTEXT_SEGMENTS (CONTEXT_i386 | 0x00000004L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L)
#define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER |\
	CONTEXT_SEGMENTS)

#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
	CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
	CONTEXT_EXTENDED_REGISTERS)
typedef struct _CONTEXT
{
	DWORD ContextFlags;

	DWORD Dr0;
	DWORD Dr1;
	DWORD Dr2;
	DWORD Dr3;
	DWORD Dr6;
	DWORD Dr7;

	FLOATING_SAVE_AREA FloatSave;

	DWORD SegGs;
	DWORD SegFs;
	DWORD SegEs;
	DWORD SegDs;

	DWORD Edi;
	DWORD Esi;
	DWORD Ebx;
	DWORD Edx;
	DWORD Ecx;
	DWORD Eax;


	DWORD Ebp;
	DWORD Eip;
	DWORD SegCs;
	DWORD EFlags;
	DWORD Esp;
	DWORD SegSs;

	BYTE ExtendedRegisters[512];

} CONTEXT;
typedef double ULONGLONG;

#elif _M_X64

#define CONTEXT_AMD64 0x100000

#define CONTEXT_CONTROL (CONTEXT_AMD64 | 0x1L)
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 0x2L)
#define CONTEXT_SEGMENTS (CONTEXT_AMD64 | 0x4L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_AMD64 | 0x8L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x10L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

#define CONTEXT_EXCEPTION_ACTIVE 0x8000000
#define CONTEXT_SERVICE_ACTIVE 0x10000000
#define CONTEXT_EXCEPTION_REQUEST 0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000


typedef struct DECLSPEC_ALIGN(16) _CONTEXT
{
	DWORD64 P1Home;
	DWORD64 P2Home;
	DWORD64 P3Home;
	DWORD64 P4Home;
	DWORD64 P5Home;
	DWORD64 P6Home;

	DWORD ContextFlags;
	DWORD MxCsr;
	WORD SegCs;
	WORD SegDs;
	WORD SegEs;
	WORD SegFs;
	WORD SegGs;
	WORD SegSs;
	DWORD EFlags;

	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;


	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;

	DWORD64 Rip;

	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		};
	};

	M128A VectorRegister[26];
	DWORD64 VectorControl;


	DWORD64 DebugControl;
	DWORD64 LastBranchToRip;
	DWORD64 LastBranchFromRip;
	DWORD64 LastExceptionToRip;
	DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;
typedef unsigned __int64 ULONGLONG;

#endif


typedef union _LARGE_INTEGER
{
	union
	{
		DWORD LowPart;
		LONG HighPart;
	};
	union
	{
		DWORD LowPart;
		LONG HighPart;
	} u;
	LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _IO_COUNTERS
{
	ULONGLONG ReadOperationCount;
	ULONGLONG WriteOperationCount;
	ULONGLONG OtherOperationCount;
	ULONGLONG ReadTransferCount;
	ULONGLONG WriteTransferCount;
	ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;


typedef struct _LIST_ENTRY
{
	struct _LIST_ENTRY  *Flink;
	struct _LIST_ENTRY  *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _MEMORY_BASIC_INFORMATION
{
	PVOID BaseAddress;
	PVOID AllocationBase;
	DWORD AllocationProtect;
	SIZE_T RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
#endif


typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef long KPRIORITY;

typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _VM_COUNTERS { 
	SIZE_T PeakVirtualSize; 
	SIZE_T VirtualSize; 
	ULONG PageFaultCount; 
	SIZE_T PeakWorkingSetSize; 
	SIZE_T WorkingSetSize; 
	SIZE_T QuotaPeakPagedPoolUsage; 
	SIZE_T QuotaPagedPoolUsage; 
	SIZE_T QuotaPeakNonPagedPoolUsage; 
	SIZE_T QuotaNonPagedPoolUsage; 
	SIZE_T PagefileUsage; 
	SIZE_T PeakPagefileUsage; 
} VM_COUNTERS; 


typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	LONG State;
	LONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING,*PUNICODE_STRING;

#define UNICODE_STRING_ \
	sizeof (UNICODE_STRING)

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG           NextEntryDelta;         // offset to the next entry
	ULONG           ThreadCount;            // number of threads
	ULONG           Reserved1[6];           // reserved
	LARGE_INTEGER   CreateTime;             // process creation time
	LARGE_INTEGER   UserTime;               // time spent in user mode
	LARGE_INTEGER   KernelTime;             // time spent in kernel mode
	UNICODE_STRING  ProcessName;            // process name
	KPRIORITY       BasePriority;           // base process priority
	ULONG           ProcessId;              // process identifier
	ULONG           InheritedFromProcessId; // parent process identifier
	ULONG           HandleCount;            // number of handles
	ULONG           Reserved2[2];           // reserved
	VM_COUNTERS     VmCounters;             // virtual memory counters
#if _WIN32_WINNT >= 0x500
	IO_COUNTERS     IoCounters;             // i/o counters
#endif
	SYSTEM_THREAD_INFORMATION Threads[1];   // threads
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOL Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

typedef DWORD ACCESS_MASK;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG Reserved[10];
} PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;



typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;


#define OBJ_INHERIT          0x00000002
#define OBJ_PERMANENT        0x00000010
#define OBJ_EXCLUSIVE        0x00000020
#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_OPENIF           0x00000080
#define OBJ_OPENLINK         0x00000100
#define OBJ_KERNEL_HANDLE    0x00000200
#define OBJ_VALID_ATTRIBUTES 0x000003F2

#define OBJECT_ATTRIBUTES_ \
        sizeof (OBJECT_ATTRIBUTES)



typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags; 
	USHORT Length; 
	ULONG TimeStamp; 
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength; 
	ULONG Length; 
	ULONG Flags; 
	ULONG DebugFlags; 
	PVOID ConsoleHandle; 
	ULONG ConsoleFlags; 
	HANDLE StdInputHandle; 
	HANDLE StdOutputHandle; 
	HANDLE StdErrorHandle; 
	UNICODE_STRING CurrentDirectoryPath; 
	HANDLE CurrentDirectoryHandle; 
	UNICODE_STRING DllPath; 
	UNICODE_STRING ImagePathName; 
	UNICODE_STRING CommandLine; 
	PVOID Environment; 
	ULONG StartingPositionLeft; 
	ULONG StartingPositionTop; 
	ULONG Width; 
	ULONG Height; 
	ULONG CharWidth; 
	ULONG CharHeight; 
	ULONG ConsoleTextAttributes; 
	ULONG WindowFlags; 
	ULONG ShowWindowFlags; 
	UNICODE_STRING WindowTitle; 
	UNICODE_STRING DesktopName; 
	UNICODE_STRING ShellInfo; 
	UNICODE_STRING RuntimeData; 
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];

} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void (*PPEBLOCKROUTINE)(
	PVOID PebLock
); 

typedef PVOID *PPVOID;

typedef struct _PEB_FREE_BLOCK
{
   struct _PEB_FREE_BLOCK* Next;
   ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace; 
	BOOLEAN ReadImageFileExecOptions; 
	BOOLEAN BeingDebugged; 
	BOOLEAN Spare; 
	HANDLE Mutant; 
	PVOID ImageBaseAddress; 
	PPEB_LDR_DATA LoaderData; 
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters; 
	PVOID SubSystemData; 
	PVOID ProcessHeap; 
	PVOID FastPebLock; 
	PPEBLOCKROUTINE FastPebLockRoutine; 
	PPEBLOCKROUTINE FastPebUnlockRoutine; 
	ULONG EnvironmentUpdateCount; 
	PPVOID KernelCallbackTable; 
	PVOID EventLogSection; 
	PVOID EventLog; 
	PPEB_FREE_BLOCK FreeList; 
	ULONG TlsExpansionCounter; 
	PVOID TlsBitmap; 
	ULONG TlsBitmapBits[0x2]; 
	PVOID ReadOnlySharedMemoryBase; 
	PVOID ReadOnlySharedMemoryHeap; 
	PPVOID ReadOnlyStaticServerData; 
	PVOID AnsiCodePageData; 
	PVOID OemCodePageData; 
	PVOID UnicodeCaseTableData; 
	ULONG NumberOfProcessors; 
	ULONG NtGlobalFlag; 
	BYTE Spare2[0x4]; 
	LARGE_INTEGER CriticalSectionTimeout; 
	ULONG HeapSegmentReserve; 
	ULONG HeapSegmentCommit; 
	ULONG HeapDeCommitTotalFreeThreshold; 
	ULONG HeapDeCommitFreeBlockThreshold; 
	ULONG NumberOfHeaps; 
	ULONG MaximumNumberOfHeaps; 
	PPVOID *ProcessHeaps; 
	PVOID GdiSharedHandleTable; 
	PVOID ProcessStarterHelper; 
	PVOID GdiDCAttributeList; 
	PVOID LoaderLock; 
	ULONG OSMajorVersion; 
	ULONG OSMinorVersion; 
	ULONG OSBuildNumber; 
	ULONG OSPlatformId; 
	ULONG ImageSubSystem; 
	ULONG ImageSubSystemMajorVersion; 
	ULONG ImageSubSystemMinorVersion; 
	ULONG GdiHandleBuffer[0x22]; 
	ULONG PostProcessInitRoutine; 
	ULONG TlsExpansionBitmap; 
	BYTE TlsExpansionBitmapBits[0x80]; 
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _TEB {
	NT_TIB Tib; 
	PVOID EnvironmentPointer; 
	CLIENT_ID Cid; 
	PVOID ActiveRpcInfo; 
	PVOID ThreadLocalStoragePointer; 
	PPEB Peb; ULONG LastErrorValue; 
	ULONG CountOfOwnedCriticalSections; 
	PVOID CsrClientThread; 
	PVOID Win32ThreadInfo; 
	ULONG Win32ClientInfo[0x1F]; 
	PVOID WOW32Reserved; 
	ULONG CurrentLocale; 
	ULONG FpSoftwareStatusRegister; 
	PVOID SystemReserved1[0x36]; 
	PVOID Spare1; 
	ULONG ExceptionCode; 
	ULONG SpareBytes1[0x28]; 
	PVOID SystemReserved2[0xA]; 
	ULONG GdiRgn; 
	ULONG GdiPen; 
	ULONG GdiBrush; 
	CLIENT_ID RealClientId; 
	PVOID GdiCachedProcessHandle; 
	ULONG GdiClientPID; 
	ULONG GdiClientTID; 
	PVOID GdiThreadLocaleInfo; 
	PVOID UserReserved[5]; 
	PVOID GlDispatchTable[0x118]; 
	ULONG GlReserved1[0x1A]; 
	PVOID GlReserved2; 
	PVOID GlSectionInfo; 
	PVOID GlSection; 
	PVOID GlTable; 
	PVOID GlCurrentRC; 
	PVOID GlContext; 
	NTSTATUS LastStatusValue; 
	UNICODE_STRING StaticUnicodeString; 
	WCHAR StaticUnicodeBuffer[0x105]; 
	PVOID DeallocationStack; 
	PVOID TlsSlots[0x40]; 
	LIST_ENTRY TlsLinks; 
	PVOID Vdm; 
	PVOID ReservedForNtRpc; 
	PVOID DbgSsReserved[0x2]; 
	ULONG HardErrorDisabled; 
	PVOID Instrumentation[0x10]; 
	PVOID WinSockData; 
	ULONG GdiBatchCount; 
	ULONG Spare2; 
	ULONG Spare3; 
	ULONG Spare4; 
	PVOID ReservedForOle; 
	ULONG WaitingOnLoaderLock; 
	PVOID StackCommit; 
	PVOID StackCommitMax; 
	PVOID StackReserved;
} TEB, *PTEB;

typedef struct _STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

#define STATUS_SUCCESS                   ((NTSTATUS) 0x00000000)

typedef LONG    KPRIORITY;



#define TH32CS_SNAPHEAPLIST	0x1
#define TH32CS_SNAPPROCESS	0x2
#define TH32CS_SNAPTHREAD	0x4
#define TH32CS_SNAPMODULE	0x8
#define TH32CS_SNAPALL	(TH32CS_SNAPHEAPLIST|TH32CS_SNAPPROCESS|TH32CS_SNAPTHREAD|TH32CS_SNAPMODULE)
#define TH32CS_INHERIT	0x80000000

struct snapshot
{
    int         process_count;
    int         process_pos;
    int         process_offset;
    int         thread_count;
    int         thread_pos;
    int         thread_offset;
    int         module_count;
    int         module_pos;
    int         module_offset;
    char        data[1];
};

#define MAX_MODULE_NAME32 255

typedef struct tagMODULEENTRY32W
{
    DWORD   dwSize;
    DWORD   th32ModuleID;       // This module
    DWORD   th32ProcessID;      // owning process
    DWORD   GlblcntUsage;       // Global usage count on the module
    DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context
    BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
    DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
    HMODULE hModule;            // The hModule of this module in th32ProcessID's context
    WCHAR   szModule[MAX_MODULE_NAME32 + 1];
    WCHAR   szExePath[MAX_PATH];
} MODULEENTRY32W;
typedef MODULEENTRY32W *  PMODULEENTRY32W;
typedef MODULEENTRY32W *  LPMODULEENTRY32W;

typedef unsigned long ULONG_PTR;

typedef struct tagPROCESSENTRY32W
{
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;          // this process
    ULONG_PTR th32DefaultHeapID;
    DWORD   th32ModuleID;           // associated exe
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;    // this process's parent process
    LONG    pcPriClassBase;         // Base priority of process's threads
    DWORD   dwFlags;
    WCHAR   szExeFile[MAX_PATH];    // Path
} PROCESSENTRY32W;
typedef PROCESSENTRY32W *  PPROCESSENTRY32W;
typedef PROCESSENTRY32W *  LPPROCESSENTRY32W;

typedef struct tagTHREADENTRY32
{
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ThreadID;       // this thread
    DWORD   th32OwnerProcessID; // Process this thread is associated with
    LONG    tpBasePri;
    LONG    tpDeltaPri;
    DWORD   dwFlags;
} THREADENTRY32;
typedef THREADENTRY32 *  PTHREADENTRY32;
typedef THREADENTRY32 *  LPTHREADENTRY32;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x)>=0)
#endif

typedef struct {
	PIMAGE_NT_HEADERS headers;
	unsigned char *codeBase;
	HMODULE *modules;
	int numModules;
	int initialized;
} MEMORYMODULE, *PMEMORYMODULE;

#define GET_HEADER_DICTIONARY(module, idx)	&(module)->headers->OptionalHeader.DataDirectory[idx]

	typedef enum _MEMORY_INFORMATION_CLASS
	{
		MemoryBasicInformation

	} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;


typedef struct tagPROCESSENTRY32
{
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;          // this process
    ULONG_PTR th32DefaultHeapID;
    DWORD   th32ModuleID;           // associated exe
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;    // this process's parent process
    LONG    pcPriClassBase;         // Base priority of process's threads
    DWORD   dwFlags;
    CHAR    szExeFile[MAX_PATH];    // Path
} PROCESSENTRY32;
typedef PROCESSENTRY32 *  PPROCESSENTRY32;
typedef PROCESSENTRY32 *  LPPROCESSENTRY32;

typedef struct tagMODULEENTRY32
{
    DWORD   dwSize;
    DWORD   th32ModuleID;       // This module
    DWORD   th32ProcessID;      // owning process
    DWORD   GlblcntUsage;       // Global usage count on the module
    DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context
    BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
    DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
    HMODULE hModule;            // The hModule of this module in th32ProcessID's context
    char    szModule[MAX_MODULE_NAME32 + 1];
    char    szExePath[MAX_PATH];
} MODULEENTRY32;
typedef MODULEENTRY32 *  PMODULEENTRY32;
typedef MODULEENTRY32 *  LPMODULEENTRY32;


/* disposition for NtCreateFile */
#define FILE_SUPERSEDE                  0
#define FILE_OPEN                       1
#define FILE_CREATE                     2
#define FILE_OPEN_IF                    3
#define FILE_OVERWRITE                  4
#define FILE_OVERWRITE_IF               5
#define FILE_MAXIMUM_DISPOSITION        5

/* flags for NtCreateFile and NtOpenFile */
#define FILE_DIRECTORY_FILE             0x00000001
#define FILE_WRITE_THROUGH              0x00000002
#define FILE_SEQUENTIAL_ONLY            0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING  0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT       0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#define FILE_NON_DIRECTORY_FILE         0x00000040
#define FILE_CREATE_TREE_CONNECTION     0x00000080
#define FILE_COMPLETE_IF_OPLOCKED       0x00000100
#define FILE_NO_EA_KNOWLEDGE            0x00000200
#define FILE_OPEN_FOR_RECOVERY          0x00000400
#define FILE_RANDOM_ACCESS              0x00000800
#define FILE_DELETE_ON_CLOSE            0x00001000
#define FILE_OPEN_BY_FILE_ID            0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT     0x00004000
#define FILE_NO_COMPRESSION             0x00008000
#define FILE_RESERVE_OPFILTER           0x00100000
#define FILE_TRANSACTED_MODE            0x00200000
#define FILE_OPEN_OFFLINE_FILE          0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY  0x00800000