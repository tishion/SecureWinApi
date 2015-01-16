#ifndef DirectSysCall_h_INC
#define DirectSysCall_h_INC

#include <windows.h>
#include <intrin.h>
#include "StructDefine.h"
#include "WinApiDefine.h"

#if !defined(_M_IX86) && !defined(_M_X64)
#error Unsupported platform.
#endif

namespace WinNtApi
{
	HMODULE OriginalNtdllHanlde();
	HMODULE NtdllModuleHandle();

	PTEB NtCurrentTeb();

	NTSTATUS WINAPI LdrLoadDll(
		LPCWSTR path_name,
		DWORD flags,
		const UNICODE_STRING* libname, HMODULE* phModule);

	NTSTATUS WINAPI LdrGetProcedureAddress(
		HMODULE module, 
		const ANSI_STRING *name,
		ULONG ord, 
		PVOID *address);

	NTSTATUS WINAPI NtAcceptConnectPort(
		PHANDLE PortHandle,
		ULONG PortIdentifier,
		PVOID Message,
		BOOLEAN Accept,
		PVOID ServerView,
		PVOID ClientView);

	NTSTATUS WINAPI NtAccessCheck(
		PSECURITY_DESCRIPTOR SecurityDescriptor,
		HANDLE TokenHandle,
		ACCESS_MASK DesiredAccess,
		PGENERIC_MAPPING GenericMapping,
		PPRIVILEGE_SET PrivilegeSet,
		PULONG PrivilegeSetLength,
		PULONG GrantedAccess,
		NTSTATUS* AccessStatus);

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
		PBOOLEAN GenerateOnClose);

	NTSTATUS WINAPI NtAddAtom(
		const WCHAR* String,
		ULONG StringLength,
		PVOID Atom);

	NTSTATUS WINAPI NtAdjustGroupsToken(
		HANDLE TokenHandle,
		BOOLEAN ResetToDefault,
		PTOKEN_GROUPS NewState,
		ULONG BufferLength,
		PTOKEN_GROUPS PreviousState,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtAdjustPrivilegesToken(
		HANDLE TokenHandle,
		BOOLEAN DisableAllPrivileges,
		PTOKEN_PRIVILEGES NewState,
		DWORD BufferLength,
		PTOKEN_PRIVILEGES PreviousState,
		PDWORD ReturnLength);

	NTSTATUS WINAPI NtAlertResumeThread(
		HANDLE ThreadHandle,
		PULONG PreviousSuspendCount);

	NTSTATUS WINAPI NtAlertThread(
		HANDLE ThreadHandle);

	NTSTATUS WINAPI NtAllocateLocallyUniqueId(
		PLUID Luid);

	NTSTATUS WINAPI NtAllocateVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		ULONG ZeroBits,
		SIZE_T* AllocationSize,
		ULONG AllocationType,
		ULONG Protect);

	NTSTATUS WINAPI NtCallbackReturn(
		PVOID Result,
		ULONG ResultLength,
		NTSTATUS Status);

	NTSTATUS WINAPI NtCancelIoFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock);

	NTSTATUS WINAPI NtCancelTimer(
		HANDLE TimerHandle,
		BOOLEAN* PreviousState);

	NTSTATUS WINAPI NtClearEvent(
		HANDLE EventHandle);

	NTSTATUS WINAPI NtClose(
		HANDLE Handle);

	NTSTATUS WINAPI NtCloseObjectAuditAlarm(
		PUNICODE_STRING SubsystemName,
		HANDLE Id,
		BOOLEAN GenerateOnClose);

	NTSTATUS WINAPI NtCompleteConnectPort(
		HANDLE PortHandle);

	NTSTATUS WINAPI NtConnectPort(
		PHANDLE PortHandle,
		PUNICODE_STRING PortName,
		PSECURITY_QUALITY_OF_SERVICE SecurityQos,
		PVOID ClientView,
		PVOID ServerView,
		PULONG MaxMessageLength,
		PVOID ConnectInformation,
		PULONG ConnectInformationLength);

	NTSTATUS WINAPI NtContinue(
		PCONTEXT Context,
		BOOLEAN TestAlert);

	NTSTATUS WINAPI NtCreateDirectoryObject(
		PHANDLE DirectoryHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS WINAPI NtCreateEvent(
		PHANDLE EventHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		PVOID EventType,
		BOOLEAN InitialState);

	NTSTATUS WINAPI NtCreateEventPair(
		PHANDLE EventPairHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes);

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
		ULONG EaLength);

	NTSTATUS WINAPI NtCreateIoCompletion(
		PHANDLE IoCompletionHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		ULONG NumberOfConcurrentThreads);

	NTSTATUS WINAPI NtCreateKey(
		PHANDLE KeyHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		ULONG TitleIndex,
		const UNICODE_STRING* Class,
		ULONG CreateOptions,
		PULONG Disposition);

	NTSTATUS WINAPI NtCreateMailslotFile(
		PHANDLE FileHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock,
		ULONG CreateOptions,
		ULONG InBufferSize,
		ULONG MaxMessageSize,
		PLARGE_INTEGER ReadTime);

	NTSTATUS WINAPI NtCreateMutant(
		HANDLE* MutantHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		BOOLEAN InitialOwner);

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
		PLARGE_INTEGER DefaultTime);

	NTSTATUS WINAPI NtCreatePagingFile(
		PUNICODE_STRING FileName,
		PLARGE_INTEGER InitialSize,
		PLARGE_INTEGER MaximumSize,
		PLARGE_INTEGER Priority);

	NTSTATUS WINAPI NtCreatePort(
		PHANDLE PortHandle,
		POBJECT_ATTRIBUTES ObjectAttributes,
		ULONG MaxConnectionInfoLength,
		ULONG MaxMessageLength,
		PULONG MaxPoolUsage);

	NTSTATUS WINAPI NtCreateProcess(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		HANDLE InheritFromProcessHandle,
		BOOLEAN InheritHandles,
		HANDLE SectionHandle,
		HANDLE DebugPort,
		HANDLE ExceptionPort);

	NTSTATUS WINAPI NtCreateProfile(
		PHANDLE ProfileHandle,
		HANDLE ProcessHandle,
		PVOID Base,
		ULONG Size,
		ULONG BucketShift,
		PVOID Buffer,
		ULONG BufferLength,
		PVOID Source,
		KAFFINITY ProcessorMask);

	NTSTATUS WINAPI NtCreateSection(
		HANDLE* SectionHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		const LARGE_INTEGER* SectionSize,
		ULONG Protect,
		ULONG Attributes,
		HANDLE FileHandle);

	NTSTATUS WINAPI NtCreateSemaphore(
		PHANDLE SemaphoreHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		LONG InitialCount,
		LONG MaximumCount);

	NTSTATUS WINAPI NtCreateSymbolicLinkObject(
		PHANDLE SymbolicLinkHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PUNICODE_STRING TargetName);

	NTSTATUS WINAPI NtCreateThread(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		HANDLE ProcessHandle,
		PCLIENT_ID ClientId,
		PCONTEXT ThreadContext,
		PVOID UserStack,
		BOOLEAN CreateSuspended);

	NTSTATUS WINAPI NtCreateTimer(
		HANDLE* TimerHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		PVOID TimerType);

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
		PTOKEN_SOURCE Source);

	NTSTATUS WINAPI NtDelayExecution(
		BOOLEAN Alertable,
		const LARGE_INTEGER* Interval);

	NTSTATUS WINAPI NtDeleteAtom(
		PVOID Atom);

	NTSTATUS WINAPI NtDeleteFile(
		POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS WINAPI NtDeleteKey(
		HANDLE KeyHandle);

	NTSTATUS WINAPI NtDeleteValueKey(
		HANDLE KeyHandle,
		const UNICODE_STRING* ValueName);

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
		ULONG OutputBufferLength);

	NTSTATUS WINAPI NtDisplayString(
		PUNICODE_STRING String);

	NTSTATUS WINAPI NtDuplicateObject(
		HANDLE SourceProcessHandle,
		HANDLE SourceHandle,
		HANDLE TargetProcessHandle,
		PHANDLE TargetHandle,
		ACCESS_MASK DesiredAccess,
		ULONG Attributes,
		ULONG Options);

	NTSTATUS WINAPI NtDuplicateToken(
		HANDLE ExistingTokenHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		SECURITY_IMPERSONATION_LEVEL EffectiveOnly,
		TOKEN_TYPE TokenType,
		PHANDLE NewTokenHandle);

	NTSTATUS WINAPI NtEnumerateKey(
		HANDLE KeyHandle,
		ULONG Index,
		PVOID KeyInformationClass,
		void* KeyInformation,
		DWORD KeyInformationLength,
		DWORD* ResultLength);

	NTSTATUS WINAPI NtEnumerateValueKey(
		HANDLE KeyHandle,
		ULONG Index,
		PVOID KeyValueInformationClass,
		PVOID KeyValueInformation,
		ULONG KeyValueInformationLength,
		PULONG ResultLength);

	NTSTATUS WINAPI NtExtendSection(
		HANDLE SectionHandle,
		PLARGE_INTEGER SectionSize);

	NTSTATUS WINAPI NtFindAtom(
		const WCHAR* String,
		ULONG StringLength,
		PVOID* Atom);

	NTSTATUS WINAPI NtFlushBuffersFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock);

	NTSTATUS WINAPI NtFlushInstructionCache(
		HANDLE ProcessHandle,
		LPCVOID BaseAddress,
		SIZE_T FlushSize);

	NTSTATUS WINAPI NtFlushKey(
		HANDLE KeyHandle);

	NTSTATUS WINAPI NtFlushVirtualMemory(
		HANDLE ProcessHandle,
		LPCVOID* BaseAddress,
		SIZE_T* FlushSize,
		ULONG IoStatusBlock);

	NTSTATUS WINAPI NtFlushWriteBuffer();

	NTSTATUS WINAPI NtFreeVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		SIZE_T* FreeSize,
		ULONG FreeType);

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
		ULONG OutputBufferLength);

	NTSTATUS WINAPI NtGetContextThread(
		HANDLE ThreadHandle,
		CONTEXT* Context);

	NTSTATUS WINAPI NtGetPlugPlayEvent(
		ULONG Reserved1,
		ULONG Reserved2,
		PVOID Buffer,
		ULONG BufferLength);

	NTSTATUS WINAPI NtImpersonateClientOfPort(
		HANDLE PortHandle,
		PVOID Message);

	NTSTATUS WINAPI NtImpersonateThread(
		HANDLE ThreadHandle,
		HANDLE TargetThreadHandle,
		PSECURITY_QUALITY_OF_SERVICE SecurityQos);

	NTSTATUS WINAPI NtInitializeRegistry(
		BOOLEAN Setup);

	NTSTATUS WINAPI NtListenPort(
		HANDLE PortHandle,
		PVOID Message);

	NTSTATUS WINAPI NtLoadDriver(
		const UNICODE_STRING* DriverServiceName);

	NTSTATUS WINAPI NtLoadKey(
		const OBJECT_ATTRIBUTES* KeyObjectAttributes,
		OBJECT_ATTRIBUTES* FileObjectAttributes);

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
		BOOLEAN ExclusiveLock);

	NTSTATUS WINAPI NtLockVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		SIZE_T* LockSize,
		ULONG LockType);

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
		ULONG Protect);

	NTSTATUS WINAPI NtNotifyChangeDirectoryFile(
		HANDLE FileHandle,
		HANDLE Event,
		PVOID ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG BufferLength,
		ULONG NotifyFilter,
		BOOLEAN WatchSubtree);

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
		BOOLEAN Asynchronous);

	NTSTATUS WINAPI NtOpenDirectoryObject(
		PHANDLE DirectoryHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS WINAPI NtOpenEvent(
		PHANDLE EventHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes);

	NTSTATUS WINAPI NtOpenEventPair(
		PHANDLE EventPairHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS WINAPI NtOpenFile(
		PHANDLE FileHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock,
		ULONG ShareAccess,
		ULONG OpenOptions);

	NTSTATUS WINAPI NtOpenIoCompletion(
		PHANDLE IoCompletionHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS WINAPI NtOpenKey(
		PHANDLE KeyHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes);

	NTSTATUS WINAPI NtOpenMutant(
		PHANDLE MutantHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes);

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
		PBOOLEAN GenerateOnClose);

	NTSTATUS WINAPI NtOpenProcess(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		const CLIENT_ID* ClientId);

	NTSTATUS WINAPI NtOpenProcessToken(
		HANDLE ProcessHandle,
		DWORD DesiredAccess,
		HANDLE* TokenHandle);

	NTSTATUS WINAPI NtOpenSection(
		HANDLE* SectionHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes);

	NTSTATUS WINAPI NtOpenSemaphore(
		PHANDLE SemaphoreHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes);

	NTSTATUS WINAPI NtOpenSymbolicLinkObject(
		PHANDLE SymbolicLinkHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS WINAPI NtOpenThread(
		HANDLE* ThreadHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		const CLIENT_ID* ClientId);

	NTSTATUS WINAPI NtOpenThreadToken(
		HANDLE ThreadHandle,
		DWORD DesiredAccess,
		BOOLEAN OpenAsSelf,
		HANDLE* TokenHandle);

	NTSTATUS WINAPI NtOpenTimer(
		HANDLE* TimerHandle,
		ACCESS_MASK DesiredAccess,
		const OBJECT_ATTRIBUTES* ObjectAttributes);

	NTSTATUS WINAPI NtPrivilegeCheck(
		HANDLE TokenHandle,
		PPRIVILEGE_SET RequiredPrivileges,
		PBOOLEAN Result);

	NTSTATUS WINAPI NtPrivilegeObjectAuditAlarm(
		PUNICODE_STRING SubsystemName,
		HANDLE Id,
		HANDLE TokenHandle,
		ULONG DesiredAccess,
		PPRIVILEGE_SET Privileges,
		BOOLEAN AccessGranted);

	NTSTATUS WINAPI NtPrivilegedServiceAuditAlarm(
		PUNICODE_STRING SubsystemName,
		PUNICODE_STRING ServiceName,
		HANDLE TokenHandle,
		PPRIVILEGE_SET Privileges,
		BOOLEAN AccessGranted);

	NTSTATUS WINAPI NtProtectVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PULONG ProtectSize,
		ULONG NewProtect,
		PULONG OldProtect);

	NTSTATUS WINAPI NtPulseEvent(
		HANDLE EventHandle,
		PULONG PreviousState);

	NTSTATUS WINAPI NtQueryAttributesFile(
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		PVOID FileInformation);

	NTSTATUS WINAPI NtQueryDefaultLocale(
		BOOLEAN ThreadOrSystem,
		LCID* Locale);

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
		BOOLEAN RestartScan);

	NTSTATUS WINAPI NtQueryDirectoryObject(
		HANDLE DirectoryHandle,
		PVOID Buffer,
		ULONG BufferLength,
		BOOLEAN ReturnSingleEntry,
		BOOLEAN RestartScan,
		PULONG Context,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQueryEaFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG BufferLength,
		BOOLEAN ReturnSingleEntry,
		PVOID EaList,
		ULONG EaListLength,
		PULONG EaIndex,
		BOOLEAN RestartScan);

	NTSTATUS WINAPI NtQueryEvent(
		HANDLE EventHandle,
		PVOID EventInformationClass,
		PVOID EventInformation,
		ULONG EventInformationLength,
		PULONG ResultLength);

	NTSTATUS WINAPI NtQueryFullAttributesFile(
		const OBJECT_ATTRIBUTES* ObjectAttributes,
		PVOID FileInformation);

	NTSTATUS WINAPI NtQueryInformationAtom(
		PVOID Atom,
		PVOID AtomInformationClass,
		PVOID AtomInformation,
		ULONG AtomInformationLength,
		ULONG* ReturnLength);

	NTSTATUS WINAPI NtQueryInformationFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		LONG FileInformationLength,
		PVOID FileInformationClass);

	NTSTATUS WINAPI NtQueryInformationPort(
		HANDLE PortHandle,
		PVOID PortInformationClass,
		PVOID PortInformation,
		ULONG PortInformationLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQueryInformationProcess(
		HANDLE ProcessHandle,
		PVOID ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQueryInformationThread(
		HANDLE ThreadHandle,
		PVOID ThreadInformationClass,
		PVOID ThreadInformation,
		ULONG ThreadInformationLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQueryInformationToken(
		HANDLE TokenHandle,
		TOKEN_INFORMATION_CLASS TokenInformationClass,
		PVOID TokenInformation,
		ULONG TokenInformationLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQueryIntervalProfile(
		PVOID Source,
		PULONG Interval);

	NTSTATUS WINAPI NtQueryIoCompletion(
		HANDLE IoCompletionHandle,
		PVOID IoCompletionInformationClass,
		PVOID IoCompletionInformation,
		ULONG IoCompletionInformationLength,
		PULONG ResultLength);

	NTSTATUS WINAPI NtQueryKey(
		HANDLE KeyHandle,
		PVOID KeyInformationClass,
		void* KeyInformation,
		DWORD KeyInformationLength,
		DWORD* ResultLength);

	NTSTATUS WINAPI NtQueryMultipleValueKey(
		HANDLE KeyHandle,
		PVOID ValueList,
		ULONG NumberOfValues,
		PVOID Buffer,
		ULONG Length,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQueryMutant(
		HANDLE MutantHandle,
		PVOID MutantInformationClass,
		PVOID MutantInformation,
		ULONG MutantInformationLength,
		PULONG ResultLength);

	NTSTATUS WINAPI NtQueryObject(
		HANDLE ObjectHandle,
		OBJECT_INFORMATION_CLASS ObjectInformationClass,
		PVOID ObjectInformation,
		ULONG ObjectInformationLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQueryPerformanceCounter(
		PLARGE_INTEGER PerformanceCount,
		PLARGE_INTEGER PerformanceFrequency);

	NTSTATUS WINAPI NtQuerySection(
		HANDLE SectionHandle,
		PVOID SectionInformationClass,
		PVOID SectionInformation,
		ULONG SectionInformationLength,
		PULONG ResultLength);

	NTSTATUS WINAPI NtQuerySecurityObject(
		HANDLE Handle,
		SECURITY_INFORMATION SecurityInformation,
		PSECURITY_DESCRIPTOR SecurityDescriptor,
		ULONG SecurityDescriptorLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQuerySemaphore(
		HANDLE SemaphoreHandle,
		PVOID SemaphoreInformationClass,
		PVOID SemaphoreInformation,
		ULONG SemaphoreInformationLength,
		PULONG ResultLength);

	NTSTATUS WINAPI NtQuerySymbolicLinkObject(
		HANDLE SymbolicLinkHandle,
		PUNICODE_STRING TargetName,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQuerySystemEnvironmentValue(
		PUNICODE_STRING Name,
		PWCHAR Value,
		ULONG ValueLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQuerySystemInformation(
		PVOID SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtQuerySystemTime(
		PLARGE_INTEGER CurrentTime);

	NTSTATUS WINAPI NtQueryTimer(
		HANDLE TimerHandle,
		PVOID TimerInformationClass,
		PVOID TimerInformation,
		ULONG TimerInformationLength,
		PULONG ResultLength);

	NTSTATUS WINAPI NtQueryTimerResolution(
		PULONG CoarsestResolution,
		PULONG FinestResolution,
		PULONG ActualResolution);

	NTSTATUS WINAPI NtQueryValueKey(
		HANDLE KeyHandle,
		const UNICODE_STRING* ValueName,
		PVOID KeyValueInformationClass,
		void* KeyValueInformation,
		DWORD KeyValueInformationLength,
		DWORD* ResultLength);

	NTSTATUS WINAPI NtQueryVirtualMemory(
		HANDLE ProcessHandle,
		LPCVOID BaseAddress,
		MEMORY_INFORMATION_CLASS MemoryInformationClass,
		PVOID MemoryInformation,
		SIZE_T MemoryInformationLength,
		SIZE_T* ReturnLength);

	NTSTATUS WINAPI NtQueryVolumeInformationFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID VolumeInformation,
		ULONG VolumeInformationLength,
		PVOID VolumeInformationClass);

	NTSTATUS WINAPI NtQueueApcThread(
		HANDLE ThreadHandle,
		PVOID ApcRoutine,
		ULONG_PTR ApcContext,
		ULONG_PTR Argument1,
		ULONG_PTR Argument2);

	NTSTATUS WINAPI NtRaiseException(
		PEXCEPTION_RECORD ExceptionRecord,
		PCONTEXT Context,
		BOOL SearchFrames);

	NTSTATUS WINAPI NtRaiseHardError(
		NTSTATUS Status,
		ULONG NumberOfArguments,
		PUNICODE_STRING StringArgumentsMask,
		PVOID* Arguments,
		PVOID ResponseOption,
		PVOID Response);

	NTSTATUS WINAPI NtReadFile(
		HANDLE FileHandle,
		HANDLE Event,
		PVOID ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key);

	NTSTATUS WINAPI NtReadFileScatter(
		HANDLE FileHandle,
		HANDLE Event,
		PVOID ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		FILE_SEGMENT_ELEMENT* Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key);

	NTSTATUS WINAPI NtReadRequestData(
		HANDLE PortHandle,
		PVOID Message,
		ULONG Index,
		PVOID Buffer,
		ULONG BufferLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtReadVirtualMemory(
		HANDLE ProcessHandle,
		const void* BaseAddress,
		void* Buffer,
		SIZE_T BufferLength,
		SIZE_T* ReturnLength);

	NTSTATUS WINAPI NtRegisterThreadTerminatePort(
		HANDLE PortHandle);

	NTSTATUS WINAPI NtReleaseMutant(
		HANDLE MutantHandle,
		PLONG PreviousState);

	NTSTATUS WINAPI NtReleaseSemaphore(
		HANDLE SemaphoreHandle,
		ULONG ReleaseCount,
		PULONG PPreviousCount);

	NTSTATUS WINAPI NtRemoveIoCompletion(
		HANDLE IoCompletionHandle,
		PULONG_PTR CompletionKey,
		PULONG_PTR CompletionValue,
		PIO_STATUS_BLOCK IoStatusBlock,
		PLARGE_INTEGER Time);

	NTSTATUS WINAPI NtReplaceKey(
		POBJECT_ATTRIBUTES NewFileObjectAttributes,
		HANDLE KeyHandle,
		POBJECT_ATTRIBUTES OldFileObjectAttributes);

	NTSTATUS WINAPI NtReplyPort(
		HANDLE PortHandle,
		PVOID ReplyMessage);

	NTSTATUS WINAPI NtReplyWaitReceivePort(
		HANDLE PortHandle,
		PULONG PortIdentifier,
		PVOID ReplyMessage,
		PVOID Message);

	NTSTATUS WINAPI NtReplyWaitReplyPort(
		HANDLE PortHandle,
		PVOID ReplyMessage);

	NTSTATUS WINAPI NtRequestPort(
		HANDLE PortHandle,
		PVOID RequestMessage);

	NTSTATUS WINAPI NtRequestWaitReplyPort(
		HANDLE PortHandle,
		PVOID RequestMessage,
		PVOID ReplyMessage);

	NTSTATUS WINAPI NtResetEvent(
		HANDLE EventHandle,
		PULONG PreviousState);

	NTSTATUS WINAPI NtRestoreKey(
		HANDLE KeyHandle,
		HANDLE FileHandle,
		ULONG Flags);

	NTSTATUS WINAPI NtResumeThread(
		HANDLE ThreadHandle,
		PULONG PreviousSuspendCount);

	NTSTATUS WINAPI NtSaveKey(
		HANDLE KeyHandle,
		HANDLE FileHandle);

	NTSTATUS WINAPI NtSetContextThread(
		HANDLE ThreadHandle,
		const CONTEXT* Context);

	NTSTATUS WINAPI NtSetDefaultHardErrorPort(
		HANDLE PortHandle);

	NTSTATUS WINAPI NtSetDefaultLocale(
		BOOLEAN ThreadOrSystem,
		LCID Locale);

	NTSTATUS WINAPI NtSetEaFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG BufferLength);

	NTSTATUS WINAPI NtSetEvent(
		HANDLE EventHandle,
		PULONG PreviousState);

	NTSTATUS WINAPI NtSetHighEventPair(
		HANDLE EventPairHandle);

	NTSTATUS WINAPI NtSetHighWaitLowEventPair(
		HANDLE EventPairHandle);

	NTSTATUS WINAPI NtSetInformationFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		ULONG FileInformationLength,
		PVOID FileInformationClass);

	NTSTATUS WINAPI NtSetInformationKey(
		HANDLE KeyHandle,
		const int KeyInformationClass,
		PVOID KeyInformation,
		ULONG KeyInformationLength);

	NTSTATUS WINAPI NtSetInformationObject(
		HANDLE ObjectHandle,
		OBJECT_INFORMATION_CLASS ObjectInformationClass,
		PVOID ObjectInformation,
		ULONG ObjectInformationLength);

	NTSTATUS WINAPI NtSetInformationProcess(
		HANDLE ProcessHandle,
		PVOID ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength);

	NTSTATUS WINAPI NtSetInformationThread(
		HANDLE ThreadHandle,
		PVOID ThreadInformationClass,
		LPCVOID ThreadInformation,
		ULONG ThreadInformationLength);

	NTSTATUS WINAPI NtSetInformationToken(
		HANDLE TokenHandle,
		TOKEN_INFORMATION_CLASS TokenInformationClass,
		PVOID TokenInformation,
		ULONG TokenInformationLength);

	NTSTATUS WINAPI NtSetIntervalProfile(
		ULONG Interval,
		PVOID Source);

	NTSTATUS WINAPI NtSetIoCompletion(
		HANDLE IoCompletionHandle,
		ULONG_PTR CompletionKey,
		ULONG_PTR CompletionValue,
		NTSTATUS Status,
		SIZE_T Information);

	NTSTATUS WINAPI NtSetLowEventPair(
		HANDLE EventPairHandle);

	NTSTATUS WINAPI NtSetLowWaitHighEventPair(
		HANDLE EventPairHandle);

	NTSTATUS WINAPI NtSetSecurityObject(
		HANDLE Handle,
		SECURITY_INFORMATION SecurityInformation,
		PSECURITY_DESCRIPTOR SecurityDescriptor);

	NTSTATUS WINAPI NtSetSystemEnvironmentValue(
		PUNICODE_STRING Name,
		PUNICODE_STRING Value);

	NTSTATUS WINAPI NtSetSystemInformation(
		PVOID SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength);

	NTSTATUS WINAPI NtSetSystemPowerState(
		POWER_ACTION SystemAction,
		SYSTEM_POWER_STATE MinSystemState,
		ULONG Flags);

	NTSTATUS WINAPI NtSetSystemTime(
		const LARGE_INTEGER* NewTime,
		LARGE_INTEGER* OldTime);

	NTSTATUS WINAPI NtSetTimer(
		HANDLE TimerHandle,
		const LARGE_INTEGER* DueTime,
		PVOID TimerApcRoutine,
		PVOID TimerContext,
		BOOLEAN Resume,
		ULONG Period,
		BOOLEAN* PreviousState);

	NTSTATUS WINAPI NtSetTimerResolution(
		ULONG RequestedResolution,
		BOOLEAN Set,
		PULONG ActualResolution);

	NTSTATUS WINAPI NtSetValueKey(
		HANDLE KeyHandle,
		const UNICODE_STRING* ValueName,
		ULONG TitleIndex,
		ULONG Type,
		const void* Data,
		ULONG DataSize);

	NTSTATUS WINAPI NtSetVolumeInformationFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG BufferLength,
		PVOID VolumeInformationClass);

	NTSTATUS WINAPI NtShutdownSystem(
		PVOID Action);

	NTSTATUS WINAPI NtSignalAndWaitForSingleObject(
		HANDLE HandleToSignal,
		HANDLE HandleToWait,
		BOOLEAN Alertable,
		const LARGE_INTEGER* Time);

	NTSTATUS WINAPI NtStartProfile(
		HANDLE ProfileHandle);

	NTSTATUS WINAPI NtStopProfile(
		HANDLE ProfileHandle);

	NTSTATUS WINAPI NtSuspendThread(
		HANDLE ThreadHandle,
		PULONG PreviousSuspendCount);

	NTSTATUS WINAPI NtSystemDebugControl(
		PVOID ControlCode,
		PVOID InputBuffer,
		ULONG InputBufferLength,
		PVOID OutputBuffer,
		ULONG OutputBufferLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtTerminateProcess(
		HANDLE ProcessHandle,
		LONG ExitStatus);

	NTSTATUS WINAPI NtTerminateThread(
		HANDLE ThreadHandle,
		LONG ExitStatus);

	NTSTATUS WINAPI NtTestAlert();

	NTSTATUS WINAPI NtUnloadDriver(
		const UNICODE_STRING* DriverServiceName);

	NTSTATUS WINAPI NtUnloadKey(
		POBJECT_ATTRIBUTES KeyObjectAttributes);

	NTSTATUS WINAPI NtUnlockFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PLARGE_INTEGER LockOffset,
		PLARGE_INTEGER LockLength,
		PULONG Key);

	NTSTATUS WINAPI NtUnlockVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		SIZE_T* LockSize,
		ULONG LockType);

	NTSTATUS WINAPI NtUnmapViewOfSection(
		HANDLE ProcessHandle,
		PVOID BaseAddress);

	NTSTATUS WINAPI NtWaitForMultipleObjects(
		ULONG HandleCount,
		const HANDLE* Handles,
		BOOLEAN WaitType,
		BOOLEAN Alertable,
		const LARGE_INTEGER* Time);

	NTSTATUS WINAPI NtWaitForSingleObject(
		HANDLE Handle,
		BOOLEAN Alertable,
		const LARGE_INTEGER* Time);

	NTSTATUS WINAPI NtWaitHighEventPair(
		HANDLE EventPairHandle);

	NTSTATUS WINAPI NtWaitLowEventPair(
		HANDLE EventPairHandle);

	NTSTATUS WINAPI NtWriteFile(
		HANDLE FileHandle,
		HANDLE Event,
		PVOID ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		const void* Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key);

	NTSTATUS WINAPI NtWriteFileGather(
		HANDLE FileHandle,
		HANDLE Event,
		PVOID ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		FILE_SEGMENT_ELEMENT* Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key);

	NTSTATUS WINAPI NtWriteRequestData(
		HANDLE PortHandle,
		PVOID Message,
		ULONG Index,
		PVOID Buffer,
		ULONG BufferLength,
		PULONG ReturnLength);

	NTSTATUS WINAPI NtWriteVirtualMemory(
		HANDLE ProcessHandle,
		void* BaseAddress,
		const void* Buffer,
		SIZE_T BufferLength,
		SIZE_T* ReturnLength);

	NTSTATUS WINAPI NtYieldExecution();

	LPVOID WINAPI RtlAllocateHeap(
		PVOID heap,
		ULONG flags,
		ULONG size);

	LPVOID WINAPI RtlReAllocateHeap(
		PVOID heap,
		ULONG flags,
		PVOID ptr,
		ULONG size);

	BOOL WINAPI RtlFreeHeap(
		PVOID heap,
		ULONG flags,
		PVOID ptr);

	VOID WINAPI RtlInitUnicodeString(
		PUNICODE_STRING target, 
		PCWSTR source);

	VOID WINAPI RtlInitAnsiString(
		PANSI_STRING target,
		PCSTR source);

	NTSTATUS WINAPI RtlAnsiStringToUnicodeString(
		PUNICODE_STRING dst,
		PANSI_STRING src,
		BOOLEAN doalloc);

	VOID WINAPI RtlFreeUnicodeString(
		PUNICODE_STRING str);

	VOID WINAPI RtlFreeAnsiString(
		PANSI_STRING str);

	LONG WINAPI RtlCompareUnicodeString(
		const UNICODE_STRING *s1, 
		const UNICODE_STRING *s2,
		BOOLEAN CaseInsensitive);

	errno_t CDECL wcsncpy_s(
		wchar_t *strDest,
		size_t numberOfElements,
		const wchar_t *strSource,
		size_t count);

	errno_t CDECL wcscat_s(
		wchar_t *strDestination,
		size_t numberOfElements,
		const wchar_t *strSource);

	size_t CDECL strlen(
		const char *str);

	size_t CDECL wcslen(
		const wchar_t *str);

	int CDECL strcmp(
		const char *string1,
		const char *string2);

	int CDECL wcscmp(
		const wchar_t *string1,
		const wchar_t *string2);

	int CDECL wcscmpi(
		const wchar_t *string1,
		const wchar_t *string2);

	wchar_t towlower(
		wchar_t c);


}

namespace Win32Api
{
	HANDLE	WINAPI GetCurrentProcess();

	HANDLE	WINAPI GetCurrentThread();

	DWORD	WINAPI GetCurrentProcessId();

	DWORD	WINAPI GetCurrentThreadId();

	HANDLE	WINAPI OpenProcess(
		DWORD dwDesiredAccess, 
		BOOL bInheritHandle, 
		DWORD dwThreadId);

	HANDLE	WINAPI OpenThread(
		DWORD dwDesiredAccess, 
		BOOL bInheritHandle, 
		DWORD dwThreadId);

	BOOL	WINAPI GetThreadContext(
		HANDLE hThread, 
		LPCONTEXT lpContext);

	BOOL	WINAPI SetThreadContext(
		HANDLE hThread, 
		LPCONTEXT lpContext);

	BOOL	WINAPI TerminateProcess(
		HANDLE hThread, 
		UINT uExitCode);

	VOID	WINAPI ExitProcess(
		UINT uExitCode);

	BOOL	WINAPI Thread32First(
		HANDLE hSnapShot, 
		LPTHREADENTRY32 lpte);

	BOOL	WINAPI Thread32Next(
		HANDLE hSnapShot, 
		LPTHREADENTRY32 lpte);
	
	BOOL	WINAPI Process32FirstA(
		HANDLE hSnapshot, 
		LPPROCESSENTRY32 lppe);

	BOOL	WINAPI Process32NextA(
		HANDLE hSnapshot, 
		LPPROCESSENTRY32 lppe);

	BOOL	WINAPI Process32FirstW(
		HANDLE hSnapshot, 
		LPPROCESSENTRY32W lppe);

	BOOL	WINAPI Process32NextW(
		HANDLE hSnapshot, 
		LPPROCESSENTRY32W lppe);

	BOOL	WINAPI Module32FirstW(
		HANDLE hSnapshot, 
		LPMODULEENTRY32W lpme);

	BOOL	WINAPI Module32FirstA(
		HANDLE hSnapshot, 
		LPMODULEENTRY32 lpme);

	BOOL	WINAPI Module32NextA(
		HANDLE hSnapshot, 
		LPMODULEENTRY32 lpme);

	BOOL	WINAPI Module32NextW(
		HANDLE hSnapshot, 
		LPMODULEENTRY32W lpme);

	BOOL	WINAPI Toolhelp32ReadProcessMemory(
		DWORD th32ProcessID, 
		LPCVOID lpBaseAddress, 
		LPVOID lpBuffer, 
		SIZE_T cbRead, 
		SIZE_T* lpNumberOfBytesRead);

	BOOL	WINAPI ReadProcessMemory(
		HANDLE hProcess, 
		LPCVOID lpBaseAddress, 
		LPVOID lpBuffer, 
		SIZE_T nSize, 
		SIZE_T * lpNumberOfBytesRead);

	BOOL	WINAPI WriteProcessMemory(
		HANDLE hProcess, 
		LPVOID lpBaseAddress, 
		LPCVOID lpBuffer, 
		SIZE_T nSize, 
		SIZE_T* lpNumberOfBytesWritten);

	LPVOID	WINAPI VirtualAllocEx(
		HANDLE hProcess, 
		LPVOID lpAddress, 
		SIZE_T dwSize, 
		DWORD flAllocationType, 
		DWORD flProtect);

	LPVOID	WINAPI VirtualAlloc(
		LPVOID lpAddress, 
		SIZE_T dwSize, 
		DWORD flAllocationType, 
		DWORD flProtect);

	SIZE_T	WINAPI VirtualQuery(
		LPVOID lpAddress, 
		PMEMORY_BASIC_INFORMATION lpBuffer , 
		SIZE_T dwLength);

	SIZE_T	WINAPI VirtualQueryEx(
		HANDLE hProcess, 
		LPCVOID lpAddress, 
		PMEMORY_BASIC_INFORMATION lpBuffer, 
		SIZE_T dwLength);
	
	BOOL	WINAPI VirtualFree(
		LPVOID lpAddress, 
		SIZE_T dwSize, 
		DWORD dwFreeType);
	
	BOOL	WINAPI VirtualFreeEx(
		HANDLE hProcess, 
		LPVOID lpAddress, 
		SIZE_T dwSize, 
		DWORD dwFreeType);
	
	BOOL	WINAPI VirtualProtect(
		LPVOID lpAddress, 
		SIZE_T dwSize, 
		DWORD flNewProtect , 
		LPDWORD lpflOldProtect);
	
	BOOL	WINAPI VirtualProtectEx(
		HANDLE hProcess, 
		LPVOID lpAddress, 
		SIZE_T dwSize, 
		DWORD flNewProtect, 
		LPDWORD lpflOldProtect);

	HANDLE	WINAPI GetProcessHeap();
	
	LPVOID	WINAPI HeapAlloc(
		HANDLE hHeap, 
		DWORD dwFlags, 
		SIZE_T dwSize);
	
	LPVOID	WINAPI HeapReAlloc(
		HANDLE hHeap, 
		DWORD dwFlags, 
		LPVOID lpMem, 
		SIZE_T dwSize);
	
	BOOL	WINAPI HeapFree(
		HANDLE hHeap, 
		DWORD dwFlags, 
		LPVOID lpMem);

	LPVOID	WINAPI MapViewOfFile(
		HANDLE hFileMappingObject, 
		DWORD dwDesiredAccess, 
		DWORD dwFileOffsetHigh, 
		DWORD dwFileOffsetLow, 
		SIZE_T dwNumberOfBytesToMap);
	
	LPVOID	WINAPI MapViewOfFileEx(
		HANDLE hFileMappingObject, 
		DWORD dwDesiredAccess, 
		DWORD dwFileOffsetHigh, 
		DWORD dwFileOffsetLow, 
		SIZE_T dwNumberOfBytesToMap, 
		LPVOID lpBaseAddress);
	
	BOOL	WINAPI UnmapViewOfFile(
		LPVOID lpBaseAddress);

	DWORD	WINAPI GetVersion();

	HMODULE	WINAPI LoadLibraryA(
		LPCSTR lpModuleName);
	
	HMODULE	WINAPI LoadLibraryW(
		LPCWSTR lpModuleName);
	
	HMODULE WINAPI GetModuleHandleA(
		LPCSTR lpModuleName);
	
	HMODULE WINAPI GetModuleHandleW(
		LPCWSTR lpModuleName);
	
	DWORD	WINAPI GetModuleSize(
		HMODULE hModule);
	
	LPCWSTR	WINAPI GetModuleFileNameW(
		HMODULE handle);

	LPCWSTR WINAPI GetModuleFullFileNameW(
		HMODULE handle);
	
	FARPROC WINAPI GetProcAddress(
		HMODULE hModule, 
		LPCSTR lpProcName);

	BOOL	WINAPI IsBadReadPtr(
		CONST VOID	* lp, 
		UINT ucb);
	
	BOOL	WINAPI IsBadWritePtr(
		LPVOID lp, 
		UINT ucb);
	
	BOOL WINAPI CloseHandle(
		HANDLE Object);

	void WINAPI SetLastError(
		DWORD error);

	HANDLE WINAPI CreateFileA(
		LPCSTR lpFileName,
		DWORD dwDesiredAccess,
		DWORD dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD dwCreationDisposition,
		DWORD dwFlagsAndAttributes,
		HANDLE hTemplateFile);

		HANDLE WINAPI CreateFileW(
		LPCWSTR lpFileName,
		DWORD dwDesiredAccess,
		DWORD dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD dwCreationDisposition,
		DWORD dwFlagsAndAttributes,
		HANDLE hTemplateFile);


		HANDLE WINAPI CreateFileMappingW(
			HANDLE hFile, 
			LPSECURITY_ATTRIBUTES sa,
			DWORD protect, 
			DWORD size_high,
			DWORD size_low, 
			LPCWSTR name);

		HANDLE WINAPI CreateFileMappingA(
			HANDLE hFile,
			SECURITY_ATTRIBUTES *sa,
			DWORD protect,
			DWORD size_high,
			DWORD size_low,
			LPCSTR name );

		int WINAPI WideCharToMultiByte(
			UINT CodePage, 
			DWORD dwFlags, 
			LPCWSTR lpWideCharStr, 
			int cchWideChar,
			LPSTR lpMultiByteStr, 
			int cbMultiByte,
			LPCSTR lpDefaultChar,
			LPBOOL lpUsedDefaultChar);
}

#endif