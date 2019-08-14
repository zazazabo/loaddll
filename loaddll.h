/***************************************************************************************
* AUTHOR : zzc
* DATE   : 2019-6-10
* MODULE : loaddll.H
*
* IOCTRL Sample Driver
*
* Description:
*   Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 zzc.
****************************************************************************************/

#ifndef CXX_LOADDLL_H
#define CXX_LOADDLL_H

#ifdef __cplusplus
extern "C" {
#endif
#include <ntifs.h>
#include <ntddk.h>
#include <devioctl.h>
#include "common.h"
#include "memload.h"
#include "lde.h"
#include "dll32.h"
#include "dll64.h"
#include <ntimage.h>
#include "disasm.h"

//
// TODO: Add your include here
//


//////////////////////////////////////////////////////////////////////////

//
// TODO: Add your struct,enum(private) here
//
#define kprintf     DbgPrint
#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p)   ExFreePool(_p)


//////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);
VOID	 DriverUnload(IN PDRIVER_OBJECT pDriverObj);
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS DispatchCommon(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);

//////////////////////////////////////////////////////////////////////////

#ifdef ALLOC_PRAGMA
// Allow the DriverEntry routine to be discarded once initialization is completed
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, DispatchCreate)
#pragma alloc_text(PAGE, DispatchClose)
#pragma alloc_text(PAGE, DispatchDeviceControl)
#pragma alloc_text(PAGE, DispatchCommon)
#endif // ALLOC_PRAGMA

//////////////////////////////////////////////////////////////////////////

//
// TODO: Add your module declarations here
//


typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
  ULONG MaximumLength;
  ULONG Length;
  ULONG Flags;
  ULONG DebugFlags;
  ULONG ConsoleHandle;
  ULONG ConsoleFlags;
  ULONG StandardInput;
  ULONG StandardOutput;
  ULONG StandardError;
  UCHAR  CURDIR[0xc];
  UNICODE_STRING32 DllPath;
  UNICODE_STRING32 ImagePathName;     //进程完整路径
  UNICODE_STRING32 CommandLine;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;


typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
  ULONG MaximumLength;
  ULONG Length;
  ULONG Flags;
  ULONG DebugFlags;
  ULONG64 ConsoleHandle;
  ULONG64 ConsoleFlags;
  ULONG64 StandardInput;
  ULONG64 StandardOutput;
  ULONG64 StandardError;
  UCHAR  CURDIR[0x14];
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;     //进程完整路径
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

typedef struct _PEB32   // Size: 0x1D8
{
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR SpareBool;
  HANDLE Mutant;
  ULONG ImageBaseAddress;
  ULONG DllList;
  ULONG ProcessParameters;    //进程参数块
} PEB32, *PPEB32;

typedef struct _PEB64   // Size: 0x1D8
{
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR SpareBool[5];
  ULONG64 Mutant;
  ULONG64 ImageBaseAddress;
  ULONG64 DllList;
  ULONG64 ProcessParameters;    //进程参数块
} PEB64, *PPEB64;



#pragma pack(1)
typedef struct ServiceDescriptorEntry
{
  unsigned int *ServiceTableBase;
  unsigned int *ServiceCounterTableBase;
  unsigned int NumberOfService;
  unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
  ServiceDescriptorTableEntry_t   ntoskrnl; // ntoskrnl.exe
  ServiceDescriptorTableEntry_t   win32k;   // win32k.sys
  ServiceDescriptorTableEntry_t   NotUsed1;
  ServiceDescriptorTableEntry_t   NotUsed2;
} SYSTEM_DESCRIPTOR_TABLE, *PSYSTEM_DESCRIPTOR_TABLE;


#ifdef _AMD64_
PServiceDescriptorTableEntry_t  KeServiceDescriptorTable;
#else
__declspec(dllimport) ServiceDescriptorTableEntry_t    KeServiceDescriptorTable;
#endif


#define   SERVICE_ID64(_function)     (*(PULONG)((PUCHAR)_function + 4))  //64位进程
#define   SERVICE_ID32(_function)     (*(PULONG)((PUCHAR)_function + 1))  //32位进程


#define SERVICE_FUNCTION(_function)   \
  ((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + 4*SERVICE_ID32(_function))

ULONGLONG GetKeServiceDescriptorTable64();

typedef struct _PARAMX
{
  ULONG64 lpFileData;
  ULONG64 DataLength;
  ULONG64 LdrGetProcedureAddress;
  ULONG64 dwNtAllocateVirtualMemory;
  ULONG64 dwLdrLoadDll;
  ULONG64 RtlInitAnsiString;
  ULONG64 RtlAnsiStringToUnicodeString;
  ULONG64 RtlFreeUnicodeString;

  UCHAR oldcode[20];
  //unsigned char code1[14] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0xC3};
  UCHAR pFunction[100];
} PARAMX, *PPARAMX;


#pragma pack()
typedef struct _INITIAL_TEB
{
  struct
  {
    PVOID OldStackBase;
    PVOID OldStackLimit;
  } OldInitialTeb;
  PVOID StackBase;
  PVOID StackLimit;
  PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef NTSTATUS(*TYPE_NtCreateThread)(PHANDLE  ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES  ObjectAttributes,
                                       HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN  CreateSuspended);
TYPE_NtCreateThread ZwCreateThread;
TYPE_NtCreateThread NtCreateThread;



typedef NTSTATUS(__stdcall *TYPE_NtCreateThreadEx)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress,
    PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

TYPE_NtCreateThreadEx NtCreateThreadEx = NULL;
TYPE_NtCreateThreadEx ZwCreateThreadEx = NULL;
PVOID       m_pCreateThread;


typedef NTSTATUS(__stdcall *TYPE_ZwWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength OPTIONAL);

TYPE_ZwWriteVirtualMemory NtWriteVirtualMemory = NULL;
TYPE_ZwWriteVirtualMemory ZwWriteVirtualMemory = NULL;





#define   HOOKADDR     "ZwContinue"   //ZwWriteVirtualMemory  ZwTestAlert  ZwCreateFile  ZwContinue
PVOID     fnHookfunc64 = NULL;
PVOID     fnHookfunc32 = NULL;
ULONG    g_mode = 0;



NTSTATUS NTAPI NewNtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer,
                                       IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL);
NTSTATUS NTAPI NewNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle,
                                   PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit,
                                   SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

typedef NTSTATUS(__stdcall *TYPE_ZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);
TYPE_ZwProtectVirtualMemory NtProtectVirtualMemory = NULL;
TYPE_ZwProtectVirtualMemory ZwProtectVirtualMemory = NULL;

NTSTATUS MyZwCreateThread(HANDLE ProcessHandle, PVOID  ThreadStartAddress, PVOID   ThreadParameter, PSIZE_T ThreadStackSize,
                          PVOID *ThreadStackAddress, HANDLE *ThreadHandle, PEPROCESS processObj);
NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect,
    IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);

BOOLEAN IsX64Module(IN PVOID pBase);
PVOID GetProcAddress(IN PVOID pBase, IN PCCHAR name_ord);

VOID ImageNotify(PUNICODE_STRING       FullImageName, HANDLE ProcessId, PIMAGE_INFO  ImageInfo);

typedef PPEB(__stdcall *P_PsGetProcessWow64Process)(PEPROCESS);
P_PsGetProcessWow64Process PsGetProcessWow64Process = NULL;
typedef PPEB(__stdcall *P_PsGetProcessPeb)(PEPROCESS);
P_PsGetProcessPeb     PsGetProcessPeb = NULL;

DWORD_PTR GetSystemRoutineAddress(WCHAR *szFunCtionAName);
BOOLEAN GetProcessNameByObj(PEPROCESS ProcessObj, WCHAR name[]);
void  InitGlobeFunc(PIMAGE_INFO     ImageInfo);
void InjectDll(PEPROCESS ProcessObj, int ibit);
NTSTATUS BBSearchPattern(IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
ULONG_PTR GetSSDTFuncCurAddr(LONG id);
ULONGLONG GetKeServiceDescriptorTable64();
ULONG MzGetFileSize(HANDLE hfile);
NTSTATUS MzReadFile(LPWCH pFile,PVOID* ImageBaseAddress,PULONG ImageSize);
void ZwDeleteFileFolder(WCHAR *wsFileName);
VOID Reinitialize( PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count );

PVOID      g_pDll64=NULL;
ULONG      g_iDll64=0;
PVOID      g_pDll32=NULL;
ULONG      g_iDll32=0;



ULONG GetPatchSize(PUCHAR Address,int asmlen);
typedef int (*LDE_DISASM)(void *p, int dw);
LDE_DISASM LDE;
void LDE_init();


typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY64 InLoadOrderLinks;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG   Flags;
	USHORT  LoadCount;
	USHORT  __Undefined5;
	ULONG64 __Undefined6;
	ULONG   CheckSum;
	ULONG   __padding1;
	ULONG   TimeDateStamp;
	ULONG   __padding2;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

WCHAR  g_exename[216] = {0};
#ifdef __cplusplus
}
#endif
//////////////////////////////////////////////////////////////////////////

#endif  //CXX_LOADDLL_H
/* EOF */
