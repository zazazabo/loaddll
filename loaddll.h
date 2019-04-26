/***************************************************************************************
* AUTHOR : zzc
* DATE   : 2019-4-22
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

#include <ntddk.h>
#include <devioctl.h>
#include "common.h"

//
// TODO: Add your include here
//

#include <ntimage.h>
#include <ntstrsafe.h>


//////////////////////////////////////////////////////////////////////////

//
// TODO: Add your struct,enum(private) here
//

DWORD                           g_OsVersion;                                            //系统版本
//操作系统版本
#define WINXP                   51
#define WIN2003                 52
#define WIN7                    61
#define WIN8                    62
#define WIN81                   63
#define WIN10                   100


//////////////////////////////////////////////////////////////////////////
//***************************************************************************************
//* NAME:     DriverEntry
//*
//* DESCRIPTION:  Registers dispatch routines.
//*
//* PARAMETERS:   pDriverObj            IN
//*           Address of the DRIVER_OBJECT created by NT for this driver.
//*         pRegistryString         IN
//*           UNICODE_STRING which represents this drivers KEY in the Registry.
//*
//* IRQL:     IRQL_PASSIVE_LEVEL.
//*
//* RETURNS:    NTSTATUS
//***************************************************************************************
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);

//***************************************************************************************
//* NAME:     DriverUnload
//*
//* DESCRIPTION:  This routine is our dynamic unload entry point.
//*
//* PARAMETERS:   pDriverObj            IN    Address of our DRIVER_OBJECT.
//*
//* IRQL:     IRQL_PASSIVE_LEVEL.
//*
//* RETURNS:    None
//***************************************************************************************
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);

//***************************************************************************************
//* NAME:     DispatchCreate, DispatchClose
//*
//* DESCRIPTION:  This two methods are the dispatch entry point for IRP_MJ_CREATE and IRP_MJ_CLOSE
//*         routines.  This sample simply completes the requests with success.
//*
//* PARAMETERS:   pDevObj             IN    Address of our DRIVER_OBJECT.
//*         pIrp              IN    Address of the IRP.
//*
//* IRQL:     IRQL_PASSIVE_LEVEL.
//*
//* RETURNS:    STATUS_SUCCESS
//***************************************************************************************
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);

//***************************************************************************************
//* NAME:     DispatchDeviceControl
//*
//* DESCRIPTION:  This is the dispatch entry point for IRP_MJ_DEVICE_CONTROL.
//*
//* PARAMETERS:   pDevObj             IN    Address of our DRIVER_OBJECT.
//*         pIrp              IN    Address of the IRP.
//*
//* IRQL:     IRQL_PASSIVE_LEVEL.
//*
//* RETURNS:    NTSTATUS
//*
//* NOTES:      IRP_MJ_DEVICE_CONTROL
//*         Parameters:
//*         Parameters.DeviceIoControl.OutputBufferLength Length of OutBuffer
//*         in bytes (length of buffer from GUI)
//*         Parameters.DeviceIoControl.InputBufferLength  Length of InBuffer
//*         in bytes (length of buffer from DRIVER)
//*         Parameters.DeviceIoControl.ControlCode      I/O control code
//***************************************************************************************
NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);

// common dispatch
//***************************************************
//* #define IRP_MJ_CREATE                   0x00
//* #define IRP_MJ_CREATE_NAMED_PIPE        0x01
//* #define IRP_MJ_CLOSE                    0x02
//* #define IRP_MJ_READ                     0x03
//* #define IRP_MJ_WRITE                    0x04
//* #define IRP_MJ_QUERY_INFORMATION        0x05
//* #define IRP_MJ_SET_INFORMATION          0x06
//* #define IRP_MJ_QUERY_EA                 0x07
//* #define IRP_MJ_SET_EA                   0x08
//* #define IRP_MJ_FLUSH_BUFFERS            0x09
//* #define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
//* #define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
//* #define IRP_MJ_DIRECTORY_CONTROL        0x0c
//* #define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
//* #define IRP_MJ_DEVICE_CONTROL           0x0e
//* #define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
//* #define IRP_MJ_SHUTDOWN                 0x10
//* #define IRP_MJ_LOCK_CONTROL             0x11
//* #define IRP_MJ_CLEANUP                  0x12
//* #define IRP_MJ_CREATE_MAILSLOT          0x13
//* #define IRP_MJ_QUERY_SECURITY           0x14
//* #define IRP_MJ_SET_SECURITY             0x15
//* #define IRP_MJ_POWER                    0x16
//* #define IRP_MJ_SYSTEM_CONTROL           0x17
//* #define IRP_MJ_DEVICE_CHANGE            0x18
//* #define IRP_MJ_QUERY_QUOTA              0x19
//* #define IRP_MJ_SET_QUOTA                0x1a
//* #define IRP_MJ_PNP                      0x1b
//* #define IRP_MJ_PNP_POWER                IRP_MJ_PNP      // Obsolete....
//* #define IRP_MJ_MAXIMUM_FUNCTION         0x1b -->
//***************************************************************************************
NTSTATUS DispatchCommon(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);

//////////////////////////////////////////////////////////////////////////

#ifdef ALLOC_PRAGMA
// Allow the DriverEntry routine to be discarded once initialization is completed
#pragma alloc_text(INIT, DriverEntry)
//
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
  UCHAR  CURDIR[0xc] ;
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
  UCHAR  CURDIR[0x14] ;
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

typedef NTSTATUS(__stdcall *TYPE_NtCreateThreadEx)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress,
    PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

TYPE_NtCreateThreadEx NtCreateThreadEx = NULL;
TYPE_NtCreateThreadEx ZwCreateThreadEx = NULL;
PVOID       m_pCreateThread;


typedef NTSTATUS(__stdcall *TYPE_ZwWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength OPTIONAL);

TYPE_ZwWriteVirtualMemory NtWriteVirtualMemory = NULL;
TYPE_ZwWriteVirtualMemory ZwWriteVirtualMemory = NULL;

NTSTATUS NTAPI ZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTKERNELAPI NTSTATUS ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState,
    ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle);

typedef  NTSTATUS(__stdcall *TYPE_ZwQueryInformationProcess)(
  HANDLE           ProcessHandle,
  PROCESSINFOCLASS ProcessInformationClass,
  PVOID            ProcessInformation,
  ULONG            ProcessInformationLength,
  PULONG           ReturnLength
);
TYPE_ZwQueryInformationProcess ZwQueryInformationProcess = NULL;

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

void InjectDll(PEPROCESS ProcessObj, int ibit);


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

struct PARAMX
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
};


#define RPL_MASK                    3
#define KGDT_R3_TEB                 56
#define KGDT_R3_CODE                24
#define KGDT_R3_DATA                32
#define IMAGEFILENAME_OFFSET        0x16c
#define ACTIVEPROCESSLINKS_OFFSET   0x0b8
#define TCB_TEB_OFFSET              0x088
#define OBJECT_TABLE_OFFSET         0x0f4


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
typedef struct _KAPC_STATE
{
  LIST_ENTRY ApcListHead[MaximumMode];
  struct _KPROCESS *Process;
  BOOLEAN KernelApcInProgress;
  BOOLEAN KernelApcPending;
  BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;


int nnnnn = 0;
PVOID     fnZwContinue = NULL;
ULONG    g_mode = 0;
WCHAR   wsexepath[2048 * (sizeof(WCHAR) + 1)] = {0};
WCHAR   wscommandline[ 2048 * (sizeof(WCHAR) + 1) ] = { 0 };


typedef PPEB(__stdcall *P_PsGetProcessWow64Process)(PEPROCESS);
P_PsGetProcessWow64Process PsGetProcessWow64Process = NULL;
typedef PPEB(__stdcall *P_PsGetProcessPeb)(PEPROCESS);
P_PsGetProcessPeb     PsGetProcessPeb = NULL;

NTKERNELAPI VOID KeStackAttachProcess(PEPROCESS PROCESS, PRKAPC_STATE ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(PRKAPC_STATE ApcState);
NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId, OUT PEPROCESS *Process);

DWORD_PTR GetSystemRoutineAddress(WCHAR* szFunCtionAName);
PVOID GetProcAddress(IN PVOID pBase, IN PCCHAR name_ord);
VOID ImageNotify(PUNICODE_STRING  FullImageName, HANDLE  ProcessId, PIMAGE_INFO  ImageInfo);
BOOLEAN GetOsVer(void);

void DealCommandLine32(PPEB pPEB);
BOOLEAN GetProcessName(PPEB pPEB, WCHAR name[]);

NTSTATUS NTAPI  NewNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
ULONG_PTR GetSSDTFuncCurAddr(LONG id);

NTSTATUS BBSearchPattern(IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
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



#ifdef __cplusplus
}
#endif
//////////////////////////////////////////////////////////////////////////

#endif  //CXX_LOADDLL_H
/* EOF */
