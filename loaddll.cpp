/***************************************************************************************
* AUTHOR : zzc
* DATE   : 2019-4-22
* MODULE : loaddll.C
*
* Command:
*   Source of IOCTRL Sample Driver
*
* Description:
*       Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 zzc.
****************************************************************************************/

//#######################################################################################
//# I N C L U D E S
//#######################################################################################

#ifndef CXX_LOADDLL_H
#include "loaddll.h"
#include "memload.h"
#include "dll32.h"
#include "dll64.h"
//#include <ntifs.h>
#endif

//#include "struct.h"

//////////////////////////////////////////////////////////////////////////

//#######################################################################################
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@@@@@@@@              D R I V E R   E N T R Y   P O I N T                      @@@@@@@@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//#######################################################################################
NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
  NTSTATUS        status = STATUS_SUCCESS;
  UNICODE_STRING  ustrLinkName;
  UNICODE_STRING  ustrDevName;
  PDEVICE_OBJECT  pDevObj;
  UCHAR PreviousModePattern[] = "\x00\x00\xC3";
  PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
  PVOID pFoundPattern = NULL;
  PEPROCESS ProcessObj = NULL;
  int i = 0;
  dprintf("EasySys Sample Driver\r\n"
          "Compiled %s %s\r\nIn DriverEntry : %wZ\r\n",
          __DATE__, __TIME__, pRegistryString);
  // Register dispatch routines
  pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
  pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
  // Dispatch routine for communications
  pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
  // Unload routine
  pDriverObj->DriverUnload = DriverUnload;
  // Initialize the device name.
  RtlInitUnicodeString(&ustrDevName, NT_DEVICE_NAME);
  // Create the device object and device extension
  status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);

  if(!NT_SUCCESS(status))
    {
      dprintf("Error, IoCreateDevice = 0x%x\r\n", status);
      return status;
    }

  //// Get a pointer to our device extension
  //deviceExtension = (PDEVICE_EXTENSION) deviceObject->DeviceExtension;

  //// Save a pointer to the device object
  //deviceExtension->DeviceObject = deviceObject;

  if(IoIsWdmVersionAvailable(1, 0x10))
    {
      RtlInitUnicodeString(&ustrLinkName, SYMBOLIC_LINK_GLOBAL_NAME);
    }
  else
    {
      RtlInitUnicodeString(&ustrLinkName, SYMBOLIC_LINK_NAME);
    }

  // Create a symbolic link to allow USER applications to access it.
  status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);

  if(!NT_SUCCESS(status))
    {
      dprintf("Error, IoCreateSymbolicLink = 0x%x\r\n", status);
      IoDeleteDevice(pDevObj);
      return status;
    }

  //  TODO: Add initialization code here.
#ifdef _AMD64_
  KeServiceDescriptorTable = (PServiceDescriptorTableEntry_t)GetKeServiceDescriptorTable64();
#else
#endif
  dprintf("KeServiceDescriptorTable:%p", KeServiceDescriptorTable);
  PsGetProcessWow64Process = (P_PsGetProcessWow64Process) GetSystemRoutineAddress(L"PsGetProcessWow64Process");
  PsGetProcessPeb = (P_PsGetProcessPeb) GetSystemRoutineAddress(L"PsGetProcessPeb");
  ZwQueryInformationProcess = (TYPE_ZwQueryInformationProcess)GetSystemRoutineAddress(L"ZwQueryInformationProcess");

  if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
    {
      //PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(DWORD *)((PUCHAR)pFoundPattern - 2);
      g_mode = *(PULONG)((PUCHAR)pFoundPattern - 2);
      DbgPrint("[DriverEntry] g_mode:%x fnExGetPreviousMode:%p\n", g_mode, fnExGetPreviousMode);
    }

  dprintf("PsGetProcessWow64Process:%p  PsGetProcessPeb:%p ", PsGetProcessWow64Process, PsGetProcessPeb);
  status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);

  if(!NT_SUCCESS(status))
    {
      DbgPrint("[DriverEntry] PsSetLoadImageNotifyRoutine Failed! status:%d\n", status);
    }

  //// Tell the I/O Manger to do BUFFERED IO
  //deviceObject->Flags |= DO_BUFFERED_IO;
  //// Save the DeviveObject
  //deviceExtension->DeviceObject = deviceObject;
  dprintf("DriverEntry Success\r\n");
  return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
  UNICODE_STRING strLink;
  // Unloading - no resources to free so just return.
  dprintf("Unloading...\r\n");;
  //
  // TODO: Add uninstall code here.
  //
  PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);
  // Delete the symbolic link
  RtlInitUnicodeString(&strLink, SYMBOLIC_LINK_NAME);
  IoDeleteSymbolicLink(&strLink);
  // Delete the DeviceObject
  IoDeleteDevice(pDriverObj->DeviceObject);
  dprintf("Unloaded Success\r\n");
  return;
}

NTSTATUS
DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  pIrp->IoStatus.Status = STATUS_SUCCESS;
  pIrp->IoStatus.Information = 0;
  IoCompleteRequest(pIrp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}


NTSTATUS
DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  pIrp->IoStatus.Status = STATUS_SUCCESS;
  pIrp->IoStatus.Information = 0;
  IoCompleteRequest(pIrp, IO_NO_INCREMENT);
  // Return success
  return STATUS_SUCCESS;
}

NTSTATUS
DispatchCommon(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  pIrp->IoStatus.Status = STATUS_SUCCESS;
  pIrp->IoStatus.Information = 0L;
  IoCompleteRequest(pIrp, 0);
  // Return success
  return STATUS_SUCCESS;
}

NTSTATUS
DispatchDeviceControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  NTSTATUS status               = STATUS_INVALID_DEVICE_REQUEST;   // STATUS_UNSUCCESSFUL
  PIO_STACK_LOCATION pIrpStack  = IoGetCurrentIrpStackLocation(pIrp);
  ULONG uIoControlCode          = 0;
  PVOID pIoBuffer               = NULL;
  ULONG uInSize                 = 0;
  ULONG uOutSize                = 0;
  // Get the IoCtrl Code
  uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
  pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
  uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
  uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

  switch(uIoControlCode)
    {
      case IOCTL_HELLO_WORLD:
        {
          dprintf("MY_CTL_CODE(0)=%d\r\n,MY_CTL_CODE");
          // Return success
          status = STATUS_SUCCESS;
        }
        break;

      case IOCTRL_REC_FROM_APP:
        {
          // Receive data form Application
          //dprintf("IOCTRL_REC_FROM_APP\r\n");

          // Do we have any data?
          if(uInSize > 0)
            {
              dprintf("Get Data from App: %ws\r\n", pIoBuffer);
            }

          // Return success
          status = STATUS_SUCCESS;
        }
        break;

      case IOCTRL_SEND_TO_APP:
        {
          // Send data to Application
          //dprintf("IOCTRL_SEND_TO_APP\r\n");

          // If we have enough room copy the data upto the App - note copy the terminating character as well...
          if(uOutSize >= strlen(DATA_TO_APP) + 1)
            {
              RtlCopyMemory(pIoBuffer,
                            DATA_TO_APP,
                            strlen(DATA_TO_APP) + 1);
              // Update the length for the App
              pIrp->IoStatus.Information = strlen(DATA_TO_APP) + 1;
              dprintf("Send Data to App: %s\r\n", pIoBuffer);
              // Return success
              status = STATUS_SUCCESS;
            }
        }
        break;

      //
      // TODO: Add execute code here.
      //

      default:
        {
          // Invalid code sent
          dprintf("Unknown IOCTL: 0x%X (%04X,%04X)\r\n",
                  uIoControlCode,
                  DEVICE_TYPE_FROM_CTL_CODE(uIoControlCode),
                  IoGetFunctionCodeFromCtlCode(uIoControlCode));
          status = STATUS_INVALID_PARAMETER;
        }
        break;
    }

  if(status == STATUS_SUCCESS)
    {
      pIrp->IoStatus.Information = uOutSize;
    }
  else
    {
      pIrp->IoStatus.Information = 0;
    }

  // Complete the I/O Request
  pIrp->IoStatus.Status = status;
  IoCompleteRequest(pIrp, IO_NO_INCREMENT);
  return status;
}


//
// TODO: Add your module definitions here.
//

DWORD_PTR GetSystemRoutineAddress(WCHAR* szFunCtionAName)
{
  UNICODE_STRING FsRtlLegalAnsiCharacterArray_String;
  RtlInitUnicodeString(&FsRtlLegalAnsiCharacterArray_String, szFunCtionAName);
  return (DWORD_PTR)MmGetSystemRoutineAddress(&FsRtlLegalAnsiCharacterArray_String);
}


BOOLEAN IsX64Module(IN PVOID pBase)
{
  PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
  PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
  PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
  PIMAGE_EXPORT_DIRECTORY pExport = NULL;
  ULONG expSize = 0;
  ULONG_PTR pAddress = 0;
  ASSERT(pBase != NULL);

  if(pBase == NULL)
    return FALSE;

  /// Not a PE file
  if(pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    return FALSE;

  pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
  pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

  // Not a PE file
  if(pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
    return FALSE;

  // 64 bit image
  if(pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
      return TRUE;
    }

  return FALSE;
}


PVOID GetProcAddress(IN PVOID pBase, IN PCCHAR name_ord)
{
  PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
  PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
  PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
  PIMAGE_EXPORT_DIRECTORY pExport = NULL;
  ULONG expSize = 0;
  ULONG_PTR pAddress = 0;
  ASSERT(pBase != NULL);

  if(pBase == NULL)
    return NULL;

  /// Not a PE file
  if(pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;

  pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
  pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

  // Not a PE file
  if(pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  // 64 bit image
  if(pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
      pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
      expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
  // 32 bit image
  else
    {
      pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
      expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

  PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
  PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
  PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

  for(ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
    {
      USHORT OrdIndex = 0xFFFF;
      PCHAR  pName = NULL;

      // Find by index
      if((ULONG_PTR)name_ord <= 0xFFFF)
        {
          OrdIndex = (USHORT)i;
        }
      // Find by name
      else if((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
        {
          pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
          //DbgPrint("api:%s\r\n",pName);
          OrdIndex = pAddressOfOrds[i];
        }
      // Weird params
      else
        return NULL;

      if(((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
          ((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
        {
          pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;
          break;
        }
    }

  return (PVOID)pAddress;
}


VOID ImageNotify(PUNICODE_STRING       FullImageName, HANDLE ProcessId, PIMAGE_INFO  ImageInfo)
{
  PVOID pDrvEntry;
  PEPROCESS ProcessObj = NULL;
  char*    pname;
  char*    pname1;
  PPEB       pPEB    = NULL;
  NTSTATUS st = STATUS_UNSUCCESSFUL;
  NTSTATUS  status;
  HANDLE  thread = NULL;
  char szFullImageName[260] = {0};
  UCHAR*  pData = NULL;
  wchar_t* pfind = NULL;
  PVOID pEntry = NULL;
  WCHAR pTempBuf[ 512 ] = { 0 };
  WCHAR *pNonPageBuf = NULL, *pTemp = pTempBuf;
  WCHAR   exename[216] = {0};
  WCHAR     pModuleName[216] = {0};
  int i = 0;

  if(FullImageName == NULL || MmIsAddressValid(FullImageName) == FALSE || FullImageName->Length > 216)
    {
      return;
    }

  RtlCopyMemory(pTempBuf, FullImageName->Buffer, FullImageName->Length);
  pfind    = wcsrchr(pTempBuf, L'\\');

  if(pfind == NULL)
    goto fun_ret;

  ++pfind;

  if(_wcsicmp(pfind, L"ntdll.dll") == 0)
    {
      dprintf("find %ws", pTempBuf);

      if(NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &ProcessObj)))
        {
          if(!m_pCreateThread || !ZwProtectVirtualMemory || !fnZwContinue || !ZwWriteVirtualMemory)
            {
              ZwWriteVirtualMemory = (TYPE_ZwWriteVirtualMemory) GetProcAddress(ImageInfo->ImageBase, "ZwWriteVirtualMemory");
              ZwCreateThreadEx = (TYPE_NtCreateThreadEx) GetProcAddress(ImageInfo->ImageBase, "ZwCreateThreadEx");        //
              ZwCreateThread = (TYPE_NtCreateThread) GetProcAddress(ImageInfo->ImageBase, "ZwCreateThread");
              fnZwContinue = GetProcAddress(ImageInfo->ImageBase, "ZwCreateFile");
              ZwProtectVirtualMemory = (TYPE_ZwProtectVirtualMemory) GetProcAddress(ImageInfo->ImageBase, "ZwProtectVirtualMemory");
              m_pCreateThread = ZwCreateThreadEx == NULL ? (PVOID)ZwCreateThread : (PVOID)ZwCreateThreadEx;
              dprintf("fnZwContinue:%p ZwProtectVirtualMemory:%p m_pCreateThread:%p", fnZwContinue, ZwProtectVirtualMemory, m_pCreateThread);

              if(m_pCreateThread && ZwProtectVirtualMemory && ZwWriteVirtualMemory)
                {
                  ULONG CreateThreadId = NULL;
                  ULONG protectvmId = NULL;
                  ULONG WriteId = NULL;

                  if(IsX64Module(ImageInfo->ImageBase) == TRUE)
                    {
                      CreateThreadId = (ULONG)SERVICE_ID64(m_pCreateThread);
                      protectvmId = (ULONG)SERVICE_ID64(ZwProtectVirtualMemory);
                      WriteId = (ULONG)SERVICE_ID64(ZwWriteVirtualMemory);
                    }
                  else
                    {
                      CreateThreadId =   SERVICE_ID32(m_pCreateThread);
                      protectvmId =   SERVICE_ID32(ZwProtectVirtualMemory);
                      WriteId = (ULONG)SERVICE_ID32(ZwWriteVirtualMemory);
                    }

                  if(CreateThreadId && protectvmId && WriteId)
                    {
                      NtProtectVirtualMemory = (TYPE_ZwProtectVirtualMemory)GetSSDTFuncCurAddr(protectvmId);
                      NtWriteVirtualMemory = (TYPE_ZwWriteVirtualMemory)GetSSDTFuncCurAddr(WriteId);

                      if(m_pCreateThread == ZwCreateThreadEx)
                        {
                          NtCreateThreadEx = (TYPE_NtCreateThreadEx)GetSSDTFuncCurAddr(CreateThreadId);
                        }
                      else
                        {
                          NtCreateThread = (TYPE_NtCreateThread)GetSSDTFuncCurAddr(CreateThreadId);
                        }

                      dprintf("WriteId:%d CreateThreadId:%d protectvmId:%d", WriteId, CreateThreadId, protectvmId);
                      dprintf("NtWriteVirtualMemory:%p NtProtectVirtualMemory:%p m_pCreateThread:%p", NtWriteVirtualMemory, NtProtectVirtualMemory, m_pCreateThread);
                    }
                }
            }

          pPEB =    PsGetProcessPeb(ProcessObj);

          if(pPEB && (ULONG64)pPEB < (ULONG64)0x7FFFFFFF)
            {
              //PPEB p2=PsGetProcessWow64Process(ProcessObj);
              if(IsX64Module(ImageInfo->ImageBase) == TRUE)
                {
                  BOOLEAN  bfind = GetProcessName(pPEB, exename);
                  dprintf("pPEB:%p exename:%ws", pPEB, exename);

                  if(bfind == TRUE && _wcsicmp(exename, L"dnf.exe") == 0)
                    {
                      dprintf("find process");
                      InjectDll(ProcessObj, 32);
                    }
                }
            }
          else if(pPEB && ((ULONG64)pPEB > (ULONG64)0x7FFFFFFF))
            {
              BOOLEAN  bfind = GetProcessName(pPEB, exename);
              dprintf("pPEB:%p exename:%ws", pPEB, exename);

              if(bfind == TRUE && _wcsicmp(exename, L"dnf64.exe") == 0)
                {
                  dprintf("find process");
                  InjectDll(ProcessObj, 64);
                }
            }

          ObfDereferenceObject(ProcessObj);
        }
    }

fun_ret:
  return;
}


BOOLEAN GetOsVer(void)
{
  ULONG    dwMajorVersion = 0;
  ULONG    dwMinorVersion = 0;
  PsGetVersion(&dwMajorVersion, &dwMinorVersion, NULL, NULL);

  if(dwMajorVersion == 5 && dwMinorVersion == 1)
    g_OsVersion = WINXP;
  else if(dwMajorVersion == 5 && dwMinorVersion == 2)
    g_OsVersion = WIN2003;
  else if(dwMajorVersion == 6 && dwMinorVersion == 1)
    g_OsVersion = WIN7;
  else if(dwMajorVersion == 6 && dwMinorVersion == 2)
    g_OsVersion = WIN8;
  else if(dwMajorVersion == 6 && dwMinorVersion == 3)
    g_OsVersion = WIN81;
  else if(dwMajorVersion == 10 && dwMinorVersion == 0)
    g_OsVersion = WIN10;
  else
    {
      g_OsVersion = 0;
      return FALSE;
    }

  return TRUE;
}

BOOLEAN GetProcessName(PPEB pPEB, WCHAR name[])
{
#ifdef _AMD64_
  PPEB64 peb64 = (PPEB64)pPEB;
  ULONG64 p1 = 0;
  ULONG64 uCommandline = 0;
  ULONG64 uImagepath = 0;
  ULONG    type = 0;
  PUNICODE_STRING   pCommandline = NULL;
  UNICODE_STRING    pImagePath = {0};
  UNICODE_STRING    tempcommand;
  WCHAR  pexe[216] = {0};

  if(pPEB == NULL)
    return FALSE;

  PRTL_USER_PROCESS_PARAMETERS64 processParam = (PRTL_USER_PROCESS_PARAMETERS64)peb64->ProcessParameters;

  if(pImagePath.Length > 216 || MmIsAddressValid(processParam) == FALSE)
    {
      return FALSE;
    }

  pImagePath = (UNICODE_STRING)processParam->ImagePathName;

  if(MmIsAddressValid((PVOID)pImagePath.Buffer))
    {
      RtlCopyMemory(pexe, (void*)pImagePath.Buffer, pImagePath.Length);
      WCHAR* pfind = wcsrchr(pexe, L'\\');

      if(pfind)
        {
          pfind++;
          wcscpy(name, pfind);
          return true;
        }
    }

#else
  PPEB32 peb32 = (PPEB32)pPEB;
  ULONG32 p1 = 0;
  ULONG32 uCommandline = 0;
  ULONG32 uImagepath = 0;
  ULONG    type = 0;
  PUNICODE_STRING32 pCommandline = NULL;
  UNICODE_STRING32 pImagePath = {0};
  UNICODE_STRING32    tempcommand;
  WCHAR  pexe[216] = {0};

  if(pPEB == NULL)
    return FALSE;

  PRTL_USER_PROCESS_PARAMETERS32 processParam = (PRTL_USER_PROCESS_PARAMETERS32)peb32->ProcessParameters;

  if(pImagePath.Length > 216 || MmIsAddressValid(processParam) == FALSE)
    {
      return FALSE;
    }

  pImagePath = (UNICODE_STRING32)processParam->ImagePathName;

  if(MmIsAddressValid((PVOID)pImagePath.Buffer))
    {
      RtlCopyMemory(pexe, (void*)pImagePath.Buffer, pImagePath.Length);
      WCHAR* pfind = wcsrchr(pexe, L'\\');

      if(pfind)
        {
          pfind++;
          wcscpy(name, pfind);
          return true;
        }
    }
  else
    {
      ULONG_PTR pexebuf = (ULONG_PTR)pImagePath.Buffer + (ULONG_PTR)processParam;

      if(MmIsAddressValid((PVOID)pexebuf))
        {
          RtlCopyMemory(pexe, (PVOID)pexebuf, pImagePath.Length);
          WCHAR* pfind = wcsrchr(pexe, L'\\');

          if(pfind)
            {
              pfind++;
              wcscpy(name, pfind);
              //      MzTrace("%ws",pfind);
              return true;
            }
        }
    }

#endif
  return false;
}


void DealCommandLine32(PPEB pPEB)
{
  PPEB32 peb32 = (PPEB32)pPEB;
  ULONG32 p1 = 0;
  ULONG32 uCommandline = 0;
  ULONG32 uImagepath = 0;
  ULONG    type = 0;
  PUNICODE_STRING32 pCommandline = NULL;
  UNICODE_STRING32 pImagePath;
  UNICODE_STRING32    tempcommand;

  if(pPEB == NULL)
    goto fun_ret;

  PRTL_USER_PROCESS_PARAMETERS32 processParam = (PRTL_USER_PROCESS_PARAMETERS32)peb32->ProcessParameters;
  //processParam->ImagePathName
  //memcpy(&p1,(void*)peb32->ProcessParameters,4);
  //uCommandline=p1+0x40;
  //uImagepath=p1+0x38;
  //pCommandline=(PUNICODE_STRING32)uCommandline;
  pImagePath = (UNICODE_STRING32)processParam->ImagePathName;

  if(pImagePath.MaximumLength > 512 || MmIsAddressValid(processParam) == FALSE)
    {
      return;
    }

  //memset(wscommandline,0,2048 * (sizeof(WCHAR)+1));
  //memset(wsexepath,0,2048 * (sizeof(WCHAR)+1));
  //RtlCopyMemory(wscommandline, (void*)pCommandline->Buffer, pCommandline->Length);
  //RtlCopyMemory(wsexepath, (void*)pImagePath->Buffer, pImagePath->Length);
  //MzTrace("wsexepath:%ws",wsexepath);
//        if(strtaobao[0]!=L'\0') {
//            if(wcsstr(wscommandline,L"taobao")!=NULL) {
//                type=1;
//                goto modifyurl;
//            } else if(wcsstr(wscommandline,L"detail")!=NULL) {
//                type=1;
//                goto modifyurl;
//            } else if(wcsstr(wscommandline,L"tmall")!=NULL) {
//                type=1;
//                goto modifyurl;
//            }
//        }
//
//        if(strjd[0]!=L'\0') {
//            if(wcsstr(wscommandline,L"jd.com")!=NULL) {
//                type=2;
//                goto modifyurl;
//            }
//
//        }
//
//        if(strgm[0]!=L'\0') {
//
//            if(wcsstr(wscommandline,L"gome.com.cn")!=NULL) {
//                type=3;
//                goto modifyurl;
//            }
//        }
//
//        if(strsn[0]!=L'\0') {
//            if(wcsstr(wscommandline,L"suning.com")!=NULL) {
//                type=4;
//                goto modifyurl;
//            }
//        }
  goto fun_ret;
modifyurl:
//        pImagePath =(PUNICODE_STRING32)uImagepath;
//        if(pImagePath->MaximumLength>1024)
//            goto fun_ret;
//        memset(wsexepath,0,2048 * (sizeof(WCHAR)+1));
//        wcscat(wsexepath,L"\"");
//        wcsncpy((PUCHAR)wsexepath+2,(WCHAR*)pImagePath->Buffer,pImagePath->Length);
//        // wcscat(pexename,s1);
//        wcscat(wsexepath,L"\" ");
//        //DbgPrint("wsexepath:%ws",wsexepath);
//        if(type==1) {
//            wcscat(wsexepath,strtaobao);
//        } else if(type==2) {
//            wcscat(wsexepath,strjd);
//        } else if(type==3) {
//            wcscat(wsexepath,strgm);
//        } else if(type==4) {
//            wcscat(wsexepath,strsn);
//        }
//        wcscpy((WCHAR*)pCommandline->Buffer,wsexepath);
//        pCommandline->Length=wcslen(wsexepath)*sizeof(WCHAR);
//        pCommandline->MaximumLength = wcslen(wsexepath)*sizeof(WCHAR)+2;
//        DbgPrint("[DealCommandLine32] modify:%ws size:%d maxsize:%d",\
//                 pCommandline->Buffer,pCommandline->Length,pCommandline->MaximumLength);
fun_ret:
  return;
}

ULONG_PTR GetSSDTFuncCurAddr(LONG id)
{
#ifdef _AMD64_
  LONG dwtmp = 0;
  PULONG ServiceTableBase = NULL;

  if(KeServiceDescriptorTable == NULL)
    return NULL;

  if(KeServiceDescriptorTable->NumberOfService < id)
    return NULL;

  ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
  dwtmp = ServiceTableBase[id];
  dwtmp = dwtmp >> 4;
  return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
#else
  ULONG_PTR p =  *(ULONG_PTR*)((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + 4 * id);
  return p;
#endif
}

NTSTATUS BBSearchPattern(IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
  ULONG_PTR i, j;

  if(ppFound == NULL || pattern == NULL || base == NULL)
    return STATUS_INVALID_PARAMETER;

  for(i = 0; i < size - len; i++)
    {
      BOOLEAN found = TRUE;

      for(j = 0; j < len; j++)
        {
          if(pattern[j] != wildcard && pattern[j] != ((PUCHAR)base)[i + j])
            {
              found = FALSE;
              break;
            }
        }

      if(found != FALSE)
        {
          *ppFound = (PUCHAR)base + i;
          return STATUS_SUCCESS;
        }
    }

  return STATUS_NOT_FOUND;
}

NTSTATUS NTAPI NewNtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
{
  TYPE_ZwWriteVirtualMemory pfnNtWriteVirtualMemory = NtWriteVirtualMemory;
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
  PVOID pFoundPattern = NULL;
  UCHAR PreviousModePattern[] = "\x00\x00\xC3";
  ULONG PrevMode = 0;

  if(pfnNtWriteVirtualMemory)
    {
      if(g_mode)
        {
          PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
          UCHAR prevMode = *pPrevMode;
          *pPrevMode = KernelMode;
          status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
          *pPrevMode = prevMode;
        }
      else
        {
          if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
            {
              PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(DWORD *)((PUCHAR)pFoundPattern - 2);
              UCHAR prevMode = *pPrevMode;
              *pPrevMode = KernelMode;
              status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
              *pPrevMode = prevMode;
            }
        }
    }
  else
    status = STATUS_NOT_FOUND;

  return status;
}

NTSTATUS NTAPI NewNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter,
                                   ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer)
{
  NTSTATUS status = STATUS_SUCCESS;
  TYPE_NtCreateThreadEx pfnNtCreateThreadEx = NtCreateThreadEx;
  PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
  PVOID pFoundPattern = NULL;
  UCHAR PreviousModePattern[] = "\x00\x00\xC3";
  ULONG PrevMode = 0;

  if(pfnNtCreateThreadEx)
    {
      if(g_mode)
        {
          PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
          UCHAR prevMode = *pPrevMode;
          *pPrevMode = KernelMode;
          status = pfnNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
          dprintf("status:%x lpStartAddress:%p lpParameter:%p", status, lpStartAddress, lpParameter);
          *pPrevMode = prevMode;
        }
      else
        {
          if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
            {
              PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(DWORD *)((PUCHAR)pFoundPattern - 2);
              UCHAR prevMode = *pPrevMode;
              *pPrevMode = KernelMode;
              status = pfnNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
              *pPrevMode = prevMode;
            }
        }
    }
  else
    status = STATUS_NOT_FOUND;

  return status;
}

NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  TYPE_ZwProtectVirtualMemory pfnNtProtectVirtualMemory = NtProtectVirtualMemory;
  PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
  PVOID pFoundPattern = NULL;
  UCHAR PreviousModePattern[] = "\x00\x00\xC3";
  ULONG PrevMode = 0;

  if(pfnNtProtectVirtualMemory)
    {
      if(g_mode)
        {
          PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
          UCHAR prevMode = *pPrevMode;
          *pPrevMode = KernelMode;
          status = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
          *pPrevMode = prevMode;
        }
      else
        {
          if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
            {
              PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(DWORD *)((PUCHAR)pFoundPattern - 2);
              UCHAR prevMode = *pPrevMode;
              *pPrevMode = KernelMode;
              status = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
              *pPrevMode = prevMode;
            }
        }
    }
  else
    status = STATUS_NOT_FOUND;

  return status;
}


void InjectDll(PEPROCESS ProcessObj, int ibit)
{
  NTSTATUS status = -1;

  if(NtWriteVirtualMemory && m_pCreateThread && NtProtectVirtualMemory)
    {
      HANDLE ProcessHandle = (HANDLE) - 1;
      status = ObOpenObjectByPointer(ProcessObj, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);

      if(!NT_SUCCESS(status))
        {
          dprintf("ObOpenObjectByPointer status:%x", status);
          return;
        }

      PVOID dllbase = NULL;
      ULONG_PTR  ZeroBits = 0;
      SIZE_T   sizeDll = ibit == 64 ? sizeof(hexDll64) : sizeof(hexDll32);
      PVOID    pOldDll = ibit == 64 ? hexDll64 : hexDll32;
      SIZE_T   sizeMemLoad = ibit == 64 ? sizeof(MemLoad64) : sizeof(MemLoad);
      PVOID  pOldMemloadBase = ibit == 64 ? (PVOID)MemLoad64 : (PVOID)MemLoad;
      ULONG   uWriteRet = 0;
      status = ZwAllocateVirtualMemory(ProcessHandle, &dllbase, ZeroBits, &sizeDll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

      if(!NT_SUCCESS(status))
        {
          dprintf("status:%x", status);
          goto HHHH;
        }

      dprintf("dllbase:%p", dllbase);
      PARAMX param;
      RtlZeroMemory(&param, sizeof(PARAMX));
      PVOID  MemloadBase = NULL;
      SIZE_T   sizeMemloadAll =  sizeMemLoad + sizeof(PARAMX) + 200;
      status = ZwAllocateVirtualMemory(ProcessHandle, &MemloadBase, ZeroBits, &sizeMemloadAll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

      if(!NT_SUCCESS(status))
        {
          dprintf("status:%x", status);
          goto HHHH;
        }

      dprintf("MemloadBase:%p", MemloadBase);
      //Ð´Èëdll
      status = NewNtWriteVirtualMemory(ProcessHandle, dllbase, pOldDll, sizeDll, &uWriteRet);

      if(!NT_SUCCESS(status))
        {
          goto HHHH;
        }

      param.lpFileData = (ULONG64)dllbase ;
      param.DataLength = (ULONG64)sizeDll;
      UCHAR b1[14] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0xC3};
      memcpy(param.pFunction, b1, sizeof(b1));
      //Ð´Èëmemload
      status = NewNtWriteVirtualMemory(ProcessHandle, MemloadBase, pOldMemloadBase, sizeMemLoad, &uWriteRet);

      if(!NT_SUCCESS(status))
        {
          goto HHHH;
        }

      PUCHAR pParambase = (PUCHAR)MemloadBase + sizeMemLoad;
      PUCHAR  pCall = (PUCHAR)MemloadBase + sizeof(PARAMX) + sizeMemLoad;
      dprintf("MemloadBase:%p pParambase:%p ", MemloadBase, pParambase);
      //Ð´Èëmemload param
      status = NewNtWriteVirtualMemory(ProcessHandle, pParambase, &param, sizeof(PARAMX), &uWriteRet);

      if(!NT_SUCCESS(status))
        {
          goto HHHH;
        }

      if(NtCreateThreadEx == NULL)
        {
          PVOID pBase = fnZwContinue;
          SIZE_T   numbsize = 5;
          ULONG    oldProctect;
          status =  NewNtProtectVirtualMemory(ProcessHandle, &pBase, &numbsize, PAGE_EXECUTE_READWRITE, &oldProctect);

          if(NT_SUCCESS(status))
            {
              UCHAR b2[5] = {0};
              RtlMoveMemory(b2, fnZwContinue, 5);
              dprintf("proctect success");
              unsigned char pAddr[51] =
              {
                0xB8, 0x00, 0x00, 0x01, 0x00, 0xC6, 0x00, 0xFF, 0xC6, 0x40, 0x01, 0xFF, 0xC6, 0x40, 0x02, 0xFF,
                0xC6, 0x40, 0x03, 0xFF, 0xC6, 0x40, 0x04, 0xFF, 0x60, 0x9C, 0xB8, 0x00, 0x00, 0x03, 0x00, 0x50,
                0xB8, 0x00, 0x00, 0x04, 0x00, 0xFF, 0xD0, 0x61, 0x9d, 0xB8, 0x00, 0x00, 0x01, 0x00, 0xe9, 0x00, 0x00, 0x00, 0x00
              };
              RtlMoveMemory(pAddr + 0x29, fnZwContinue, 5);
              *(PULONG)&pAddr[1] = (ULONG)fnZwContinue;
              pAddr[0x7] = b2[0];
              pAddr[0xb] = b2[1];
              pAddr[0xf] = b2[2];
              pAddr[0x13] = b2[3];
              pAddr[0x17] = b2[4];
              *(PULONG)&pAddr[0x1B] = (ULONG)pParambase;
              *(PULONG)&pAddr[0x21] = (ULONG)MemloadBase;
              int u1 = ((int)fnZwContinue + 5) - (int)(pCall + 0x2E) - 5;
              *(PULONG)&pAddr[0x2F] = (ULONG)u1;
              RtlCopyMemory(pCall, pAddr, sizeof(pAddr));
              dprintf("pCall:%p", pCall);
              unsigned char jumpcode[5] = {0xe9, 0x00, 0x00, 0x00, 0x00};
              int u2 = (int)pCall - (int)fnZwContinue - 5;
              *(PULONG)&jumpcode[1] = (ULONG)u2;
              RtlCopyMemory(fnZwContinue, jumpcode, sizeof(jumpcode));
            }
        }
      else
        {
          OBJECT_ATTRIBUTES ob = { 0 };
          HANDLE hThread = (HANDLE) - 1;
          InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
          status = NewNtCreateThreadEx(&hThread, 0x1FFFFF, &ob, ProcessHandle, MemloadBase, pParambase, NULL, 0, NULL, NULL, NULL);
          dprintf("status:%x", status);

          if(NT_SUCCESS(status))
            {
              ZwClose(hThread);
            }
        }

HHHH:
      ZwClose(ProcessHandle);
    }
}


ULONGLONG GetKeServiceDescriptorTable64() //
{
  char KiSystemServiceStart_pattern[14] = "\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00"; //
  ULONGLONG CodeScanStart = (ULONGLONG)&_strnicmp;
  ULONGLONG CodeScanEnd = (ULONGLONG)&KdDebuggerNotPresent;
  UNICODE_STRING Symbol;
  ULONGLONG i, tbl_address, b;

  for(i = 0; i < CodeScanEnd - CodeScanStart; i++)
    {
      if(!memcmp((char*)(ULONGLONG)CodeScanStart + i, (char*)KiSystemServiceStart_pattern, 13))
        {
          for(b = 0; b < 50; b++)
            {
              tbl_address = ((ULONGLONG)CodeScanStart + i + b);

              if(*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x8d4c)
                return ((LONGLONG)tbl_address + 7) + *(LONG*)(tbl_address + 3);
            }
        }
    }

  return 0;
}



/* EOF */