/*
 * fork.c
 * Experimental fork() on Windows.  Requires NT 6 subsystem or
 * newer.
 *
 * Copyright (c) 2012 William Pitcock <nenolod@dereferenced.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

//#define USE_HARDCODED_OFFSET

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>
#include <ntdef.h>
#include <stdio.h>
#include <errno.h>
#include <process.h>

#define DEBUG
#ifdef DEBUG
#define debug_printf(fmt, args...) printf(fmt, ##args);
#else
#define debug_printf(fmt, ...)
#endif

#ifndef _WINTERNL_
/* defined in the <winternl.h> */
typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;
#endif /* !_WINTERNL_ */

#ifndef BASESRV_SERVERDLL_INDEX
#define BASESRV_SERVERDLL_INDEX         1
#endif
#ifndef USERSRV_SERVERDLL_INDEX
#define USERSRV_SERVERDLL_INDEX         3
#endif

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID EntryPoint;
	ULONG StackZeroBits;
	ULONG StackReserved;
	ULONG StackCommit;
	ULONG ImageSubsystem;
	WORD SubSystemVersionLow;
	WORD SubSystemVersionHigh;
	ULONG Unknown1;
	ULONG ImageCharacteristics;
	ULONG ImageMachineType;
	ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Size;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED	0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES		0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE		0x00000004

#define RTL_CLONE_PARENT				0
#define RTL_CLONE_CHILD					297

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS) 0)
#endif
#define STATUS_PROCESS_CLONED           ((NTSTATUS) 0x00000129)

typedef NTSTATUS (*RtlCloneUserProcess_t)(ULONG ProcessFlags,
	PSECURITY_DESCRIPTOR ProcessSecurityDescriptor /* optional */,
	PSECURITY_DESCRIPTOR ThreadSecurityDescriptor /* optional */,
	HANDLE DebugPort /* optional */,
	PRTL_USER_PROCESS_INFORMATION ProcessInformation);

static int ConnectCsrChild(void);
#ifndef USE_HARDCODED_OFFSET
static int setupCsrDataRva(void);
#endif
pid_t fork(void)
{
	HMODULE mod;
	RtlCloneUserProcess_t RtlCloneUserProcess_p;
	RTL_USER_PROCESS_INFORMATION process_info;
	NTSTATUS result;
	DWORD child;
	HANDLE hp, ht;

	mod = GetModuleHandle("ntdll.dll");
	if (!mod)
		return -ENOSYS;

	RtlCloneUserProcess_p = (RtlCloneUserProcess_t) GetProcAddress(mod, "RtlCloneUserProcess");
	if (RtlCloneUserProcess_p == NULL)
		return -ENOSYS;

#ifndef USE_HARDCODED_OFFSET
        setupCsrDataRva();
#endif

	/* lets do this */
	result = RtlCloneUserProcess_p(
		RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
		NULL, NULL, NULL, &process_info);

	switch(result) {
	case STATUS_SUCCESS:
		/* parent */
		child = GetProcessId(process_info.Process);
		//child = (DWORD)(process_info.ClientId.UniqueProcess);

		hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, child);
		ht = OpenThread(THREAD_ALL_ACCESS, FALSE, child);

		ResumeThread(process_info.Thread);
		CloseHandle(process_info.Process);
		CloseHandle(process_info.Thread);
		CloseHandle(hp);
		CloseHandle(ht);

		return (pid_t)child;
		break;
	case STATUS_PROCESS_CLONED:
		/* child */
		/* fix stdio */
		FreeConsole();
		AllocConsole();

		/* Remove these calls to improve performance, at the cost of losing stdio. */
		SetStdHandle(STD_INPUT_HANDLE, stdin);
		SetStdHandle(STD_OUTPUT_HANDLE, stdout);
		SetStdHandle(STD_ERROR_HANDLE, stderr);

		// connect Csrss
		if (ConnectCsrChild()) {
			return -1;
		}

		return 0;
		break;
	default:
		return -1;
	}

	/* NOTREACHED */
	return -1;
}

typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);
NtQueryInformationProcess_t NtQueryInformationProcess_p;

typedef NTSTATUS(NTAPI *CsrClientConnectToServer_t)(
    IN PWSTR ObjectDirectory,
    IN ULONG ServerId,
    IN PVOID ConnectionInfo,
    IN ULONG ConnectionInfoSize,
    OUT PBOOLEAN ServerToServerCall
);
CsrClientConnectToServer_t CsrClientConnectToServer;

// private
typedef NTSTATUS (NTAPI *RtlRegisterThreadWithCsrss_t)(VOID);

RtlRegisterThreadWithCsrss_t RtlRegisterThreadWithCsrss;

#define RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

typedef void *PVOID;
typedef unsigned int ULONG32,*PULONG32;

/**
 * from https://github.com/helpsystems/CreateProcess/blob/main/source/main.c
 * with small fix.

 * find a pattern within the code of an API,
 * get the address of a global variable and
 * return its address
 */
PVOID find_generic(
    PVOID funcAddress,
    PBYTE searchPattern,
    ULONG32 patternSize,
    DWORD offset)
{
    ULONG sizeOfRegion = 0x200; /* original 0x100 */

    for (ULONG i = offset; i < sizeOfRegion + offset; i++)
    {
        PVOID address = RVA2VA(PVOID, funcAddress, i);
        if (!memcmp(address, searchPattern, patternSize))
        {
            ULONG32 ripOffset = *RVA2VA(PULONG32, address, min(3, patternSize));
            PVOID rip = RVA2VA(PVOID, address, min(3, patternSize) + sizeof(ULONG32));
            return RVA2VA(PVOID, rip, ripOffset);
        }
    }

    return NULL;
}

PVOID find_ntdll_variable_offset(char *procName, BYTE *pattern, size_t sz)
{
    PVOID address = NULL;
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    PVOID offset = NULL;
    DWORD searchOffset = 0;

    if (sz == 0) {
        // in this case, first byte is the size and the last are pattern.
        sz = pattern[0];
        if ((INT8)pattern[1] <= 0) {
            // if second byte <= 0 then use it as offset.
            searchOffset = -(INT8)pattern[1] * 0x100;
            pattern = pattern + 2;
            debug_printf("[i] search offset = %x\n", searchOffset);
        } else {
            pattern = pattern + 1;
        }
    }

    PVOID procAddress = GetProcAddress(ntdll, procName);
    if (!procAddress) {
        printf("%s not found\n", procName);
        return NULL;
    }

    address = find_generic(
        procAddress,
        pattern,
        sz,
        searchOffset);

    if (address)
    {
        debug_printf("[i] variable address found at 0x%p\n", address);
        offset = (PVOID)((PVOID)address - (PVOID)(uintptr_t)ntdll);
        debug_printf("[i] variable offset is 0x%x\n", offset);
        return offset;
    }

    debug_printf("[!] could not find the variable!\n");
    return NULL;
}

/*
 * from https://github.com/sslab-gatech/winnie Winnie project : forklib
 *
 * HARDCODED OFFSET, obtained by the gen_csrss_offsets.py and see the output csrss_offsets.h
 */
#define CACHE_PROC(mod, name) name##_t name = (name##_t)GetProcAddress(mod, #name)

#ifdef USE_HARDCODED_OFFSET
// obtained by the gen_csrss_offsets.py
// RVA of CsrServerApiRoutine up to RtlpEnvironLookupTable in System32/ntdll.dll
#define csrDataRva_x64 0x16cc08
#define csrDataSize_x64 0xf8
#else
// detect csrDataRvaOff on the fly.
// using the CreateProcess's method.
// please see https://github.com/helpsystems/CreateProcess
static PVOID csrDataRvaOff = NULL;
static int csrDataSize = -1;

static int setupCsrDataRva(void)
{
    if (csrDataRvaOff != NULL)
        return 0;

    // byte pattern could be found by WinDbg command like as following:
    //
    // 0:005> # ntdll!CsrServerApiRoutine ntdll!CsrClientCallServer
    // ntdll!CsrClientCallServer+0x13c:
    // 00007ff8`b3138adc 488b0525411600  mov     rax,qword ptr [ntdll!CsrServerApiRoutine (00007ff8`b329cc08)]

    // # ntdll!CsrServerApiRoutine ntdll!CsrClientCallServer
    BYTE pattern_csrServerApiRoutine[] = { 3, 0, 0x48, 0x8b, 0x05 };
    // # ntdll!CsrServerApiRoutine ntdll!CsrClientConnectToServer+0x5f
    BYTE pattern_csrServerApiRoutine_2[] = { 4, 0, 0x4c, 0x8d, 0x0d, 0x98 };
    // # ntdll!CsrServerApiRoutine ntdll!RtlRegisterThreadWithCsrss+0x50
    BYTE pattern_csrServerApiRoutine_3[] = { 4, 0, 0x48, 0x8b, 0x05, 0x7f };

    BYTE *patterns[] = {
        pattern_csrServerApiRoutine,
        pattern_csrServerApiRoutine_2,
        pattern_csrServerApiRoutine_3,
    };
    char *routines[] = {
        "CsrClientCallServer",
        "CsrClientConnectToServer",
        "RtlRegisterThreadWithCsrss",
    };

    for (int i = 0; i < 3; i++) {
        PVOID offset = find_ntdll_variable_offset(routines[i], patterns[i], 0);
        if (offset) {
            debug_printf("[!] csrDataRvaOff = 0x%x\n", offset);
            csrDataRvaOff = offset;
            break;
        }
    }

    // # ntdll!RtlpEnvironLookupTable ntdll!RtlCompareUnicodeString
    BYTE pattern_rtlpEnvironLookupTable[] = { 3, 0, 0x4c, 0x8d, 0x05 };
    // # ntdll!RtlpEnvironLookupTable ntdll!RtlpScanEnvironment+0x40 (at RtlCompareUnicodeString)
    BYTE pattern_rtlpEnvironLookupTable_2[] = { 2, 0, 0x8d, 0x05 };
    // # ntdll!RtlpEnvironLookupTable ntdll!RtlpScanEnvironment+0x88
    BYTE pattern_rtlpEnvironLookupTable_3[] = { 3, -5, 0x48, 0x8d, 0x0d };

    BYTE *patterns_end[] = {
        pattern_rtlpEnvironLookupTable,
        pattern_rtlpEnvironLookupTable_2,
        pattern_rtlpEnvironLookupTable_3,
    };
    char *routines_end[] = {
        "RtlCompareUnicodeString",
        "RtlCompareUnicodeString",
        "RtlSetEnvironmentVar",
    };

    PVOID csrDataRvaEnd = NULL;
    for (int i = 0; i < 3; i++) {
        PVOID offset = find_ntdll_variable_offset(routines_end[i], patterns_end[i], 0);
        if (offset) {
            debug_printf("[!] csrDataRvaEnd = 0x%x\n", offset);
            csrDataRvaEnd = offset;
            break;
        }
    }

    if (csrDataRvaOff) {
        if (csrDataRvaEnd) {
            csrDataSize = csrDataRvaEnd - csrDataRvaOff;
        } else {
            debug_printf("[!] csrDataRvaEnd not found\n");
            // no csrDataRvaEnd found
            // XXX
            csrDataSize = 0xf0;
        }
        debug_printf("[!] csrDataSize = 0x%x\n", csrDataSize);
        return 0;
    }
    return -1;
}
#endif

static int ConnectCsrChild(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return -ENOSYS;

    // Zero Csr fields???
    // Required or else Csr calls will crash
    CACHE_PROC(ntdll, CsrClientConnectToServer);
    CACHE_PROC(ntdll, RtlRegisterThreadWithCsrss);

#ifdef USE_HARDCODED_OFFSET
    // HARDCODED OFFSET, obtained from the gen_csrss_offsets.py and see the output csrss_offsets.h
    void* pCsrData = (void*)((uintptr_t)ntdll + csrDataRva_x64);
    // reset data area.
    memset(pCsrData, 0, csrDataSize_x64);
#else
    // Setup CsrDataRvaOffset and Size on the fly.
    if (csrDataRvaOff == NULL) {
        int ret = setupCsrDataRva();
        if (ret < 0)
            return -ENOSYS;
    }

    void* pCsrData = (void*)((uintptr_t)ntdll + csrDataRvaOff);
    memset(pCsrData, 0, csrDataSize);
    // we don't have to clean all data area anyway.
    // reset from CsrInitOnceDone/CsrServerApiRoutine ~ 0x80 bytes is ok.
#endif

    DWORD session_id;
    wchar_t ObjectDirectory[100];
    ProcessIdToSessionId(GetProcessId(GetCurrentProcess()), &session_id);
    // get session_id
    swprintf(ObjectDirectory, 100, L"\\Sessions\\%d\\Windows", session_id);

    BOOLEAN trash;
    // Not required?
    // Link Console subsystem
    void* pCtrlRoutine = (void*)GetProcAddress(GetModuleHandleA("kernelbase"), "CtrlRoutine");

    if (!NT_SUCCESS(CsrClientConnectToServer(ObjectDirectory, BASESRV_SERVERDLL_INDEX, &pCtrlRoutine, 8, &trash))) {
        return -1;
    }

    // Link Windows subsystem
    // passing &gfServerProcess is not necessary, actually? passing &trash is okay?
    char buf[0x240]; // this seem to just be all zero everytime?
    memset(buf, 0, sizeof(buf));

    if (!NT_SUCCESS(CsrClientConnectToServer(ObjectDirectory, USERSRV_SERVERDLL_INDEX, buf, 0x240, &trash))) {
        return -1;
    }

    // Connect to Csr
    if (!NT_SUCCESS(RtlRegisterThreadWithCsrss())) {
        return -1;
    }

    return 0;
}
