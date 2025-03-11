#include <Windows.h>
#include <cstdint>
#include <ntstatus.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <conio.h> // just for _getch();
#include <string> // For ProcessName -> PID
#include <optional>

#include "ComfierSyscalls/ComfierSyscalls.h"

namespace CS = ComfierSyscalls;

#define NT_SUCCESS(NtStatus) NtStatus == 0x00000000
#define NT_FAILURE(NtStatus) NtStatus != 0x00000000

#define VALID_HANDLE(Handle) Handle != nullptr && Handle != INVALID_HANDLE_VALUE
#define INVALID_HANDLE(Handle) Handle == nullptr || Handle == INVALID_HANDLE_VALUE

static std::optional<HANDLE> FindDuplicationRightsHandle(uint32_t PID)
{
    ULONG Size = 0x10000;
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID Buffer = nullptr;

    BOOLEAN oPrivilege = FALSE;
    CS::RtlAdjustPrivilege(0x14, TRUE, FALSE, &oPrivilege); // LUID of SeDebugPrivilege == 0x14

    do 
    {
        Buffer = VirtualAlloc(nullptr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!Buffer)
        {
            printf("[-] Buffer Allocation Failed (0x%lX)\n", GetLastError());
            return std::nullopt;
        }

        Status = CS::NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), Buffer, Size, &Size);

        if (Status == STATUS_INFO_LENGTH_MISMATCH) 
        {
            VirtualFree(Buffer, 0, MEM_RELEASE);
            Size *= 2;
        }

    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_FAILURE(Status)) 
    {
        VirtualFree(Buffer, 0, MEM_RELEASE);
        printf("[-] NtQuerySystemInformation Failed (0x%lX)\n", Status);
        return std::nullopt;
    }

    _SYSTEM_HANDLE_INFORMATION_EX* HandleInfo = reinterpret_cast<_SYSTEM_HANDLE_INFORMATION_EX*>(Buffer);
    HANDLE DuplicateHandle = 0;
    CLIENT_ID cID = {};
    HANDLE CurrentHandle = 0;
    OBJECT_ATTRIBUTES Attributes = { sizeof(OBJECT_ATTRIBUTES), nullptr, nullptr, 0, nullptr, nullptr };

    for (ULONG_PTR i = 0; i < HandleInfo->NumberOfHandles; i++) 
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& Info = HandleInfo->Handles[i];
        HANDLE Handle = Info.HandleValue;

        if (INVALID_HANDLE(Handle))
        {
            continue; // Invalid Handle
        }

        if (Info.ObjectTypeIndex != 0x7)
        {
            continue; // Not a Process Handle
        }

        cID.UniqueProcess = Info.UniqueProcessId;

        if (VALID_HANDLE(CurrentHandle)) CloseHandle(CurrentHandle);

        NTSTATUS Status = CS::NtOpenProcess(&CurrentHandle, PROCESS_DUP_HANDLE, &Attributes, &cID);

        if (INVALID_HANDLE(CurrentHandle) || NT_FAILURE(Status))
        {
            continue;
        }

        Status = CS::NtDuplicateObject(CurrentHandle, Info.HandleValue, reinterpret_cast<HANDLE>(-1), &DuplicateHandle, PROCESS_ALL_ACCESS, 0, 0);
    
        if (INVALID_HANDLE(DuplicateHandle) || NT_FAILURE(Status))
        {
            continue;
        }

        if (GetProcessId(DuplicateHandle) != PID)
        {
            CloseHandle(DuplicateHandle);
            continue;
        }

        return DuplicateHandle;
    }

    return std::nullopt;
}

static void PrintProcessBase(HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION PBI;
    NTSTATUS Status = CS::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &PBI, sizeof(PBI), nullptr);

    if (NT_FAILURE(Status))
    {
        printf("[-] Couldn't Query Handle (0x%lX)\n", Status);
        return;
    }

    printf("[~] PEB: 0x%llX\n", (uintptr_t)PBI.PebBaseAddress);

    uintptr_t BaseAddress = 0x0;
    uintptr_t pBaseAddress = (uintptr_t)PBI.PebBaseAddress + 0x10;
    Status = CS::NtReadVirtualMemory(hProcess, (PVOID)pBaseAddress, &BaseAddress, sizeof(uintptr_t), nullptr);

    if (NT_FAILURE(Status))
    {
        printf("[-] Couldn't Read Virtual Memory (0x%lX)\n", Status);
        return;
    }

    printf("[~] ProcessBase: 0x%llX\n", BaseAddress);
}

static std::optional<uint32_t> ResolvePID(const std::wstring& ProcessName) 
{
    PROCESSENTRY32 ProcessEntry32 = {};
    ProcessEntry32.dwSize = static_cast<uint32_t>(sizeof(PROCESSENTRY32));

    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (INVALID_HANDLE(Snapshot)) return std::nullopt;

    if (Process32First(Snapshot, &ProcessEntry32)) 
    {
        do 
        {
            if (ProcessName == ProcessEntry32.szExeFile) 
            {
                CloseHandle(Snapshot);
                return ProcessEntry32.th32ProcessID;
            }
        } while (Process32Next(Snapshot, &ProcessEntry32));
    }

    CloseHandle(Snapshot);
    return std::nullopt;
}

int main()
{
    const std::optional<uint32_t> PID = ResolvePID(L"notepad.exe");

    if (!PID.has_value())
    {
        printf("[-] Could not find a PID for target process\n");
        return -1;
    }

    const std::optional<HANDLE> DuplicateHandle = FindDuplicationRightsHandle(PID.value());

    if (DuplicateHandle.has_value())
    {
        PrintProcessBase(DuplicateHandle.value());
        (void)_getch();
        return 0;
    }

    printf("[-] Failed to find a handle\n");
    (void)_getch();
}