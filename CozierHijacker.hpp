#pragma once
#include <Windows.h>
#include <cstdint>
#include <ntstatus.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <conio.h> // just for _getch();
#include <string> // For ProcessName -> PID
#include <optional>

#include "ComfierSyscalls/ComfierSyscalls.h"

namespace CozierHijacker
{
    using namespace ComfierSyscalls;

#define NT_SUCCESS(NtStatus) NtStatus == 0x00000000
#define NT_FAILURE(NtStatus) NtStatus != 0x00000000

#define VALID_HANDLE(Handle) Handle != nullptr && Handle != INVALID_HANDLE_VALUE
#define INVALID_HANDLE(Handle) Handle == nullptr || Handle == INVALID_HANDLE_VALUE

    inline std::optional<HANDLE> FindDuplicationRightsHandle(uint32_t PID)
    {
        ULONG Size = 0x10000;
        NTSTATUS Status = STATUS_SUCCESS;
        PVOID Buffer = nullptr;

        BOOLEAN oPrivilege = FALSE;
        RtlAdjustPrivilege(0x14, TRUE, FALSE, &oPrivilege); // LUID of SeDebugPrivilege == 0x14

        do
        {
            Buffer = VirtualAlloc(nullptr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!Buffer)
            {
                printf("[-] Buffer Allocation Failed (0x%lX)\n", GetLastError());
                return std::nullopt;
            }

            Status = NtQuerySystemInformation(SystemExtendedHandleInformation, Buffer, Size, &Size);

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
        HANDLE CurrentHandle = nullptr;
        OBJECT_ATTRIBUTES Attributes = { sizeof(OBJECT_ATTRIBUTES), nullptr, nullptr, 0, nullptr, nullptr };

        for (ULONG_PTR i = 0; i < HandleInfo->NumberOfHandles; i++)
        {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& Info = HandleInfo->Handles[i];
            HANDLE Handle = Info.HandleValue;

            if (INVALID_HANDLE(Handle))
            {
                continue; // Invalid Handle
            }

            if ((ULONG_PTR)Info.UniqueProcessId == PID)
            {
                continue; // Target Process
            }

            if (VALID_HANDLE(CurrentHandle))
            {
                CloseHandle(CurrentHandle);
                CurrentHandle = nullptr;
            }

            cID.UniqueProcess = Info.UniqueProcessId;
            cID.UniqueThread = nullptr;

            NTSTATUS Status = NtOpenProcess(&CurrentHandle, PROCESS_DUP_HANDLE, &Attributes, &cID);

            if (NT_FAILURE(Status))
            {
                continue;
            }

            Status = NtDuplicateObject(CurrentHandle, Info.HandleValue, reinterpret_cast<HANDLE>(-1), &DuplicateHandle, PROCESS_ALL_ACCESS, 0, 0);

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
}