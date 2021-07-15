#pragma once

#include "utils.h"
#include "xor.h"

namespace utils {
	void* get_ntosrknl_base_addr() {

		#pragma pack(push, 1)
		typedef struct
		{
			UCHAR Padding[4];
			PVOID InterruptServiceRoutine;
		} IDT_ENTRY;
		#pragma pack(pop)

		const auto idt_base = reinterpret_cast<IDT_ENTRY*>(__readgsqword(0x38));

		const auto first_isr_address = idt_base[0].InterruptServiceRoutine;

		auto page_within_ntoskrnl = reinterpret_cast<uintptr_t>(first_isr_address) & ~static_cast<uintptr_t>(0xfff);

		while (*reinterpret_cast<const USHORT*>(page_within_ntoskrnl) != 0x5a4d)
		{
			page_within_ntoskrnl -= 0x1000;
		}

		return reinterpret_cast<void*>(page_within_ntoskrnl);
	}

    PVOID find_pattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {

        auto check_mask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
        {
            for (auto index = buffer; *mask; pattern++, mask++, index++) {
                auto addr = *(BYTE*)(pattern);

                if (addr != *index && *mask != E("?")[0])
                    return FALSE;
            }

            return TRUE;
        };

        for (auto index = 0; index < size - strlen(mask); index++) {
            auto address = (PBYTE)module + index;

            if (check_mask(address, pattern, mask))
                return address;
        }

        return 0;
    }

    PVOID find_pattern_image(PVOID base, LPCSTR pattern, LPCSTR mask) {
		auto get_nt_header = [](PVOID module) -> PIMAGE_NT_HEADERS
		{
			return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
		};

        auto header = get_nt_header(base);
        auto section = IMAGE_FIRST_SECTION(header);

        for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {
            if (!memcmp(section->Name, E(".text"), 5) || !memcmp(section->Name, E("PAGE"), 4)) {
                auto addr = find_pattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
                if (addr) {
                    return addr;
                }
            }
        }

        return 0;
    }

	PVOID return_DLL_base_addr(PEPROCESS pe_process, UNICODE_STRING module_name) {
		if (!pe_process)
			return nullptr;

		PPEB peb = PsGetProcessPeb(pe_process);

		if (!peb)
			return nullptr;

		KAPC_STATE state;
		KeStackAttachProcess(pe_process, &state);
		PPEB_LDR_DATA ldr = peb->Ldr;

		if (!ldr)
		{
			KeUnstackDetachProcess(&state);
			return 0;
		}

		for (PLIST_ENTRY listEntry = (PLIST_ENTRY)ldr->ModuleListLoadOrder.Flink; listEntry != &ldr->ModuleListLoadOrder; listEntry = (PLIST_ENTRY)listEntry->Flink) {
			PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

			if (RtlCompareUnicodeString(&ldrEntry->BaseDllName, &module_name, TRUE) == 0) {
				PVOID baseAddr = ldrEntry->DllBase;
				KeUnstackDetachProcess(&state);
				return baseAddr;
			}

		}

		KeUnstackDetachProcess(&state);

		return 0;
	}

	NTSTATUS read_write_mem(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T Size)
	{
		SIZE_T Bytes = 0;

		if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, UserMode, &Bytes)))
			return STATUS_SUCCESS;
		else
			return STATUS_ACCESS_DENIED;
	}
}