#pragma once

#include "utils.h"
#include "xor.h"

#define relative_address(addr, size) ((PVOID)((PBYTE)addr + *(PINT)((PBYTE)addr + (size - (INT)sizeof(INT))) + size))

#define our_req_io_control_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x06292, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define our_initiate_req_io_control_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x04182, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

bool requests_initiated = false;
PDRIVER_DISPATCH acpi_original_device_control = nullptr;

NTSTATUS hooked_device_control(PDEVICE_OBJECT device_object, PIRP irp) {
	auto stack = IoGetCurrentIrpStackLocation(irp);

	if (stack) {
		auto buffer = (Communication*)irp->AssociatedIrp.SystemBuffer;
		auto io_control_code = stack->Parameters.DeviceIoControl.IoControlCode;

		if (buffer) {

			if (io_control_code == our_initiate_req_io_control_code || io_control_code == our_req_io_control_code) {

				if (io_control_code == our_initiate_req_io_control_code) {
					requests_initiated = true;
				}

				if (requests_initiated) {
					if (io_control_code == our_req_io_control_code) {

						if (buffer->req_type == RequestType::GetEXEBase) {
							if (buffer->process_id) {
								PEPROCESS process = { 0 };
								if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)buffer->process_id, &process))) {
									buffer->out_base_addr = PsGetProcessSectionBaseAddress(process);
									ObfDereferenceObject(process);
								}
							}
						}
						else if (buffer->req_type == RequestType::GetUnityBase) {
							if (buffer->process_id) {
								PEPROCESS process = { 0 };

								if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)buffer->process_id, &process))) {
									UNICODE_STRING DLLName;
									RtlInitUnicodeString(&DLLName, EW(L"UnityPlayer.dll"));
									buffer->out_base_addr = utils::return_DLL_base_addr(process, DLLName);
									ObfDereferenceObject(process);
								}
							}
						}
						else if (buffer->req_type == RequestType::GetAssemblyBase) {
							if (buffer->process_id) {
								PEPROCESS process = { 0 };
								if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)buffer->process_id, &process))) {
									UNICODE_STRING DLLName;
									RtlInitUnicodeString(&DLLName, EW(L"GameAssembly.dll"));
									buffer->out_base_addr = utils::return_DLL_base_addr(process, DLLName);
									ObfDereferenceObject(process);
								}
							}
						}
						else if (buffer->req_type == RequestType::ReadMemory) {
							PEPROCESS process = { 0 };

							if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)buffer->process_id, &process))) {

								utils::read_write_mem(process, (PVOID)buffer->ProcessAddress, IoGetCurrentProcess(), (PVOID)buffer->OutBuffer, buffer->Length);

								ObfDereferenceObject(process);
							}
						}
						else if (buffer->req_type == RequestType::WriteMemory) {
							PEPROCESS process = { 0 };

							if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)buffer->process_id, &process))) {

								utils::read_write_mem(IoGetCurrentProcess(), (PVOID)buffer->InBuffer, process, (PVOID)buffer->ProcessAddress, buffer->Length);

								ObfDereferenceObject(process);
							}
						}
					}
				}

				irp->IoStatus.Status = STATUS_SUCCESS;
				irp->IoStatus.Information = sizeof(Communication);

				IofCompleteRequest(irp, IO_NO_INCREMENT);

				return STATUS_SUCCESS;
			}
		}
	}
	
	return acpi_original_device_control(device_object, irp);
}

NTSTATUS DriverEntry() {
	PVOID					function_found			=		{ 0 };
	PDRIVER_OBJECT			acpi_driver_object		=		{ 0 };
	UNICODE_STRING			acpi_driver_name		=		{ 0 };

	RtlInitUnicodeString(&acpi_driver_name, EW(L"\\Driver\\acpi"));

	if (!NT_SUCCESS(
		ObReferenceObjectByName(
			&acpi_driver_name,
			OBJ_CASE_INSENSITIVE,
			nullptr,
			0,
			*IoDriverObjectType,
			KernelMode,
			nullptr,
			(PVOID*)&acpi_driver_object))
	) {
		return STATUS_UNSUCCESSFUL;
	}

	if (!acpi_driver_object->DriverStart)
		return STATUS_UNSUCCESSFUL;

	// 2004
	if (!function_found)
		function_found = utils::find_pattern_image(acpi_driver_object->DriverStart, E("\x48\x8B\x05\x4B\xE5\x04\x00\x44\x8B\xCD\x4C\x8B\x84\x24\x90\x00\x00\x00"), E("xxxxxx?xxxxxxxx???"));

	// 1909
	if (!function_found)
		function_found = utils::find_pattern_image(acpi_driver_object->DriverStart, E("\x48\x8B\x05\xB3\xD9\x04\x00\xFF\x15\xDD\x78\x05\x00\x41\xBB\x08\x00\x00\x00\x4C\x8D\x0D\x40\xD5\x03\x00"), E("xxxxxx?xxxxx?xxx???xxxxxx?"));

	// 1903
	if (!function_found)
		function_found = utils::find_pattern_image(acpi_driver_object->DriverStart, E("\x48\x8B\x05\xAC\x02\x05\x00\x4C\x89\x8C\x24\x88\x00\x00\x00\x41\xB9\x08\x00"), E("xxxxxx?xxxxx???xxx?"));

	if (!function_found)
		return STATUS_UNSUCCESSFUL;

	function_found = relative_address(function_found, 7);

	{
		_disable();
		auto cr0 = __readcr0();
		cr0 &= 0xfffffffffffeffff;
		__writecr0(cr0);
	}

	function_found = &hooked_device_control;

	{
		auto cr0 = __readcr0();
		cr0 |= 0x10000;
		__writecr0(cr0);
		_enable();
	}

	*(PVOID*)&acpi_original_device_control = _InterlockedExchangePointer((volatile PVOID*)&acpi_driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL], function_found);

	return STATUS_SUCCESS;
}