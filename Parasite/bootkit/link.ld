SECTIONS
{
	.text.mbr 0:
	{
		build/mbr16.obj(.text)
	}
	.text.idt 0x200:
	{
		build/idt32.obj(.text)
		build/idt64.obj(.text)
	}
}