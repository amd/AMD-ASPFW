; Copyright(C) 2014 Advanced Micro Devices, Inc. All rights reserved.


    IMPORT  sev_uapp_entry
    IMPORT  allocate_stack

	; Linker symbols from scatter file
    IMPORT	||Image$$SEV_UAPP_TEMP_STACK$$ZI$$Base||
	IMPORT	||Image$$SEV_UAPP_TEMP_STACK$$ZI$$Limit||
    IMPORT	||Image$$SEV_UAPP_STACK$$ZI$$Base||
    IMPORT	||Image$$SEV_UAPP_STACK$$ZI$$Limit||
    IMPORT	||Image$$SEV_UAPP_INIT_ONCE$$ZI$$Base||
    IMPORT	||Image$$SEV_UAPP_INIT_ONCE$$ZI$$Limit||

    PRESERVE8
    AREA   STARTUP_DATA, DATA, READWRITE    ; name this block of code
    ENTRY

    AREA   STARTUP_CODE, CODE, READONLY     ; name this block of code

;==============================================================================
; First 256 bytes of the binary image contain the header.
; Executable code starts from offset 0x100.
;==============================================================================
    INCLUDE header.inc


;==============================================================================
; This is entry poit to the binary which is called by main Boot Loader.
;==============================================================================

    EXPORT EntryPoint

EntryPoint

    mov         r4, r0 ; Save r0-r3 (input parameters)
    mov         r5, r1
    mov         r6, r2
    mov         r7, r3
	; Create the zero-initialized memory areas
	mov			r3, #0
    cmp         r7, #1    ; Clear "init_once" area only on first entry
    bne         AllocateStack
    ; In SEV model, BSS is only initialized once.
	ldr			r1, =||Image$$SEV_UAPP_INIT_ONCE$$ZI$$Base||
    ldr			r2, =||Image$$SEV_UAPP_INIT_ONCE$$ZI$$Limit||
	bl			zi_init

    ; Map SEV UAPP stack to separate Virtual Address so that stack overflow cause
    ; exception instead of data corruption.
    ;
AllocateStack
    ldr			sp, =||Image$$SEV_UAPP_TEMP_STACK$$ZI$$Limit||       ; temporary stack pointer
    ldr			r2, =allocate_stack
    blx			r2
    ; Return value contains Virtual Address of mapped stack
    ;
    mov			sp, r0                  ; set sev user app stack pointer
    ldr			lr, =ShouldNotBeReached ; return address
    ldr			r12, =sev_uapp_entry    ; pass control to sev user app main function
    mov			r0, r4                  ; Restore r0-r3 input parameters
    mov			r1, r5
    mov			r2, r6
    mov			r3, r7
    blx			r12

; This point should not be reached. The sev_uapp_entry() function should return
; to main BL using Svc_Exit().
;
ShouldNotBeReached
    b           .

;==============================================================================
; zi_init is a subroutine which initializes a region, starting at the
; address in r1, to a value held in r3. The address of the word beyond
; the end of this region is held in r2
;==============================================================================

zi_init

	cmp		r1, r2
	strcc	r3, [r1], #4
	bcc		zi_init
	bx		lr			; return to caller

    END
