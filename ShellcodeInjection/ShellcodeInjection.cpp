// ShellcodeInjection.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//
#include "defs.h"

UINT initializeIatShellcode(kernel32Iat& iat)
{
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    LPVOID baseAddrKernel32 = GetModuleByName(kernel32_dll_name);
    if (!baseAddrKernel32) {
        return 1;
    }
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
    LPVOID get_proc = GetFunctionByName((HMODULE)baseAddrKernel32, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }
    iat._GetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;

    char get_console_window_name[] = { 'G','e','t','C','o','n','s','o','l','e','W','i','n','d','o','w',0 };
    char alloc_console_name[] = { 'A','l','l','o','c','C','o','n','s','o','l','e',0 };
    char set_console_cp_name[] = { 'S','e','t','C','o','n','s','o','l','e','C','P',0 };
    char set_console_output_cp_name[] = { 'S','e','t','C','o','n','s','o','l','e','O','u','t','p','u','t','C','P',0 };
    char set_Thread_UI_language_Name[] = { 'S','e','t','T', 'h', 'r','e','a','d', 'U','I', 'L', 'a','n','g','u','a','g','e', 0 };

    iat._SetConsoleOutputCP = (BOOL(WINAPI * )(UINT))iat._GetProcAddress((HMODULE)baseAddrKernel32, set_console_output_cp_name);
    if (!iat._SetConsoleOutputCP) {
        return 4;
    }
    iat._GetConsoleWindow = (HWND(WINAPI * )()) iat._GetProcAddress((HMODULE)baseAddrKernel32, get_console_window_name);
    if (!iat._GetConsoleWindow) {
        return 5;
    }
    iat._SetConsoleCP = (BOOL(WINAPI * )(UINT))iat._GetProcAddress((HMODULE)baseAddrKernel32, set_console_cp_name);
    if (!iat._SetConsoleCP) {
        return 6;
    }
    iat._AllocConsole = (BOOL(WINAPI* )()) iat._GetProcAddress((HMODULE)baseAddrKernel32, alloc_console_name);
    if (!iat._AllocConsole) {
        return 7;
    }
    iat._SetThreadUILanguage = (LANGID(WINAPI *)(LANGID))iat._GetProcAddress((HMODULE)baseAddrKernel32, set_Thread_UI_language_Name);
    if (!iat._SetThreadUILanguage) {
        return 8;
    }
    return 0;
}

//Fix this payload trigger, it fails!
void SpawnPayload(DWORD* dwCodePageId, kernel32Iat& iat)
{
    DWORD dwCodePageID = *dwCodePageId;
    if (!iat._GetConsoleWindow())
    {
        if (!iat._AllocConsole()) {
            return;
        }
    }
    //Shellcode fails here.
    if (!iat._SetConsoleOutputCP(dwCodePageID)){
        return;
    }
    if (!iat._SetConsoleCP(dwCodePageID)){
        return;
    }
    iat._SetThreadUILanguage(0);
}

//cl /c /FA /GS- ShellcodeInjection.cpp
//Delete xdata and pdata, comment INCLUDELIB LIBCMT and INCLUDELIB OLDNAMES
//ml64 /c ShellcodeInjection.asm /link /entry:AlignRSP

int main(DWORD* dwCodeID)
{
    kernel32Iat iat;
    if (initializeIatShellcode(iat)) {
        return 1;
    }
    SpawnPayload(dwCodeID, iat);

    return 0;   
}