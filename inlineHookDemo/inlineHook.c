#include <windows.h>

#define HOOK_JUMP_LEN 5

HANDLE handle = NULL;
void *origin = NULL;
char replaceIns[HOOK_JUMP_LEN];
char oldIns[HOOK_JUMP_LEN];
void *antiAddr = NULL;

void reHook() {
    WriteProcessMemory(GetCurrentProcess(), origin, replaceIns, HOOK_JUMP_LEN, NULL);
}

void doHook() {
    reHook();
}

void unHook() {
    WriteProcessMemory(GetCurrentProcess(), origin, oldIns, HOOK_JUMP_LEN, NULL);
} 

BOOL WINAPI hookWriteConsoleA(HANDLE hConsoleOutput, CONST VOID *lpBuffer,
    DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved) 
{
    unHook();
    char buf[128];
    strcpy(buf, (char *)lpBuffer);
    buf[nNumberOfCharsToWrite - 1] = '\0';
    strcat(buf, "\t[hook]\n");
    int len = nNumberOfCharsToWrite + 8;
    BOOL result = WriteConsoleA(hConsoleOutput, buf, len, NULL, NULL);
    reHook();
    return result;
}

void initHook() {
    HMODULE hmodule = GetModuleHandleA("kernelbase.dll");
    origin = (void *)GetProcAddress(hmodule, "WriteConsoleA");
    VirtualProtect(origin, HOOK_JUMP_LEN, PAGE_EXECUTE_READWRITE, NULL);
    replaceIns[0] = 0xE9;
    *(long *)&replaceIns[1] = (BYTE *)hookWriteConsoleA - (BYTE *)origin - 5;
    memcpy(&oldIns, origin, HOOK_JUMP_LEN);
}

boolean detect() {
    antiAddr = (void*)GetProcAddress(GetModuleHandleA("kernelbase"), "WriteConsoleA");

    if (*(char*)antiAddr == '\xe9') { 
       return TRUE;
    } 
    return FALSE;
}

int main() {
    initHook();
    doHook();
    if (detect()) {
        WinExec("calc", SW_SHOW);
        return 0;
    }
    handle = GetStdHandle(-11);
    WriteConsoleA(handle, "demo\n", 5, NULL, NULL);
    unHook();
    return 0;
}
