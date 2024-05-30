#include <windows.h>

#define OFFSET 0x1fA380

typedef int (WINAPI* pWriteConsole) (HANDLE hConsoleOutput, const VOID *lpBuffer, 
DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);

int main() {
    HMODULE hlib = GetModuleHandle("kernelbase.dll");
    FARPROC APIAddr = (pWriteConsole)((DWORD_PTR) hlib + OFFSET);
    FARPROC other = GetProcAddress(hlib, "WriteConsoleA");
    printf("is %p equal to %p?\n", APIAddr, other);
    return 0;
}