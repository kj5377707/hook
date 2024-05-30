#include <Windows.h>
#include <stdio.h>

SYSTEM_INFO system_info;
PVOID handle;
struct hookInfo {
    void* source;
    void* destination;
    struct hookInfo* next;

};

typedef int (WINAPI* pWriteConsole) (HANDLE hConsoleOutput, const VOID *lpBuffer, 
DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);

int WINAPI myWriteConsoleA(HANDLE hConsoleOutput, const VOID *lpBuffer, 
DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved) {
	WinExec("calc", SW_SHOW);
	return 0;
}

int WINAPI myMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
  WinExec("calc", SW_SHOW);
  return 0;
}


struct hookInfo* first = NULL;

LONG exceptionHandler(EXCEPTION_POINTERS* exceptionInfo) {
    struct hookInfo* now = first;
    if (exceptionInfo -> ExceptionRecord -> ExceptionCode == EXCEPTION_GUARD_PAGE) {
        do {
            if (exceptionInfo -> ExceptionRecord -> ExceptionAddress == now -> source) {
                exceptionInfo -> ContextRecord -> Eip = (DWORD) now -> destination;
            }
        }while (now -> next != NULL);

        exceptionInfo -> ContextRecord -> EFlags |= PAGE_GUARD; // 0x100
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (exceptionInfo -> ExceptionRecord -> ExceptionCode == EXCEPTION_SINGLE_STEP) {
        while (now -> next != NULL) {
            DWORD tmp;
            VirtualProtect(now -> source, system_info.dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &tmp);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


struct hookInfo* createNode(void* source, void* destination) {
    struct hookInfo* newNode = (struct hookInfo*)malloc(sizeof(struct hookInfo));
    if (newNode == NULL) {
        printf("Memory allocation failed.\n");
        exit(1);
    }
    newNode-> source = source;
    newNode->destination = destination;
    newNode->next = NULL;
    return newNode;
}

void appendNode(struct hookInfo** headRef, void* source, void* destination) {
    struct hookInfo* newNode = createNode(source, destination);
    if (*headRef == NULL) {
        *headRef = newNode;
        return;
    }
    struct hookInfo* current = *headRef;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = newNode;
}


BOOL Hook(void* source, void* destination) {
    if (!handle) return FALSE;
    MEMORY_BASIC_INFORMATION source_info;
    if (!VirtualQuery(source, &source_info, sizeof(MEMORY_BASIC_INFORMATION)))
        return FALSE;

    MEMORY_BASIC_INFORMATION destination_info;
    if (!VirtualQuery(destination, &destination_info, sizeof(MEMORY_BASIC_INFORMATION)))
        return FALSE;

    if (source_info.AllocationBase == destination_info.AllocationBase)
        return FALSE;

    appendNode(&first, source, destination);
    DWORD tmp;
    VirtualProtect(source, system_info.dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &tmp);
    return TRUE;
}


void setupHandler() {
    GetSystemInfo(&system_info);
    handle = AddVectoredExceptionHandler(1, exceptionHandler);
}

#define OFFSET 0x1fA380 // offset of WriteConsoleA

int main() {
    setupHandler();
    HMODULE hlib = GetModuleHandle("kernelbase.dll");
    FARPROC addr = GetProcAddress(hlib, "WriteConsoleA");

    Hook(WriteConsoleA, myWriteConsoleA);
    pWriteConsole APIAddr = (pWriteConsole)((DWORD_PTR) hlib + OFFSET);
	HANDLE handle = GetStdHandle(-11);
	APIAddr(handle, "can't hook this", 16, NULL, NULL);
    WriteConsoleA(handle, "hi", 2, NULL, NULL);
    return 0;
}