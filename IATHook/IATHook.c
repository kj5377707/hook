#include <stdio.h>
#include <Windows.h>

typedef int (WINAPI* pWriteConsole) (HANDLE hConsoleOutput, const VOID *lpBuffer, 
DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);

int WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
  	WinExec("calc", SW_SHOW);
	return 0;
}

PIMAGE_NT_HEADERS GetLocalNtHead()
{
	DWORD dwTemp = NULL;
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	HMODULE ImageBase = GetModuleHandle(NULL);                              
	pDosHead = (PIMAGE_DOS_HEADER)(DWORD)ImageBase;                         
	dwTemp = (DWORD)pDosHead + (DWORD)pDosHead->e_lfanew;
	pNtHead = (PIMAGE_NT_HEADERS)dwTemp;                                   
	return pNtHead;
}

void IATHook()
{
	PVOID pFuncAddress = NULL;
	pFuncAddress = GetProcAddress(GetModuleHandleA("user32"), "MessageBoxA");  
	OldMessageBoxA = (pfMessageBoxA)pFuncAddress;                                  
	PIMAGE_NT_HEADERS pNtHead = GetLocalNtHead();                                  
	PIMAGE_FILE_HEADER pFileHead = (PIMAGE_FILE_HEADER)&pNtHead->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOpHead = (PIMAGE_OPTIONAL_HEADER)&pNtHead->OptionalHeader;

	DWORD dwInputTable = pOpHead->DataDirectory[1].VirtualAddress;    
	DWORD dwTemp = (DWORD)GetModuleHandle(NULL) + dwInputTable;
	PIMAGE_IMPORT_DESCRIPTOR   pImport = (PIMAGE_IMPORT_DESCRIPTOR)dwTemp;
	PIMAGE_IMPORT_DESCRIPTOR   pCurrent = pImport;
	DWORD *pFirstThunk; 

	while (pCurrent->Characteristics && pCurrent->FirstThunk != NULL)
	{
		dwTemp = pCurrent->FirstThunk + (DWORD)GetModuleHandle(NULL);
		pFirstThunk = (DWORD *)dwTemp;                               
		while (*(DWORD*)pFirstThunk != NULL)                      
		{
			if (*(DWORD*)pFirstThunk == (DWORD)OldMessageBoxA)       
			{
				DWORD oldProtected;
				VirtualProtect(pFirstThunk, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtected);  
				dwTemp = (DWORD)MyMessageBoxA;
				memcpy(pFirstThunk, (DWORD *)&dwTemp, 4);
				VirtualProtect(pFirstThunk, 0x1000, oldProtected, &oldProtected);            
			}
			pFirstThunk++; 
		}
		pCurrent++;        
	}
}

int main() {
	printf("addr before IATHook : %p\n", MessageBox);
	IATHook();
	printf("addr after IATHook : %p\n", MessageBox);
    MessageBoxA(0, "hi", "demo", 0);
	return 0;
}