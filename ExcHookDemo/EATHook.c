#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <Shlwapi.h>



BOOL EATHook(LPCTSTR szDllName, LPCTSTR szFunName, LPVOID NewFun)
{
  DWORD addr = 0, index = 0, dwProtect = 0;

  HMODULE DllBase = LoadLibrary(szDllName);
  if (NULL == DllBase)
  {
    return(FALSE);
  }

  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)DllBase;
  PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
  PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);

  PIMAGE_EXPORT_DIRECTORY pExpDes = (PIMAGE_EXPORT_DIRECTORY)
    ((PBYTE)DllBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  PULONG pAddressOfFunctions = (PULONG)((PBYTE)DllBase + pExpDes->AddressOfFunctions);
  PULONG pAddressOfNames = (PULONG)((PBYTE)DllBase + pExpDes->AddressOfNames);
  PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)DllBase + pExpDes->AddressOfNameOrdinals);

  for (int i = 0; i < pExpDes->NumberOfNames; ++i)
  {
    index = pAddressOfNameOrdinals[i];

    LPCTSTR pFuncName = (LPTSTR)((PBYTE)DllBase + pAddressOfNames[i]);

    if (!_tcscmp((LPCTSTR)pFuncName, szFunName))
    {
      addr = pAddressOfFunctions[index];
      break;
    }
  }

  VirtualProtect(&pAddressOfFunctions[index], 0x1000, PAGE_READWRITE, &dwProtect);

  pAddressOfFunctions[index] = (DWORD)NewFun - (DWORD)DllBase;

  WriteProcessMemory(GetCurrentProcess(), &pAddressOfFunctions[index],
    (LPCVOID)((DWORD)NewFun - (DWORD)DllBase), sizeof(NewFun), &dwProtect);
  return(TRUE);
}

int WINAPI MyMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
  ShellExecute(NULL, "open", "calc", NULL, NULL, SW_SHOWNORMAL);
  return 0;
}

typedef int (WINAPI* LPFNMESSAGEBOX)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

int main(int argc, char *argv[])

{
  LoadLibrary("kernel32.dll");
  HMODULE hDll = GetModuleHandle("kernel32.dll");
  size_t kernelBase = GetModHandle(L"kernel32.dll");
	size_t ptr_WinExec = (size_t)GetFuncAddr(kernelBase, "WinExec");
	((UINT(WINAPI*)(LPCSTR, UINT))ptr_WinExec)("calc", SW_SHOW);
  EATHook("kernel32.dll", "WinExec", MyMessageBox);

  FARPROC lpMessageBox = (LPFNMESSAGEBOX)GetProcAddress(hDll, "MessageBoxA");
  printf("addr after EATHook : %p\n", lpMessageBox);
  lpMessageBox(NULL, "Hello, EAT Hook", "Info", MB_OK);

  system("pause");
  return(0);
}
