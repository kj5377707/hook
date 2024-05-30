#include<windows.h>
#include <stdio.h>

int main() {
    FARPROC IATAddr = (FARPROC) MessageBoxA;
    FARPROC EATAddr = GetProcAddress(GetModuleHandle("user32"), "MessageBoxA");
    printf("%p, %p", IATAddr, EATAddr);
    return 0;
}