#include <Windows.h>
#include <string>

using namespace std;

PVOID g_AddrofMessageBoxA; //MessageBoxA函数的地址
BYTE AddrMessageBoxA_Old; //保存之前的值
ULONG g_jmpBackAddr = 0;

_declspec(naked) int WINAPI OriginalMessageBox()
{
	_asm
	{
		//写入的int 3指令破坏了原来的指令，因此在这里执行原函数的指令
		mov edi, edi
		jmp g_jmpBackAddr  //跳回原函数被Hook指令之后的位置，绕过自己安装的Hook
	}
}

//安装Hook--int 3
void HookMessageBoxA()
{
	PBYTE AddrMessageBoxA = (PBYTE)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
	g_AddrofMessageBoxA = AddrMessageBoxA;
	//保存之前的值
	AddrMessageBoxA_Old = (BYTE)*AddrMessageBoxA;
	printf("address = %hhx\n", AddrMessageBoxA_Old);
	g_jmpBackAddr = (ULONG)g_AddrofMessageBoxA + 2; //之前指令2个字节
	printf("%x\n", g_jmpBackAddr);

	//向原函数添加跳转到DetourFun的jmp
	BYTE newEntry[1] = { 0 };
	newEntry[0] = 0xcc; //int 3 的机器码 ，此处MessageBox第一行指令占2个字节最后加个nop
	//修改MessageBoxA函数开头，写入我们的 int 3
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	VirtualQuery(AddrMessageBoxA, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi.BaseAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(AddrMessageBoxA, newEntry, 1);   //写入int 3指令的机器码
	VirtualProtect(mbi.BaseAddress, 5, dwOldProtect, &dwOldProtect);


	/*
	VirtualProtect((void*)AddrMessageBoxA, MAX_PATH,dwOldProtect,&dwOldProtect);
	*(BYTE*)(AddrMessageBoxA)=0xcc;
	VirtualProtect((void*)AddrMessageBoxA, MAX_PATH,dwOldProtect,&dwOldProtect);
	*/
}


//要实现的这个VectoredHandler函数，在捕获异常后，会通过异常代码和发生异常的地址来
//判断这里是不是预先埋伏的断点
LONG WINAPI VectoredHandlerNew(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	char szNewMsg[1024] = { 0 };
	LONG lResult = EXCEPTION_CONTINUE_SEARCH;  //在不处理该异常时默认的返回值 继续执行
	PEXCEPTION_RECORD pPexceptionRecord = ExceptionInfo->ExceptionRecord;
	PCONTEXT pContextRecord = ExceptionInfo->ContextRecord;
	int ret = 0;
	ULONG_PTR* uESP = 0;
	PVOID g_Trampoline;
	DWORD EFlags = 0;

	g_Trampoline = pPexceptionRecord->ExceptionAddress;
	printf("进入VectoredHandlerNew函数\n");
	printf("Exception Address = %p\n", pPexceptionRecord->ExceptionAddress);

	//判断异常的类型和异常发生时的Eip
	if (pPexceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT && pPexceptionRecord->ExceptionAddress == g_AddrofMessageBoxA)
	{
		printf("int 3 BreakPoint Hited.\n");     //中断命中

#ifdef _WIN64

		//在x64下函数调用的前4个参数总是放在寄存器中传递，剩余的参数则压入堆栈中。
		//在x64中，前4个参数依次RCX、RDX、R8、R9 ,按照参数表声明的顺序，从左向右，前4个参数依次放入RCX,RDX,R8,R9中。
		printf("lpText = 0x%p   %s\n", pContextRecord->Rdx, (char*)pContextRecord->Rdx);

		//Rip x64体系
		pContextRecord->Rdx = (ULONG_PTR)szNewMsg;
		pContextRecord->Rip = (ULONG_PTR)g_Trampoline; //跳转到Trampoline继续执行

#else
		//86体系,会将函数参数放入栈中
		//修改参数
		printf("ESP = 0x%p\n", pContextRecord->Esp);
		uESP = (ULONG_PTR*)pContextRecord->Esp;
		lstrcpyA(szNewMsg, (LPSTR)uESP[2]); //移动2个字节是函数第二个参数
		lstrcatA(szNewMsg, "\n\n    Hacked by VectoredHandler.");
		uESP[2] = (ULONG_PTR)szNewMsg;
		pContextRecord->Eip = (ULONG_PTR)OriginalMessageBox;

#endif
		lResult = EXCEPTION_CONTINUE_EXECUTION;
	}
	return lResult;
}

//安装Hook
void InstallHook()
{
	AddVectoredExceptionHandler(0, VectoredHandlerNew);
	HookMessageBoxA();
}


int main(int argc, char* argv[])
{

	MessageBoxA(NULL, "zhongchang", "Test", MB_OK);

	InstallHook();

	MessageBoxA(NULL, "zhongchang", "Test", MB_OK);

	MessageBoxA(NULL, "zhongchang22222", "Test", MB_OK);

	return 0;
}