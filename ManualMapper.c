//tool made by b4shcr00k


#include <stdio.h>
#include <Windows.h>

//macros i like to use
#define okay(msg , ...) printf("[+] "msg"\n",##__VA_ARGS__)
#define error(msg , ...) printf("[-] "msg"\n",##__VA_ARGS__)
#define warn(msg , ...) printf("[!] "msg"\n",##__VA_ARGS__)
#define input(msg , ...) printf("[->] "msg" > ",##__VA_ARGS__)
#define debug(msg , ...) printf("[DEBUG] "msg"\n",##__VA_ARGS__)
#define PAGE_SIZE 0x1000

//pe headers 
PIMAGE_DOS_HEADER dosHeader;
PIMAGE_NT_HEADERS ntHeader;
PIMAGE_SECTION_HEADER sectionHeader;
PIMAGE_OPTIONAL_HEADER optionalHeader;
PIMAGE_FILE_HEADER fileHeader;

//important winapi functions we will need
typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);
typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

//struct to hold all important data we need to pass to the stub
typedef struct loaderData
{
    LPVOID ImageBase;

    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;

} loaderData;

//stub and stubend functions 
DWORD __stdcall loader(loaderData* loaderParams);
void stubFunction();

//function to open the dll 
BYTE* OpenDll(char* dllPath) {
    BYTE* pSrcDllData = NULL;
    FILE* pFile = NULL;
    long fileSize = 0;

    pFile = fopen(dllPath, "rb");
    if (pFile == NULL) {
        error("Failed To Open File");
        return FALSE;
    }
    else
    {
        okay("File Opened");
    }

    // getting the file size (classic c moment)
    fseek(pFile, 0, SEEK_END);
    fileSize = ftell(pFile);
    fseek(pFile, 0, SEEK_SET);

    // if there is nothing except PE headers
    if (fileSize < PAGE_SIZE) {
        error("Invalid Pe File");

        fclose(pFile);
        return FALSE;
    }

    // reading the dll file into memory for analysis
    pSrcDllData = (BYTE*)malloc(fileSize * sizeof(BYTE));
    if (pSrcDllData == NULL) {
        error("Failed To Allocate Space For The Dll In The Current Process");

        fclose(pFile);
        return FALSE;
    }

    if (!fread(pSrcDllData, 1, fileSize, pFile)) {
        error("Failed To Read The Dll Into Current Process Memory");

        free(pSrcDllData);
        fclose(pFile);
        return FALSE;
    }
    else
    {
        okay("Dll Written Into Current Process Memory");
    }

    fclose(pFile);
    return pSrcDllData;
}

//function to get a handle to the target process

HANDLE OpenTargetProcess(int PID)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess)
    {
        error("Failed To Get Handle To Process");
        CloseHandle(hProcess);
    }
    else
    {
        okay("Got Handle To Process");
    }


    return hProcess;
}
//functions that maps the dll into the target process
void ManualMapper(BYTE* dllBuffer,HANDLE hProcess)
{
   
    dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
    if (dosHeader->e_magic != 0x00005a4d)
    {
        error("Couldn't Find Dos Header");
        CloseHandle(hProcess);
    }
    else
    {
        okay("Dos Header Found");
    }

    ntHeader = (PIMAGE_NT_HEADERS)(dllBuffer + dosHeader->e_lfanew); 
    PIMAGE_OPTIONAL_HEADER optHeader = &ntHeader->OptionalHeader;
    PIMAGE_FILE_HEADER fileHeader = &ntHeader->FileHeader;
    BYTE* remoteBase = (BYTE*)VirtualAllocEx(hProcess, (void*)optHeader->ImageBase, optHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBase == NULL)
    {
        BYTE* remoteBase = (BYTE*)VirtualAllocEx(hProcess, NULL, optHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remoteBase == NULL)
        {
            error("Failed To Allocate Space In Target Process");
            CloseHandle(hProcess);
        }
        else
        {
            okay("Allocated Space In Target Process");
        }
    }
    else
    {
        okay("Allocated Space In Target Process");
    }
    if (!WriteProcessMemory(hProcess,remoteBase,dllBuffer, optHeader->SizeOfHeaders,NULL))
    {
        error("Failed To Write Headers Into Target Process");
        CloseHandle(hProcess);
    }
    else
    {
        okay("Headers Written Into Target Process");
    }
   sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
   for (int i = 0; i != fileHeader->NumberOfSections; i++, sectionHeader++) {
       if (!WriteProcessMemory(hProcess, remoteBase + sectionHeader->VirtualAddress, dllBuffer + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, NULL)) {
           error("Failed To Write Sections Into Target Process");

           VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
           CloseHandle(hProcess);
           
       }

   }
   okay("Sections Written Into Target Process");
   loaderData data;
   data.fnGetProcAddress = GetProcAddress;
   data.fnLoadLibraryA = LoadLibraryA;
   data.ImageBase = remoteBase;
   data.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(remoteBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
   data.BaseReloc = (PIMAGE_BASE_RELOCATION)(remoteBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
   data.NtHeaders = (PIMAGE_NT_HEADERS)(remoteBase + dosHeader->e_lfanew);
   unsigned int stubsize = 0;
   stubsize = (unsigned int)stubFunction - (unsigned int)loader;
   BYTE* stubAddress = VirtualAllocEx(hProcess, NULL, stubsize + sizeof(loaderData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
   if (stubAddress == NULL)
   {
       error("Failed To Allocate Space For The Stub %d %p %d %d",GetLastError(),hProcess,stubsize,sizeof(loaderData));
       VirtualFreeEx(hProcess, stubAddress, 0, MEM_RELEASE);
       VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
       CloseHandle(hProcess);
   }
   else
   {
       okay("Space Allocated For The Stub");
   }
   //We Write The Data First Then The Stub
   
   if (!WriteProcessMemory(hProcess, stubAddress, &data, sizeof(loaderData), NULL))
   {
       error("Failed To Write The Stub Data");
   }
   
   if (!WriteProcessMemory(hProcess, (void*)((loaderData*)stubAddress + 1), loader, stubsize, NULL))
   {
       error("Failed To Write The Stub");
   }
   else
   {
       okay("Stub And Params Written Into The Target Process");
   }
   HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderData*)stubAddress + 1), stubAddress, 0, NULL);
   if (hThread == NULL)
   {
       error("Failed To Create Remote Thread");
       VirtualFreeEx(hProcess, stubAddress, 0, MEM_RELEASE);
       VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
       CloseHandle(hThread);
       CloseHandle(hProcess);
   }
   else
   {
       okay("Stub Remote Thread Created");
   }
   WaitForSingleObject(hThread, INFINITE);
   VirtualFreeEx(hProcess, stubAddress, 0, MEM_RELEASE);
   VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
   CloseHandle(hThread);
   CloseHandle(hProcess);
}




//stub that resolves the imports and preform base relocations
DWORD __stdcall loader(loaderData *data) 
{
    PIMAGE_THUNK_DATA FirstThunk = NULL;
    PIMAGE_THUNK_DATA OriginalFirstThunk = NULL;
    PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
    HMODULE hMod;
    void* modFunc;
    dllmain entryPointOfDll = 0;

    DWORD delta = (DWORD)((LPBYTE)data->ImageBase - data->NtHeaders->OptionalHeader.ImageBase);
    if (delta) {
        if (data->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            while (data->BaseReloc->VirtualAddress) {
      
                if (data->BaseReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {

                    DWORD amountOfEntries = (data->BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    PWORD pRelativeRelocInfo = (PWORD)(data->BaseReloc + 1); // gets the entry info (offset + type)

                    for (int i = 0; i < amountOfEntries; i++) {
                        if (pRelativeRelocInfo[i]) {
                            
                            PDWORD pRva = (PDWORD)((LPBYTE)data->ImageBase + data->BaseReloc->VirtualAddress + (pRelativeRelocInfo[i] & 0xFFF));
                            *pRva += delta;
                        }
                    }
                }
                data->BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)data->BaseReloc + data->BaseReloc->SizeOfBlock);
            }
        }
    }

    while (data->ImportDirectory->Characteristics) {
        OriginalFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)data->ImageBase + data->ImportDirectory->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)data->ImageBase + data->ImportDirectory->FirstThunk);

        hMod = data->fnLoadLibraryA((LPCSTR)data->ImageBase + data->ImportDirectory->Name);
        if (!hMod) {
            return FALSE;
        }

        while (OriginalFirstThunk->u1.AddressOfData) {
            if (OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                modFunc = (void*)data->fnGetProcAddress(hMod, (LPCSTR)(OriginalFirstThunk->u1.Ordinal & 0xFFFF));
            }
            else {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)data->ImageBase + OriginalFirstThunk->u1.AddressOfData);
                modFunc = (void*)data->fnGetProcAddress(hMod, (LPCSTR)pImportByName->Name);
            }

            if (!modFunc) {
                return FALSE;
            }
            FirstThunk->u1.Function = modFunc;

            OriginalFirstThunk++;
            FirstThunk++;
        }
        data->ImportDirectory++;
    }

    if (data->NtHeaders->OptionalHeader.AddressOfEntryPoint) {
        entryPointOfDll = (dllmain)((LPBYTE)data->ImageBase + data->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        entryPointOfDll((HMODULE)data->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }
}
void stubFunction() {} // Acts as an end marker





int main()
{
    okay("Tool Written By B4shCr00k \n///// Manual Mapping Dll Injection POC ///// \nPress Enter To Continue");
    getchar();
    int PID;
    char path[MAX_PATH];
    input("PID");
    scanf_s("%d", &PID);
    getchar();
    input("PATH");
    fgets(path, MAX_PATH, stdin);
    path[strcspn(path, "\n")] = 0;
    BYTE* hFile = OpenDll(path);
    if (hFile == FALSE)
    {
        error("Invalid File Handle");
        return 1;
    }
    HANDLE hProcess = OpenTargetProcess(PID);
    if (hProcess == NULL)
    {
        error("Invalid Process Handle");
        return 1;
    }
    ManualMapper(hFile,hProcess);
    getchar();
    return 0;
}
