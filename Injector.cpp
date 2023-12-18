#include <iostream>
#include <vector>
#include <format>
#include "Header.h"
#include <TlHelp32.h>
#include <stdlib.h>
#include <windows.h>
#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <string>

DWORD GetProcessID(const char* UygulamaIsim) {

    DWORD ProcessId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 ProcessEntry;
        ProcessEntry.dwSize = sizeof(ProcessEntry);

        if (Process32First(hSnap, &ProcessEntry)) {
            do
            {

                if (!_strcmpi((ProcessEntry.szExeFile), UygulamaIsim))
                {
                    ProcessId = ProcessEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &ProcessEntry));
        }
    }
    CloseHandle(hSnap);
    return ProcessId;
}

//

#ifdef _WIN64
static constexpr const auto PEB_OFFSET = 0x60;
#else
static constexpr const auto PEB_OFFSET = 0x30;
#endif

//


BOOL write(DWORD processid, char* dllpath);
DWORD getprocessid();
BOOL exists(char* dll);

//

int main(int argc, char** argv)
{

    char* dllpath = argv[1];
    if (exists(dllpath)) {
        write(getprocessid(), dllpath);
        Sleep(5000);
        exit(0);
        return 0;
    }
    else {
        std::cout << "bro tf, dll is not available here" << dllpath << std::endl;
        Sleep(5000);
        exit(EXIT_FAILURE);
        return EXIT_FAILURE;
    }
    return -1;
}

BOOL exists(char* dll) {
    std::ifstream file(dll);
    return file.good();
}

DWORD getprocessid()
{
    std::string exename;

    std::cout << "exe name : ";

    std::cin >> exename;

    DWORD ProcessID = GetProcessID(exename.c_str());
    return ProcessID;
}

BOOL write(DWORD processid, char* dllpath)
{
    HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, false, processid);
    if (Process)
    {
        LPVOID LoadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        LPVOID VALLEX = VirtualAllocEx(Process, NULL, strlen(dllpath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(Process, VALLEX, dllpath, strlen(dllpath), NULL);
        HANDLE Thread = CreateRemoteThread(Process, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLib, VALLEX, 0, NULL);
        WaitForSingleObject(Thread, INFINITE);
        VirtualFreeEx(Process, VALLEX, strlen(dllpath), MEM_RELEASE);
        CloseHandle(Thread);
        CloseHandle(Process);
        std::cout << "injected" << std::endl;
        return true;
    }
    return false;
}
