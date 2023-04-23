#include <Windows.h>
#include <Urlmon.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <comdef.h>
#include <Shlobj.h>
#pragma comment(lib, "urlmon.lib")

bool DownloadDllFromUrlAndInject(const char* url, const wchar_t* filePath, const wchar_t* processName) {
    HRESULT hr = URLDownloadToFile(NULL, _bstr_t(url), filePath, 0, NULL);
    if (hr != S_OK) {
        _com_error error(hr);
        LPCTSTR errorMessage = error.ErrorMessage();
        std::wcout << L"Failed to download the DLL. Error: " << errorMessage << L" (0x" << std::hex << hr << L")\n";
        return false;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    DWORD processId = 0;
    for (BOOL hasData = Process32First(hSnapshot, &pe); hasData; hasData = Process32Next(hSnapshot, &pe)) {
        if (wcscmp(pe.szExeFile, processName) == 0) {
            processId = pe.th32ProcessID;
            break;
        }
    }
    CloseHandle(hSnapshot);
    if (processId == 0) return false;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return false;

    size_t dllPathSize = (wcslen(filePath) + 1) * sizeof(wchar_t);
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!WriteProcessMemory(hProcess, pDllPath, filePath, dllPathSize, NULL)) {
        VirtualFreeEx(hProcess, pDllPath, dllPathSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibraryW = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, LPTHREAD_START_ROUTINE(pLoadLibraryW), pDllPath, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pDllPath, dllPathSize, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

int main() {
    const char* url = "https://github.com/whoskanji/ReverieYUHR/releases/download/2.0/Reverie.dll";

    char userProfile[MAX_PATH];
    size_t len;
    getenv_s(&len, userProfile, MAX_PATH, "USERPROFILE");
    std::string folderPathStr = std::string(userProfile) + "\\Documents\\Reverie";
    std::wstring folderPath(folderPathStr.begin(), folderPathStr.end());

    // Create the "Reverie" folder if it doesn't exist
    SHCreateDirectoryEx(NULL, folderPath.c_str(), NULL);

    std::string filePathStr = folderPathStr + "\\Reverie.dll";
    std::wstring filePath(filePathStr.begin(), filePathStr.end());

    const wchar_t* processName = L"GTA5.exe";

    if (!DownloadDllFromUrlAndInject(url, filePath.c_str(), processName)) {
        std::cout << "Failed to download the DLL and inject it into the process." << std::endl;
        return 1;
    }

    std::cout << "Successfully injected the DLL into the process." << std::endl;
    return 0;
}
