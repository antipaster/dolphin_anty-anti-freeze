#include <windows.h>
#include <objbase.h>
#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <shellapi.h>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")


static const wchar_t* kRegPath = L"SOFTWARE\\Microsoft\\Cryptography";
static const wchar_t* kRegValue = L"MachineGuid";

std::filesystem::path get_exe_dir()
{
    wchar_t buf[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0) return std::filesystem::current_path();
    std::filesystem::path exePath(buf);
    return exePath.parent_path();
}

std::filesystem::path get_guid_path()
{
    return get_exe_dir() / L"machineguid.txt";
}

std::wstring read_machine_guid()
{
    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0,
                             KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (res != ERROR_SUCCESS)
        return L"";

    DWORD type = 0;
    wchar_t buffer[256] = {0};
    DWORD size = sizeof(buffer);
    res = RegQueryValueExW(hKey, kRegValue, nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size);
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
        return L"";

    return std::wstring(buffer);
}

bool set_machine_guid(const std::wstring& guid)
{
    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0,
                             KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
    if (res != ERROR_SUCCESS)
        return false;

    const DWORD bytes = static_cast<DWORD>((guid.size() + 1) * sizeof(wchar_t));
    res = RegSetValueExW(hKey, kRegValue, 0, REG_SZ,
                         reinterpret_cast<const BYTE*>(guid.c_str()), bytes);
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS;
}

bool save_orig_guid(const std::wstring& guid)
{
    auto path = get_guid_path();
    if (std::filesystem::exists(path))
        return false; // already saved

    std::wofstream ofs(path);
    if (!ofs.is_open())
        return false;
    ofs << guid;
    ofs.close();
    return true;
}

std::wstring load_orig_guid()
{
    auto path = get_guid_path();
    if (!std::filesystem::exists(path))
        return L"";

    std::wifstream ifs(path);
    if (!ifs.is_open())
        return L"";
    std::wstring guid;
    std::getline(ifs, guid);
    ifs.close();
    return guid;
}

std::wstring gen_guid()
{
    GUID g{};
    if (CoCreateGuid(&g) != S_OK)
        return L"";

    wchar_t buf[37]{}; // 36 chars + null
    swprintf(buf, 37, L"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             g.Data1, g.Data2, g.Data3,
             g.Data4[0], g.Data4[1],
             g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return std::wstring(buf);
}

bool is_admin()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

bool relaunch_admin()
{
    wchar_t exePath[MAX_PATH] = {0};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH))
        return false;
    HINSTANCE h = ShellExecuteW(nullptr, L"runas", exePath, nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(h) > 32;
}

void start()
{
    std::wstring current = read_machine_guid();
    if (current.empty()) {
        std::wcout << L"[error] failed to read mg." << std::endl;
        return;
    }

    bool saved = save_orig_guid(current);
    if (saved) {
        std::wcout << L"[saved]  mg written to '" << get_guid_path().wstring() << L"'\n";
    } else {
        std::wcout << L"[info] 'machineguid.txt' already exists." << std::endl;
    }

    std::wstring newGuid = gen_guid();
    if (newGuid.empty()) {
        std::wcout << L"[error] failed to generate a new gd" << std::endl;
        return;
    }

    if (set_machine_guid(newGuid)) {
        std::wcout << L"[success] mg changed to: " << newGuid << std::endl;
    } else {
        std::wcout << L"[error] failed to set mg. run as admin." << std::endl;
    }
}

void restore()
{
    std::wstring original = load_orig_guid();
    if (original.empty()) {
        std::wcout << L"[warn] no mg found." << std::endl;
        return;
    }

    if (set_machine_guid(original)) {
        std::wcout << L"[restored] mg restored to: " << original << std::endl;
    } else {
        std::wcout << L"[error] run as admin." << std::endl;
    }
}

int wmain()
{
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    if (!is_admin()) {
        std::wcout << L"[Info] requesting admin." << std::endl;
        if (relaunch_admin()) {
            std::wcout << L"[Info] exiting." << std::endl;
            CoUninitialize();
            return 0;
        } else {
            std::wcout << L"[error] run as admin." << std::endl;
            CoUninitialize();
            return 1;
        }
    }

    std::wcout << L"DolphinAnty Freeze Bypass" << std::endl;
    std::wcout << L"--------------------------------" << std::endl;
    std::wcout << L"Select an option:" << std::endl;
    std::wcout << L"  [1] Start (randomize mg)" << std::endl;
    std::wcout << L"  [2] Bring back old mg" << std::endl;
    std::wcout << L"> ";

    std::wstring choice;
    std::getline(std::wcin, choice);
    if (choice == L"1") {
        start();
    } else if (choice == L"2") {
        restore();
    } else {
        std::wcout << L"wrong option" << std::endl;
    }

    CoUninitialize();
    return 0;
}
