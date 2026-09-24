#include <winsock2.h> 
#include <windows.h>


#include <iphlpapi.h>
#include <ws2tcpip.h>





#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <vector>
#include <sstream>
#include <lm.h> 
#include <cstring>



#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;



std::string WCharToString(const wchar_t* wstr) {
    if (wstr == nullptr || *wstr == L'\0')
        return {};

    int required = WideCharToMultiByte(
        CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr
    );

    if (required <= 1)
        return {};

    std::string result(static_cast<size_t>(required), '\0');

    int written = WideCharToMultiByte(
        CP_UTF8, 0, wstr, -1, result.data(), required, nullptr, nullptr
    );

    if (written == 0)
        return {};

    result.resize(static_cast<size_t>(written - 1)); // حذف null terminator
    return result;
}

string getTimestampedFilename() {
    time_t now = time(0);
    tm *ltm = localtime(&now);
    stringstream ss;
    ss << "Security_Audit_Report_" << 1900 + ltm->tm_year << ltm->tm_mon + 1 << ltm->tm_mday << ".txt";
    return ss.str();
}

void scanLocalPorts(ofstream& report) {
    report << "\n[+] Scanning Common Local Ports...\n";
    int commonPorts[] = {21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389};
    
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    for (int port : commonPorts) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;

        sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr("127.0.0.1");
        server.sin_port = htons(port);

        DWORD timeout = 100; 
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        if (connect(s, (sockaddr*)&server, sizeof(server)) == 0) {
            report << "    [!] Port " << port << " is OPEN\n";
        }
        closesocket(s);
    }
    WSACleanup();
}

void enumerateUsers(ofstream& report) {
    report << "\n[+] Enumerating System Users...\n";
    USER_INFO_1* pBuf = NULL;
    DWORD dwEntries = 0;
    DWORD dwNeeded = 0;
    DWORD dwResumeHandle = 0;

    NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntries, &dwNeeded, &dwResumeHandle);

    if (nStatus == NERR_Success) {
        for (DWORD i = 0; i < dwEntries; i++) {
            string userName = WCharToString(pBuf[i].usri1_name);
            report << "    User: " << userName << " | Privileges: " 
                   << (pBuf[i].usri1_priv == USER_PRIV_ADMIN ? "Administrator" : "Standard User") << "\n";
        }
        NetApiBufferFree(pBuf);
    } else {
        report << "    [!] Could not enumerate users. Error Code: " << nStatus << "\n";
    }
}

void checkRegistrySecurity(ofstream& report) {
    report << "\n[+] Checking Registry Security Settings...\n";

    HKEY hKey;
    // Check UAC
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD uac = 0; DWORD size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "EnableLUA", NULL, NULL, (LPBYTE)&uac, &size) == ERROR_SUCCESS) {
            report << "    UAC (EnableLUA): " << (uac == 1 ? "ENABLED" : "DISABLED (VULNERABLE)") << "\n";
        }
        RegCloseKey(hKey);
    }

    // Check Credential Guard
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD lsa = 0; DWORD size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "LsaCfgFlags", NULL, NULL, (LPBYTE)&lsa, &size) == ERROR_SUCCESS) {
            report << "    Credential Guard: " << (lsa > 0 ? "ENABLED" : "DISABLED (VULNERABLE)") << "\n";
        } else {
            report << "    Credential Guard: NOT FOUND/DISABLED\n";
        }
        RegCloseKey(hKey);
    }
}



//using RtlGetVersionFn = LONG (WINAPI*)(OSVERSIONINFOW*);



std::string GetComputerNameText() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (!GetComputerNameW(buffer, &size))
        return "Unavailable";

    return WCharToString(buffer);
}

std::string GetWindowsVersionText() {
   
    using RtlGetVersionFn = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return "Unavailable";

    auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion")
    );

    if (!rtlGetVersion)
        return "Unavailable";

    RTL_OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);

    if (rtlGetVersion(&version) != 0)
        return "Unavailable";

    std::ostringstream out;
    out << version.dwMajorVersion << '.'
        << version.dwMinorVersion
        << " (Build " << version.dwBuildNumber << ')';

    return out.str();
}






std::string GetProcessNameByPid(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!process)
        return "Access denied or unavailable";

    wchar_t path[MAX_PATH];
    DWORD pathSize = MAX_PATH;

    std::string result = "Unknown";

    if (QueryFullProcessImageNameW(process, 0, path, &pathSize)) {
    
        
        const wchar_t* filename = path;
        for (const wchar_t* p = path; *p; ++p) {
            if (*p == L'\\' || *p == L'/')
                filename = p + 1;
        }

        result = WCharToString(filename);
    }

    CloseHandle(process);
    return result;
}

std::string IPv4ToString(DWORD address) {
    IN_ADDR addr{};
    addr.S_un.S_addr = address;

    char buffer[INET_ADDRSTRLEN]{};
    if (!InetNtopA(AF_INET, &addr, buffer, sizeof(buffer)))
        return "Unknown";

    return buffer;
}

std::string IPv6ToString(const UCHAR address[16], DWORD scopeId) {
    IN6_ADDR addr{};
    memcpy(&addr, address, sizeof(addr));

    char buffer[INET6_ADDRSTRLEN]{};
    if (!InetNtopA(AF_INET6, &addr, buffer, sizeof(buffer)))
        return "Unknown";

    std::string result = buffer;
    if (scopeId != 0)
        result += "%" + std::to_string(scopeId);

    return result;
}

void reportListeningTcpPorts(std::ostream& report) {
    report << "\n[+] TCP Listening Ports (address, port, PID, process)...\n";

  
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(
        nullptr,
        &size,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_LISTENER,
        0
    );

    if (result != ERROR_INSUFFICIENT_BUFFER && result != NO_ERROR) {
        report << "    Could not read IPv4 TCP table. Error: "
               << result << '\n';
    } else {
        std::vector<BYTE> buffer(size);

        result = GetExtendedTcpTable(
            buffer.data(),
            &size,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0
        );

        if (result == NO_ERROR) {
            auto* table =
                reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());

            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];

               
                unsigned short port =
                    ntohs(static_cast<u_short>(row.dwLocalPort));

                report << "    IPv4 "
                       << IPv4ToString(row.dwLocalAddr)
                       << ':' << port
                       << " | PID: " << row.dwOwningPid
                       << " | Process: "
                       << GetProcessNameByPid(row.dwOwningPid)
                       << '\n';
            }
        } else {
            report << "    Could not read IPv4 TCP table. Error: "
                   << result << '\n';
        }
    }

   
    size = 0;
    result = GetExtendedTcpTable(
        nullptr,
        &size,
        FALSE,
        AF_INET6,
        TCP_TABLE_OWNER_PID_LISTENER,
        0
    );

    if (result != ERROR_INSUFFICIENT_BUFFER && result != NO_ERROR) {
        report << "    Could not read IPv6 TCP table. Error: "
               << result << '\n';
        return;
    }

    std::vector<BYTE> buffer6(size);

    result = GetExtendedTcpTable(
        buffer6.data(),
        &size,
        FALSE,
        AF_INET6,
        TCP_TABLE_OWNER_PID_LISTENER,
        0
    );

    if (result == NO_ERROR) {
        auto* table =
            reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buffer6.data());

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];

            unsigned short port =
                ntohs(static_cast<u_short>(row.dwLocalPort));

            report << "    IPv6 "
                   << IPv6ToString(row.ucLocalAddr, row.dwLocalScopeId)
                   << ':' << port
                   << " | PID: " << row.dwOwningPid
                   << " | Process: "
                   << GetProcessNameByPid(row.dwOwningPid)
                   << '\n';
        }
    } else {
        report << "    Could not read IPv6 TCP table. Error: "
               << result << '\n';
    }
}





int main() {
    string filename = getTimestampedFilename();
    ofstream report(filename);

    if (!report.is_open()) {
        cout << "Error: Could not create report file!" << endl;
        return 1;
    }

    cout << "--- Starting Security Audit ---" << endl;
    cout << "Generating report: " << filename << "..." << endl;

    report << "================================================\n";
    report << "          SYSTEM SECURITY AUDIT REPORT          \n";
    report << "================================================\n\n";

    report << "=== System Information ===\n";
    report << "Computer name: " << GetComputerNameText() << '\n';
    report << "Windows version: " << GetWindowsVersionText() << "\n\n";

    enumerateUsers(report);
    checkRegistrySecurity(report);
    reportListeningTcpPorts(report);

    report << "\n================================================\n";
    report.close();

    cout << "[+] Audit Complete. Please check " << filename << endl;
    return 0;
}
