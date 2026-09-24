# windows-security-auditor


Invite me for a coffee :

TKaEHLhwZaM3BYT58Sxv6BubzRQasGHYYN

<img width="375" height="457" alt="photo_2026-09-23_17-29-28" src="https://github.com/user-attachments/assets/69bffec1-6c40-498f-a97f-01ac4076e75c" />



# Windows Security Test


## Compile:

g++ auditor.cpp -o auditor.exe -lws2_32 -liphlpapi -lnetapi32 -ladvapi32


# What this tool does:
It is a non-intrusive Auditor. That is, instead of trying to penetrate the system (like Mimikatz), it enters like a security inspector, walks around the system and lists 'open doors' or settings that weaken security.


Here I will explain exactly what each module does:


1. The enumerateUsers module
This section uses the official Windows API (NetUserEnum) to list all the accounts present on the system.


Security Objective: In a secure system, there should be no anonymous users or users with elevated privileges (Administrator) that are not strictly necessary.
Output: Specifies the username and their privilege level. If you see users that should not be there, it indicates the system has "Over-privileged users".
2. Check Registry Security Settings Module (checkRegistrySecurity)
This section delves into the heart of Windows' security settings in the registry:


Checking UAC (User Account Control): This checks whether User Account Control is enabled. If the EnableLUA value in the registry is 0, it means UAC is disabled. This is a major security risk because any program that runs will do so with administrator privileges directly, without prompting the user for permission.
Credential Guard check: This is one of Windows' most advanced defensive layers, which prevents password theft (such as from a Mimikatz attack). This section checks whether this feature is enabled at the system level. If it is disabled, the system is vulnerable to memory attacks (LSASS).
3. Local Port Scanner Module (scanLocalPorts)
This section is a lightweight port scanner that tests well-known ports (e.g., 80, 445, 3389, etc.) on the address 127.0.0.1.


Security objective: To find listening services. For example, if port 445 (SMB) or 3389 (RDP) is open, it means the system is offering network services. If these ports are open unintentionally, a hacker can use them to get closer to the system.
Technical Note: This section attempts to establish a TCP connection using Winsock (the Windows networking library). If the connection is successful, it means the port is open.
4. Reporting
Finally, instead of displaying all this information in the console, it saves it to a text file with a name like Security_Audit_Report_20240520.txt.


Use Case: In the real world, security auditors prepare written reports to present to system administrators.
Use Case Summary:
You use this tool for Reconnaissance. Before you attempt a penetration test or secure the system, running this program will tell you:


Who is on the system?
What ports are open?
What defences (UAC/Credential Guard) are disabled?







# Sample Report :

================================================
          SYSTEM SECURITY AUDIT REPORT          
================================================

=== System Information ===
Computer name: DESKTOP-T39BTE9
Windows version: 10.0 (Build 26200)


[+] Enumerating System Users...
    User: Administrator | Privileges: Administrator
    User: DefaultAccount | Privileges: Standard User
    User: Guest | Privileges: Standard User
    User: Jack | Privileges: Administrator
    User: WDAGUtilityAccount | Privileges: Standard User
    User: WsiAccount | Privileges: Standard User

[+] Checking Registry Security Settings...
    UAC (EnableLUA): ENABLED
    Credential Guard: NOT FOUND/DISABLED

[+] TCP Listening Ports (address, port, PID, process)...
    IPv4 0.0.0.0:135 | PID: 1580 | Process: Access denied or unavailable
    IPv4 172.16.49.130:139 | PID: 4 | Process: Access denied or unavailable
    IPv4 172.28.32.1:139 | PID: 4 | Process: Access denied or unavailable
    IPv4 192.168.11.1:139 | PID: 4 | Process: Access denied or unavailable
    IPv4 192.168.43.44:139 | PID: 4 | Process: Access denied or unavailable
    IPv4 192.168.190.1:139 | PID: 4 | Process: Access denied or unavailable
    IPv4 127.0.0.1:902 | PID: 5332 | Process: Access denied or unavailable
    IPv4 127.0.0.1:912 | PID: 5332 | Process: Access denied or unavailable
    IPv4 127.0.0.1:1001 | PID: 4 | Process: Access denied or unavailable
    IPv4 0.0.0.0:1025 | PID: 5796 | Process: Access denied or unavailable
    IPv4 0.0.0.0:1026 | PID: 1224 | Process: Access denied or unavailable
    IPv4 0.0.0.0:1027 | PID: 8524 | Process: Access denied or unavailable
    IPv4 127.0.0.1:1028 | PID: 9540 | Process: explorer.exe
    IPv4 0.0.0.0:2179 | PID: 3116 | Process: Access denied or unavailable
    IPv4 0.0.0.0:3389 | PID: 7744 | Process: Access denied or unavailable
    IPv4 0.0.0.0:5040 | PID: 9252 | Process: Access denied or unavailable
    IPv4 0.0.0.0:49664 | PID: 1276 | Process: Access denied or unavailable
    IPv4 0.0.0.0:49665 | PID: 1104 | Process: Access denied or unavailable
    IPv4 0.0.0.0:49666 | PID: 2128 | Process: Access denied or unavailable
    IPv4 0.0.0.0:49667 | PID: 3500 | Process: Access denied or unavailable
    IPv4 0.0.0.0:49668 | PID: 4856 | Process: Access denied or unavailable
    IPv4 0.0.0.0:445 | PID: 4 | Process: Access denied or unavailable
    IPv4 0.0.0.0:3240 | PID: 5716 | Process: Access denied or unavailable
    IPv6 :::135 | PID: 1580 | Process: Access denied or unavailable
    IPv6 :::445 | PID: 4 | Process: Access denied or unavailable
    IPv6 ::1:1024 | PID: 5348 | Process: Access denied or unavailable
    IPv6 :::1025 | PID: 5796 | Process: Access denied or unavailable
    IPv6 :::1026 | PID: 1224 | Process: Access denied or unavailable
    IPv6 :::1027 | PID: 8524 | Process: Access denied or unavailable
    IPv6 :::2179 | PID: 3116 | Process: Access denied or unavailable
    IPv6 :::3240 | PID: 5716 | Process: Access denied or unavailable
    IPv6 :::3389 | PID: 7744 | Process: Access denied or unavailable
    IPv6 ::1:42050 | PID: 18772 | Process: OneDrive.Sync.Service.exe
    IPv6 :::49664 | PID: 1276 | Process: Access denied or unavailable
    IPv6 :::49665 | PID: 1104 | Process: Access denied or unavailable
    IPv6 :::49666 | PID: 2128 | Process: Access denied or unavailable
    IPv6 :::49667 | PID: 3500 | Process: Access denied or unavailable
    IPv6 :::49668 | PID: 4856 | Process: Access denied or unavailable

================================================
