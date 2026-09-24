# windows-security-auditor
Windows Security Test


Compile:
g++ auditor.cpp -o auditor.exe -lws2_32 -liphlpapi -lnetapi32 -ladvapi32


What this tool does:
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
