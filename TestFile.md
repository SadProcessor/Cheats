# RedTrooperFM - Empire Module Wiki
 
A one page Wiki for all your Empire RTFM needs...

## Index
 
- [powershell](#powershell)
 
    - [code_execution](#powershell---code_execution)
 
    - [collection](#powershell---collection)
 
    - [credentials](#powershell---credentials)
 
    - [exfiltration](#powershell---exfiltration)
 
    - [exploitation](#powershell---exploitation)
 
    - [lateral_movement](#powershell---lateral_movement)
 
    - [management](#powershell---management)
 
    - [persistence](#powershell---persistence)
 
    - [privesc](#powershell---privesc)
 
    - [recon](#powershell---recon)
 
    - [situational_awareness](#powershell---situational_awareness)
 
    - [trollsploit](#powershell---trollsploit)
 
- [python](#python)
 
    - [collection](#python---collection)
 
    - [exploit](#python---exploit)
 
    - [lateral_movement](#python---lateral_movement)
 
    - [management](#python---management)
 
    - [persistence](#python---persistence)
 
    - [privesc](#python---privesc)
 
    - [situational_awareness](#python---situational_awareness)
 
    - [trollsploit](#python---trollsploit)



***

# powershell

Back to [Index](#index) 

***

## powershell - code_execution

 - [invoke_dllinjection](#invoke_dllinjection)
 - [invoke_metasploitpayload](#invoke_metasploitpayload)
 - [invoke_ntsd](#invoke_ntsd)
 - [invoke_reflectivepeinjection](#invoke_reflectivepeinjection)
 - [invoke_shellcode](#invoke_shellcode)
 - [invoke_shellcodemsil](#invoke_shellcodemsil)
 
*****

## invoke_dllinjection

### Description: 

Uses PowerSploit's Invoke-DLLInjection to inject  a Dll into the process ID of your choosing.

### Author:

@mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Dll** | Name of the dll to inject. This can be an absolute or relative path. | True |  |
| **ProcessID** | Process ID of the process you want to inject a Dll into. | True |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke-DllInjection.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | code_execution |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution) Code

Back to [Index](#index)





 
*****

## invoke_metasploitpayload

### Description: 

Spawns a new, hidden PowerShell window that downloadsand executes a Metasploit payload. This relies on theexploit/multi/scripts/web_delivery metasploit module.

### Author:

@jaredhaight

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run Metasploit payload on. | True |  |
| **URL** | URL from the Metasploit web_delivery module | True |  |

### Comments:

https://github.com/jaredhaight/Invoke-MetasploitPayload/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | code_execution |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution) Code

Back to [Index](#index)





 
*****

## invoke_ntsd

### Description: 

Use NT Symbolic Debugger to execute Empire launcher code

### Author:

james fitts

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Arch** | Architecture the system is on. | True | x64 |
| **BinPath** | Binary to set NTSD to debug. | True | C:\Windows\System32\calc.exe |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UploadPath** | Path to drop dll (C:\Users\Administrator\Desktop). | False |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | code_execution |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution) Code

Back to [Index](#index)





 
*****

## invoke_reflectivepeinjection

### Description: 

Uses PowerSploit's Invoke-ReflectivePEInjection to reflectively load a DLL/EXE in to the PowerShell process or reflectively load a DLL in to a remote process.

### Author:

@JosephBialek

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Optional an array of computernames to run the script on. | False |  |
| **DllPath** | (Attacker) local path for the PE/DLL to load. | False |  |
| **ExeArgs** | Optional arguments to pass to the executable being reflectively loaded. | False |  |
| **ForceASLR** | Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. | True | False |
| **PEUrl** | A URL containing a DLL/EXE to load and execute. | False |  |
| **ProcId** | Process ID of the process you want to inject a Dll into. | False |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | code_execution |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution) Code

Back to [Index](#index)





 
*****

## invoke_shellcode

### Description: 

Uses PowerSploit's Invoke--Shellcode to inject shellcode into the process ID of your choosing or within the context of the running PowerShell process. If you're injecting custom shellcode, make sure it's in the correct format and matches the architecture of the process you're injecting into.

### Author:

@mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Lhost** | Local host handler for the meterpreter shell. | False |  |
| **Listener** | Meterpreter/Beacon listener name. | False |  |
| **Lport** | Local port of the host handler. | False |  |
| **Payload** | Metasploit payload to inject (reverse_http[s]). | False | reverse_https |
| **ProcessID** | Process ID of the process you want to inject shellcode into. | False |  |
| **Shellcode** | Custom shellcode to inject, 0xaa,0xab,... format. | False |  |

### Comments:

http://www.exploit-monday.com

https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | code_execution |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution) Code

Back to [Index](#index)





 
*****

## invoke_shellcodemsil

### Description: 

Execute shellcode within the context of the running PowerShell process without making any Win32 function calls. Warning: This script has no way to validate that your shellcode is 32 vs. 64-bit!Note: Your shellcode must end in a ret (0xC3) and maintain proper stack alignment or PowerShell will crash!

### Author:

@mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Shellcode** | Shellcode to inject, 0x00,0x0a,... format. | True |  |

### Comments:

http://www.exploit-monday.com

https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke-ShellcodeMSIL.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | code_execution |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution) Code

Back to [Index](#index)





 

***

## powershell - collection

 - [browser_data](#browser_data)
 - [ChromeDump](#ChromeDump)
 - [clipboard_monitor](#clipboard_monitor)
 - [file_finder](#file_finder)
 - [find_interesting_file](#find_interesting_file)
 - [FoxDump](#FoxDump)
 - [get_indexed_item](#get_indexed_item)
 - [get_sql_column_sample_data](#get_sql_column_sample_data)
 - [get_sql_query](#get_sql_query)
 - [inveigh](#inveigh)
 - [keylogger](#keylogger)
 - [minidump](#minidump)
 - [netripper](#netripper)
 - [ninjacopy](#ninjacopy)
 - [packet_capture](#packet_capture)
 - [prompt](#prompt)
 - [screenshot](#screenshot)
 - [vaults/add_keepass_config_trigger](#vaults/add_keepass_config_trigger)
 - [vaults/find_keepass_config](#vaults/find_keepass_config)
 - [vaults/get_keepass_config_trigger](#vaults/get_keepass_config_trigger)
 - [vaults/keethief](#vaults/keethief)
 - [vaults/remove_keepass_config_trigger](#vaults/remove_keepass_config_trigger)
 - [WebcamRecorder](#WebcamRecorder)
 
*****

## browser_data

### Description: 

Search through browser history or bookmarks

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Browser** | Which browser to dump data from. IE, Chrome, Firefox, All. | False | All |
| **DataType** | Specify to search history or bookmarks. History, Bookmarks. | False | All |
| **Search** | Specific a term to search for. | False |  |
| **UserName** | Username on the host to search. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## ChromeDump

### Description: 

This module will decrypt passwords saved in chrome and display them in the console.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |
| **OutFile** | File path to write the results to. | False |  |

### Comments:

https://github.com/xorrior/RandomPS-Scripts/blob/master/Get-ChromeDump.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## clipboard_monitor

### Description: 

Monitors the clipboard on a specified interval for changes to copied text.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CollectionLimit** | Specifies the interval in minutes to capture clipboard text. Defaults to indefinite collection. | False |  |
| **PollInterval** | Interval (in seconds) to check the clipboard for changes, defaults to 15 seconds. | True | 15 |

### Comments:

http://brianreiter.org/2010/09/03/copy-and-paste-with-clipboard-from-powershell/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## file_finder

### Description: 

Finds sensitive files on the domain.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CheckWriteAccess** | Switch. Only returns files the current user has write access to. | False |  |
| **ComputerFilter** | Host filter name to query AD for, wildcards accepted. | False |  |
| **ComputerName** | Hosts to enumerate. | False |  |
| **CreationTime** | Only return files with a CreationDate greater than this date value. | False |  |
| **Delay** | Delay between enumerating hosts, defaults to 0. | False |  |
| **Domain** | Domain to query for machines. | False |  |
| **ExcludeHidden** | Switch. Exclude hidden files and folders from the search results. | False |  |
| **FreshEXES** | Switch. Find .EXEs accessed in the last week. | False |  |
| **LastAccessTime** | Only return files with a LastAccessTime greater than this date value. | False |  |
| **NoPing** | Switch. Don't ping each host to ensure it's up before enumerating. | False |  |
| **OfficeDocs** | Switch. Return only office documents. | False |  |
| **SearchSYSVOL** | Switch. Search for login scripts on the SYSVOL of the primary DCs for each specified domain. | False |  |
| **ShareList** | List of '\\HOST\shares' (on the target) to search through. | False |  |
| **Terms** | Comma-separated terms to search for (overrides defaults). | False |  |
| **Threads** | The maximum concurrent threads to execute. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## find_interesting_file

### Description: 

Finds sensitive files on the domain.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CheckWriteAccess** | Switch. Only returns files the current user has write access to. | False |  |
| **CreationTime** | Only return files with a CreationDate greater than this date value. | False |  |
| **ExcludeHidden** | Switch. Exclude hidden files and folders from the search results. | False |  |
| **FreshEXES** | Switch. Find .EXEs accessed in the last week. | False |  |
| **LastAccessTime** | Only return files with a LastAccessTime greater than this date value. | False |  |
| **OfficeDocs** | Switch. Return only office documents. | False |  |
| **Path** | UNC/local path to recursively search. | True |  |
| **Terms** | Comma-separated terms to search for (overrides defaults). | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## FoxDump

### Description: 

This module will dump any saved passwords from Firefox to the console. This should work for any versionof Firefox above version 32. This will only be successful if the master password is blank or has not been set.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |
| **OutFile** | Path to Output File | False |  |

### Comments:

https://github.com/xorrior/RandomPS-Scripts/blob/master/Get-FoxDump.ps1

http://xakfor.net/threads/c-firefox-36-password-cookie-recovery.12192/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## get_indexed_item

### Description: 

Gets files which have been indexed by Windows desktop search.

### Author:

@James O'Neill

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Terms** | Terms to query the search indexer for. | True | password,pass,sensitive,admin,login,secret,creds,credentials |

### Comments:

https://gallery.technet.microsoft.com/scriptcenter/Get-IndexedItem-PowerShell-5bca2dae

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## get_sql_column_sample_data

### Description: 

Returns column information from target SQL Servers. Supports search by keywords, sampling data, and validating credit card numbers.

### Author:

@_nullbind, @0xbadjuju

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CheckAll** | Check all systems retrieved by Get-SQLInstanceDomain. | False |  |
| **Instance** | SQL Server instance to connection to. | False |  |
| **NoDefaults** | Don't select tables from default databases. | False |  |
| **Password** | SQL Server or domain account password to authenticate with. | False |  |
| **Username** | SQL Server or domain account to authenticate with. | False |  |

### Comments:

https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## get_sql_query

### Description: 

Executes a query on target SQL servers.

### Author:

@_nullbind, @0xbadjuju

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Instance** | SQL Server instance to connection to. | False |  |
| **Password** | SQL Server or domain account password to authenticate with. | False |  |
| **Query** | Query to be executed on the SQL Server. | True |  |
| **Username** | SQL Server or domain account to authenticate with. | False |  |

### Comments:

https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## inveigh

### Description: 

Inveigh is a Windows PowerShell LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool. Note that this module exposes only a subset of Inveigh's parameters. Inveigh can be used through Empire's scriptimport and scriptcmd if additional parameters are needed.

### Author:

Kevin Robertson

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ConsoleOutput** | (Low/Medium/Y) Default = Y: Enable/Disable real time console output. Medium and Low can be used to reduce output. | False |  |
| **ConsoleStatus** | Interval in minutes for displaying all unique captured hashes and credentials. This will display a clean list of captures in Empire. | False |  |
| **ConsoleUnique** | (Y/N) Default = Y: Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname, and username combinations. | False |  |
| **ElevatedPrivilege** | (Auto/Y/N) Default = Auto: Set the privilege mode. Auto will determine if Inveigh is running with elevated privilege. If so, options that require elevated privilege can be used. | False |  |
| **HTTP** | (Y/N) Default = Y: Enable/Disable HTTP challenge/response capture. | False |  |
| **HTTPAuth** | (Anonymous/Basic/NTLM/NTLMNoESS) HTTP listener authentication type. This setting does not apply to wpad.dat requests. | False |  |
| **HTTPContentType** | Content type for HTTP/Proxy responses. Does not apply to EXEs and wpad.dat. Set to "application/hta" for HTA files or when using HTA code with HTTPResponse. | False |  |
| **HTTPResponse** | Content to serve as the default HTTP/Proxy response. This response will not be used for wpad.dat requests. Use PowerShell escape characters and newlines where necessary. This paramater will be wrapped in double quotes by this module. | False |  |
| **Inspect** | (Switch) Inspect LLMNR, mDNS, and NBNS traffic only. | False |  |
| **IP** | Local IP address for listening and packet sniffing. This IP address will also be used for LLMNR/mDNS/NBNS spoofing if the SpooferIP parameter is not set. | False |  |
| **LLMNR** | (Y/N) Default = Y: Enable/Disable LLMNR spoofer. | False |  |
| **mDNS** | (Y/N) Enable/Disable mDNS spoofer. | False |  |
| **mDNSTypes** | (QU,QM) Default = QU: Comma separated list of mDNS types to spoof. Note that QM will send the response to 224.0.0.251. | False |  |
| **NBNS** | (Y/N) Enable/Disable NBNS spoofer. | False |  |
| **NBNSTypes** | Default = 00,20: Comma separated list of NBNS types to spoof. | False |  |
| **Proxy** | (Y/N) Enable/Disable Inveigh's proxy server authentication capture. | False |  |
| **ProxyPort** | Default = 8492: TCP port for the Inveigh's proxy listener. | False |  |
| **RunCount** | Number of NTLMv1/NTLMv2 captures to perform before auto-exiting. | False |  |
| **RunTime** | Run time duration in minutes. | True |  |
| **SMB** | (Y/N) Default = Y: Enable/Disable SMB challenge/response capture. | False |  |
| **SpooferHostsIgnore** | Comma separated list of requested hostnames to ignore when spoofing. | False |  |
| **SpooferHostsReply** | Comma separated list of requested hostnames to respond to when spoofing. | False |  |
| **SpooferIP** | Response IP address for spoofing. This parameter is only necessary when redirecting victims to a system other than the Inveigh host. | False |  |
| **SpooferIPsIgnore** | Comma separated list of source IP addresses to ignore when spoofing. | False |  |
| **SpooferIPsReply** | Comma separated list of source IP addresses to respond to when spoofing. | False |  |
| **SpooferLearning** | (Y/N) Enable/Disable LLMNR/NBNS valid host learning. | False |  |
| **SpooferLearningDelay** | Time in minutes that Inveigh will delay spoofing while valid hosts are being blacklisted through SpooferLearning. | False |  |
| **SpooferRepeat** | (Y/N) Default = Y: Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured. | False |  |
| **WPADAuth** | (Anonymous/Basic/NTLM/NTLMNoESS) HTTP listener authentication type for wpad.dat requests. | False |  |

### Comments:

https://github.com/Kevin-Robertson/Inveigh

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## keylogger

### Description: 

Logs keys pressed, time and the active window (when changed) to the keystrokes.txt file. This file is located in the agents downloads directory Empire/downloads/<AgentName>/keystrokes.txt.

### Author:

@obscuresec, @mattifestation, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Get-Keystrokes.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## minidump

### Description: 

Generates a full-memory minidump of a process.

### Author:

@mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **DumpFilePath** | Specifies the folder path where dump files will be written. Defaults to the current user directory. | False |  |
| **ProcessId** | Specifies the process ID for which a dump will be generated. | False |  |
| **ProcessName** | Specifies the process name for which a dump will be generated. | False |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## netripper

### Description: 

Injects NetRipper into targeted processes, which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.

### Author:

Ionut Popescu (@NytroRST), @mattifestation, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **AllData** | Switch. Log all data instead of just plaintext. | False |  |
| **Datalimit** | Data limit capture per request. | False | 4096 |
| **LogLocation** | Folder location to log sniffed data to. | False | TEMP |
| **ProcessID** | Specific process ID to inject the NetRipper dll into. | False |  |
| **ProcessName** | Inject the NetRipper dll into all processes with the given name (i.e. putty). | False |  |
| **SearchStrings** | Strings to search for in traffic. | True | user,login,pass,database,config |

### Comments:

https://github.com/NytroRST/NetRipper/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## ninjacopy

### Description: 

Copies a file from an NTFS partitioned volume by reading the raw volume and parsing the NTFS structures.

### Author:

@JosephBialek

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | An array of computernames to run the script on. | False |  |
| **LocalDestination** | A file path to copy the file to on the local computer. | False |  |
| **Path** | The full path of the file to copy (example: c:\windows\ntds\ntds.dit) | True |  |
| **RemoteDestination** | A file path to copy the file to on the remote computer. If this isn't used, LocalDestination must be specified. | False |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1

https://clymb3r.wordpress.com/2013/06/13/using-powershell-to-copy-ntds-dit-registry-hives-bypass-sacls-dacls-file-locks/

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## packet_capture

### Description: 

Starts a packet capture on a host using netsh.

### Author:

@obscuresec, @mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **MaxSize** | Maximum size of capture file. Blank for no limit. | True | 100MB |
| **Persistent** | Switch. Persist capture across reboots. | False |  |
| **StopTrace** | Switch. Stop trace capture. | False |  |
| **TraceFile** | File to log the capture out to. | True | C:\capture.etl |

### Comments:

http://obscuresecurity.blogspot.com/p/presentation-slides.html

http://blogs.msdn.com/b/canberrapfe/archive/2012/03/31/capture-a-network-trace-without-installing-anything-works-for-shutdown-and-restart-too.aspx

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## prompt

### Description: 

Prompts the current user to enter their credentials in a forms box and returns the results.

### Author:

greg.fossk, @harmj0y, @enigma0x3

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **IconType** | Critical, Question, Exclamation, or Information | True | Critical |
| **MsgText** | Message text to display if not waiting for a process create. | True | Lost contact with the Domain Controller. |
| **Title** | Title of the message box to display if not waiting for a process create. | True | ERROR - 0xA801B720 |

### Comments:

http://blog.logrhythm.com/security/do-you-trust-your-computer/https://enigma0x3.wordpress.com/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## screenshot

### Description: 

Takes a screenshot of the current desktop and returns the output as a .PNG.

### Author:

@obscuresec, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Ratio** | JPEG Compression ratio: 1 to 100. | False |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Get-TimedScreenshot.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** |png |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 
*****

## vaults/add_keepass_config_trigger

### Description: 

This module adds a KeePass exfiltration trigger to all KeePass configs found by Find-KeePassConfig.

### Author:

@tifkin_, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Action** | 'ExportDatabase' (export opened databases to $ExportPath) or 'ExfilDataCopied' (export copied data to $ExportPath). | True | ExportDatabase |
| **Agent** | Agent to run the module on. | True |  |
| **ExportPath** | The path to export data to, defaults to %APPDATA%\KeePass\ | False |  |
| **TriggerName** | The name for the trigger. | True | Debug |

### Comments:

https://github.com/adaptivethreat/KeeThief

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/vaults) Code

Back to [Index](#index)





 
*****

## vaults/find_keepass_config

### Description: 

This module finds and parses any KeePass.config.xml (2.X) and KeePass.ini (1.X) files.

### Author:

@tifkin_, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |

### Comments:

https://github.com/adaptivethreat/KeeThief

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/vaults) Code

Back to [Index](#index)





 
*****

## vaults/get_keepass_config_trigger

### Description: 

This module extracts out the trigger specifications from a KeePass 2.X configuration XML file.

### Author:

@tifkin_, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |

### Comments:

https://github.com/adaptivethreat/KeeThief

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/vaults) Code

Back to [Index](#index)





 
*****

## vaults/keethief

### Description: 

This module retrieves database mastey key information for unlocked KeePass database.

### Author:

@tifkin_, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |

### Comments:

https://github.com/adaptivethreat/KeeThief

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/vaults) Code

Back to [Index](#index)





 
*****

## vaults/remove_keepass_config_trigger

### Description: 

This module removes all triggers from all KeePass configs found by Find-KeePassConfig.

### Author:

@tifkin_, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |

### Comments:

https://github.com/adaptivethreat/KeeThief

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/vaults) Code

Back to [Index](#index)





 
*****

## WebcamRecorder

### Description: 

This module uses the DirectX.Capture and DShowNET .NET assemblies to capture video from a webcam.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |
| **OutPath** | Temporary save path for the .avi file. Defaults to the current users APPDATA\roaming directory | False |  |
| **RecordTime** | Length of time to record in seconds. Defaults to 5. | False |  |

### Comments:

comment

https://github.com/xorrior/RandomPS-Scripts/blob/master/Start-WebcamRecorder.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** |avi |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection) Code

Back to [Index](#index)





 

***

## powershell - credentials

 - [credential_injection](#credential_injection)
 - [enum_cred_store](#enum_cred_store)
 - [invoke_kerberoast](#invoke_kerberoast)
 - [mimikatz/cache](#mimikatz/cache)
 - [mimikatz/certs](#mimikatz/certs)
 - [mimikatz/command](#mimikatz/command)
 - [mimikatz/dcsync](#mimikatz/dcsync)
 - [mimikatz/dcsync_hashdump](#mimikatz/dcsync_hashdump)
 - [mimikatz/extract_tickets](#mimikatz/extract_tickets)
 - [mimikatz/golden_ticket](#mimikatz/golden_ticket)
 - [mimikatz/logonpasswords](#mimikatz/logonpasswords)
 - [mimikatz/lsadump](#mimikatz/lsadump)
 - [mimikatz/mimitokens](#mimikatz/mimitokens)
 - [mimikatz/pth](#mimikatz/pth)
 - [mimikatz/purge](#mimikatz/purge)
 - [mimikatz/sam](#mimikatz/sam)
 - [mimikatz/silver_ticket](#mimikatz/silver_ticket)
 - [mimikatz/trust_keys](#mimikatz/trust_keys)
 - [powerdump](#powerdump)
 - [sessiongopher](#sessiongopher)
 - [tokens](#tokens)
 - [vault_credential](#vault_credential)
 
*****

## credential_injection

### Description: 

Runs PowerSploit's Invoke-CredentialInjection to create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).

### Author:

@JosephBialek

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **AuthPackage** | authentication package to use (Kerberos or Msv1_0) | False | Kerberos |
| **CredID** | CredID from the store to use. | False |  |
| **DomainName** | The domain name of the user account. | False |  |
| **ExistingWinLogon** | Switch. Use an existing WinLogon.exe process | False |  |
| **LogonType** | Logon type of the injected logon (Interactive, RemoteInteractive, or NetworkCleartext) | False | RemoteInteractive |
| **NewWinLogon** | Switch. Create a new WinLogon.exe process. | False |  |
| **Password** | Password of the user. | False |  |
| **UserName** | Username to log in with. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-CredentialInjection.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials) Code

Back to [Index](#index)





 
*****

## enum_cred_store

### Description: 

Dumps plaintext credentials from the Windows Credential Manager for the current interactive user.

### Author:

BeetleChunks

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

The powershell used is based on JimmyJoeBob Alooba's CredMan script.
https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Credentials-d44c3cde

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials) Code

Back to [Index](#index)





 
*****

## invoke_kerberoast

### Description: 

Requests kerberos tickets for all users with a non-null service principal name (SPN) and extracts them into a format ready for John or Hashcat.

### Author:

@harmj0y, @machosec

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **AdminCount** | Kerberoast privileged accounts protected by AdminSDHolder. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | Specifies the domain to use for the query, defaults to the current domain. | False |  |
| **Identity** | Specific SamAccountName, DistinguishedName, SID, or GUID to kerberoast. | False |  |
| **LDAPFilter** | Specifies an LDAP query string that is used to filter Active Directory objects. | False |  |
| **OutputFormat** | Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format. | False | John |
| **SearchBase** | The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local". | False |  |
| **SearchScope** | Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree). | False |  |
| **Server** | Specifies an Active Directory server (domain controller) to bind to. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

https://gist.github.com/HarmJ0y/53a837fce877e32e18d78acbb08c8fe9

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials) Code

Back to [Index](#index)





 
*****

## mimikatz/cache

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to extract MSCache(v2) hashes.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#lsa

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/certs

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to extract all certificates to the local directory.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/command

### Description: 

Runs PowerSploit's Invoke-Mimikatz function with a custom command.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Command** | Custom Invoke-Mimikatz command to run. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/dcsync

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to extract a given account password through Mimikatz's lsadump::dcsync module. This doesn't need code execution on a given DC, but needs to be run from a user context with DA equivalent privileges.

### Author:

@gentilkiwi, Vincent Le Toux, @JosephBialek

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **dc** | Specified (fqdn) domain controller to pull replication data from. | False |  |
| **domain** | Specified (fqdn) domain to pull for the primary domain/DC. | False |  |
| **user** | Username to extract the hash for (domain\username format). | True |  |

### Comments:

http://blog.gentilkiwi.com

http://clymb3r.wordpress.com/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/dcsync_hashdump

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to collect all domain hashes using Mimikatz'slsadump::dcsync module. This doesn't need code execution on a given DC, but needs to be run froma user context with DA equivalent privileges.

### Author:

@gentilkiwi, Vincent Le Toux, @JosephBialek, @harmj0y, @monoxgas

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Active** | Switch. Only collect hashes for accounts marked as active. Default is True | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Computers** | Switch. Include machine hashes in the dump | False |  |
| **Domain** | Specified (fqdn) domain to pull for the primary domain/DC. | False |  |
| **Forest** | Switch. Pop the big daddy (forest) as well. | False |  |

### Comments:

http://blog.gentilkiwi.com

http://clymb3r.wordpress.com/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/extract_tickets

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to extract kerberos tickets from memory in base64-encoded form.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/golden_ticket

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to generate a golden ticket and inject it into memory.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CredID** | CredID from the store to use for ticket creation. | False |  |
| **domain** | The fully qualified domain name. | False |  |
| **endin** | Lifetime of the ticket (in minutes). Default to 10 years. | False |  |
| **groups** | Optional comma separated group IDs for the ticket. | False |  |
| **id** | id to impersonate, defaults to 500. | False |  |
| **krbtgt** | krbtgt NTLM hash for the specified domain | False |  |
| **sid** | The SID of the specified domain. | False |  |
| **sids** | External SIDs to add as sidhistory to the ticket. | False |  |
| **user** | Username to impersonate. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/logonpasswords

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to extract plaintext credentials from memory.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/lsadump

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to extract a particular user hash from memory. Useful on domain controllers.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Username** | Username to extract the hash for, blank for all local passwords. | False |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#lsa

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/mimitokens

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to list or enumerate tokens.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **admin** | Switch. List/elevate local admin tokens. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **domainadmin** | Switch. List/elevate domain admin tokens. | False |  |
| **elevate** | Switch. Elevate instead of listing tokens. | False |  |
| **id** | Token ID to list/elevate the token of. | False |  |
| **list** | Switch. List current tokens on the machine. | False | True |
| **revert** | Switch. Revert process token. | False |  |
| **user** | User name to list/elevate the token of. | False |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/pth

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to execute sekurlsa::pth to create a new process. with a specific user's hash. Use credentials/tokens to steal the token afterwards.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CredID** | CredID from the store to use for ticket creation. | False |  |
| **domain** | The fully qualified domain name. | False |  |
| **ntlm** | The NTLM hash to use. | False |  |
| **user** | Username to impersonate. | False |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

http://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/purge

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to purge all current kerberos tickets from memory.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/sam

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to extract hashes from the Security Account Managers (SAM) database.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#lsa

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/silver_ticket

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to generate a silver ticket for a server/service and inject it into memory.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CredID** | CredID from the store to use for ticket creation. | False |  |
| **domain** | The fully qualified domain name. | False |  |
| **groups** | Optional comma separated group IDs for the ticket. | False |  |
| **id** | id to impersonate, defaults to 500. | False |  |
| **rc4** | target machine rc4/NTLM hash | False |  |
| **service** | service to forge the ticket for (cifs, HOST, etc.) | True | cifs |
| **sid** | The SID of the specified domain. | False |  |
| **target** | The fully qualified domain name of the target machine. | False |  |
| **user** | Username to impersonate. | True | Administrator |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## mimikatz/trust_keys

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to extract domain trust keys from a domain controller.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Method** | Method to extract keys ("sekurlsa" or "lsadump") | True | lsadump |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/mimikatz) Code

Back to [Index](#index)





 
*****

## powerdump

### Description: 

Dumps hashes from the local system using Posh-SecMod's Invoke-PowerDump

### Author:

DarkOperator, winfang, Kathy Peters, ReL1K

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials) Code

Back to [Index](#index)





 
*****

## sessiongopher

### Description: 

Extract saved sessions & passwords for WinSCP, PuTTY, SuperPuTTY, FileZilla, RDP, .ppk files, .rdp files, .sdtid files

### Author:

@arvanaghi, created at FireEye

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **AllDomain** | Switch. Run against all computers on domain. Uses current security context, unless -u and -p arguments provided. Uses WMI. | False |  |
| **iL** | Provide path to a .txt file on the remote host containing hosts separated by newlines to run remotely against. Uses WMI. | False |  |
| **o** | Switch. Drops a folder of all output in .csvs on remote host. | False |  |
| **p** | Password for user account (if -u argument provided). | False |  |
| **Target** | Provide a single host to run remotely against. Uses WMI. | False |  |
| **Thorough** | Switch. Searches entire filesystem for .ppk, .rdp, .sdtid files. Not recommended to use with -AllDomain due to time. | False |  |
| **u** | User account (e.g. corp.com\jerry) for when using -Target, -iL, or -AllDomain. If not provided, uses current security context. | False |  |

### Comments:

Twitter: @arvanaghi | 

https://arvanaghi.com | 

https://github.com/fireeye/SessionGopher

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials) Code

Back to [Index](#index)





 
*****

## tokens

### Description: 

Runs PowerSploit's Invoke-TokenManipulation to enumerate Logon Tokens available and uses them to create new processes. Similar to Incognito's functionality. Note: if you select ImpersonateUser or CreateProcess, you must specify one of Username, ProcessID, Process, or ThreadId.

### Author:

@JosephBialek

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CreateProcess** | Specify a process to create instead of impersonating the user. | False |  |
| **ImpersonateUser** | Switch. Will impersonate an alternate users logon token in the PowerShell thread. | False |  |
| **NoUI** | Switch. Use if creating a process which doesn't need a UI. | False |  |
| **Process** | Process name to impersonate token of. | False |  |
| **ProcessArgs** | Arguments for a spawned process. | False |  |
| **ProcessID** | ProcessID to impersonate token of. | False |  |
| **RevToSelf** | Switch. Revert to original token. | False |  |
| **ShowAll** | Switch. Enumerate all tokens. | False |  |
| **ThreadId** | Thread to impersonate token of. | False |  |
| **Username** | Username to impersonate token of. | False |  |
| **WhoAmI** | Switch. Displays current credentials. | False |  |

### Comments:

http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials) Code

Back to [Index](#index)





 
*****

## vault_credential

### Description: 

Runs PowerSploit's Get-VaultCredential to display Windows vault credential objects including cleartext web credentials.

### Author:

@mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | credentials |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials) Code

Back to [Index](#index)





 

***

## powershell - exfiltration

 - [egresscheck](#egresscheck)
 - [exfil_dropbox](#exfil_dropbox)
 
*****

## egresscheck

### Description: 

This module will generate traffic on a provided range of ports and supports both TCP and UDP. Useful to identify direct egress channels.

### Author:

Stuart Morgan <stuart.morgan@mwrinfosecurity.com>

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to generate the source traffic on | True |  |
| **delay** | Delay, in milliseconds, between ports being tested | True | 50 |
| **ip** | Target IP Address | True |  |
| **portrange** | The range of ports to connect on. This can be a comma separated list or dash-separated ranges. | True | 22-25,53,80,443,445,3306,3389 |
| **protocol** | The protocol to use. This can be TCP or UDP | True | TCP |

### Comments:

https://github.com/stufus/egresscheck-framework

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | exfiltration |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/exfiltration) Code

Back to [Index](#index)





 
*****

## exfil_dropbox

### Description: 

Upload a file to dropbox 

### Author:

kdick@tevora.com, Laurent Kempe

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to use | True |  |
| **ApiKey** | Your dropbox api key | True |  |
| **SourceFilePath** | /path/to/file | True |  |
| **TargetFilePath** | /path/to/dropbox/file | True |  |

### Comments:

Uploads specified file to dropbox 

Ported to powershell2 from script by Laurent Kempe: http://laurentkempe.com/2016/04/07/Upload-files-to-DropBox-from-PowerShell/

Use forward slashes for the TargetFilePath

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | exfiltration |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/exfiltration) Code

Back to [Index](#index)





 

***

## powershell - exploitation

 - [exploit_eternalblue](#exploit_eternalblue)
 - [exploit_jboss](#exploit_jboss)
 - [exploit_jenkins](#exploit_jenkins)
 
*****

## exploit_eternalblue

### Description: 

Port of MS17_010 Metasploit module to powershell. Exploits targeted system and executes specified shellcode. Windows 7 and 2008 R2 supported. Potential for a BSOD 

### Author:

Sean Dillon <sean.dillon [at] risksense.com>, Dylan Davis <dylan.davis [at] risksense.com>Equation Group, kdick@tevora.com (e0x70i)

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **InitialGrooms** | Number of Initial Grooms | True | 12 |
| **MaxAttempts** | Number of times to try exploit (increment grooms by 5 each time) | True | 1 |
| **Shellcode** | Custom shellcode to inject, 0xaa,0xab,... format. | True |  |
| **Target** | IP or Hostname of target  | True |  |

### Comments:

https://github.com/RiskSense-Ops/MS17-010

https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue

http://threat.tevora.com/eternal-blues/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | exploitation |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/exploitation) Code

Back to [Index](#index)





 
*****

## exploit_jboss

### Description: 

Exploit vulnerable JBoss Services.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **AppName** | Application name the WAR file deploys to. Empire defaults to "launcher". | True |  |
| **JMXConsole** | Switch. Service to Exploit | True |  |
| **Port** | Specify the port to use. | True |  |
| **Rhost** | Specify the host to exploit. | True |  |
| **UseSSL** | Force SSL useage. | False |  |
| **WarFile** | Remote URL [http://IP:PORT/f.war] to your own WarFile to deploy. | True |  |

### Comments:

Requires WAR file that is not provided.

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | exploitation |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/exploitation) Code

Back to [Index](#index)





 
*****

## exploit_jenkins

### Description: 

Run command on unauthenticated Jenkins Script consoles.

### Author:

@luxcupitor

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Cmd** | command to run on remote jenkins script console. | True | whoami |
| **Port** | Specify the port to use. | True | 8080 |
| **Rhost** | Specify the host to exploit. | True |  |

### Comments:

Pass a command to run. If windows, you may have to prepend "cmd /c ".

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | exploitation |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/exploitation) Code

Back to [Index](#index)





 

***

## powershell - lateral_movement

 - [inveigh_relay](#inveigh_relay)
 - [invoke_dcom](#invoke_dcom)
 - [invoke_executemsbuild](#invoke_executemsbuild)
 - [invoke_psexec](#invoke_psexec)
 - [invoke_psremoting](#invoke_psremoting)
 - [invoke_sqloscmd](#invoke_sqloscmd)
 - [invoke_sshcommand](#invoke_sshcommand)
 - [invoke_wmi](#invoke_wmi)
 - [invoke_wmi_debugger](#invoke_wmi_debugger)
 - [jenkins_script_console](#jenkins_script_console)
 - [new_gpo_immediate_task](#new_gpo_immediate_task)
 
*****

## inveigh_relay

### Description: 

Inveigh's SMB relay function. This module can be used to relay incoming HTTP/Proxy NTLMv1/NTLMv2 authentication requests to an SMB target. If the authentication is successfully relayed and the account has the correct privilege, a specified command or Empire launcher will be executed on the target PSExec style. This module works best while also running collection/inveigh with HTTP disabled. Note that this module exposes only a subset of Inveigh Relay's parameters. Inveigh Relay can be used through Empire's scriptimport and scriptcmd if additional parameters are needed.

### Author:

Kevin Robertson

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Command** | Command to execute on relay target. Do not wrap in quotes and use PowerShell escape characters and newlines where necessary. | False |  |
| **ConsoleOutput** | (Low/Medium/Y) Default = Y: Enable/Disable real time console output. Medium and Low can be used to reduce output. | False |  |
| **ConsoleStatus** | Interval in minutes for displaying all unique captured hashes and credentials. This will display a clean list of captures in Empire. | False |  |
| **ConsoleUnique** | (Y/N) Default = Y: Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname, and username combinations. | False |  |
| **HTTP** | (Y/N) Default = Y: Enable/Disable HTTP challenge/response capture/relay. | False |  |
| **Listener** | Listener to use. | False |  |
| **Proxy** | (Y/N) Default = N: Enable/Disable Inveigh's proxy server authentication capture/relay. | False |  |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **ProxyPort** | Default = 8492: TCP port for Inveigh's proxy listener. | False |  |
| **Proxy_** | Proxy to use for request (default, none, or other). | False | default |
| **RunTime** | Run time duration in minutes. | True |  |
| **Service** | Default = 20 character random: Name of the service to create and delete on the target. | False |  |
| **SMB1** | (Switch) Force SMB1. | False |  |
| **Target** | IP address or hostname of system to target for relay. | True |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |
| **Usernames** | Comma separated list of usernames to use for relay attacks. Accepts both username and domain\username format. | False |  |
| **WPADAuth** | (Anonymous/NTLM) HTTP listener authentication type for wpad.dat requests. | False |  |

### Comments:

https://github.com/Kevin-Robertson/Inveigh

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## invoke_dcom

### Description: 

Executes a stager on remote hosts using DCOM.

### Author:

@rvrsh3ll

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Host[s] to execute the stager on, comma separated. | True |  |
| **CredID** | CredID from the store to use. | False |  |
| **Listener** | Listener to use. | True |  |
| **Method** | COM method to use. | True | ShellWindows |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## invoke_executemsbuild

### Description: 

This module utilizes WMI and MSBuild to compile and execute an xml file containing an Empire launcher

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to grab a screenshot from. | True |  |
| **ComputerName** | Host to target | True |  |
| **CredID** | CredID from the store to use. | False |  |
| **DriveLetter** | Drive letter to use when mounting the share locally | False |  |
| **FilePath** | Desired location to copy the xml file on the target | False |  |
| **Listener** | Listener to use. | True |  |
| **Password** | Password if executing with credentials | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |
| **UserName** | UserName if executing with credentials | False |  |

### Comments:

Inspired by @subtee

http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## invoke_psexec

### Description: 

Executes a stager on remote hosts using PsExec type functionality.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Command** | Custom command to execute on remote hosts. | False |  |
| **ComputerName** | Host[s] to execute the stager on, comma separated. | True |  |
| **Listener** | Listener to use. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **ResultFile** | Name of the file to write the results to on agent machine. | False |  |
| **ServiceName** | The name of the service to create. | True | Updater |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/rapid7/metasploit-framework/blob/master/tools/psexec.rb

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## invoke_psremoting

### Description: 

Executes a stager on remote hosts using PSRemoting.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Host[s] to execute the stager on, comma separated. | True |  |
| **CredID** | CredID from the store to use. | False |  |
| **Listener** | Listener to use. | True |  |
| **Password** | Password to use to execute command. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |
| **UserName** | [domain\]username to use to execute command. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## invoke_sqloscmd

### Description: 

Executes a command or stager on remote hosts using xp_cmdshell.

### Author:

@nullbind, @0xbadjuju

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Command** | Custom command to execute on remote hosts. | False |  |
| **CredID** | CredID from the store to use. | False |  |
| **Instance** | Host[s] to execute the stager on, comma separated. | True |  |
| **Listener** | Listener to use. | False |  |
| **Password** | Password to use to execute command. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |
| **UserName** | [domain\]username to use to execute command. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## invoke_sshcommand

### Description: 

Executes a command on a remote host via SSH.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Command** | The command to run on the remote host. | True |  |
| **CredID** | CredID from the store to use. | False |  |
| **IP** | Address of the target server. | True |  |
| **Password** | The password to login with. | False |  |
| **Username** | The username to login with. | False |  |

### Comments:

Open Source is the Best Source

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## invoke_wmi

### Description: 

Executes a stager on remote hosts using WMI.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Host[s] to execute the stager on, comma separated. | True |  |
| **CredID** | CredID from the store to use. | False |  |
| **Listener** | Listener to use. | True |  |
| **Password** | Password to use to execute command. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |
| **UserName** | [domain\]username to use to execute command. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## invoke_wmi_debugger

### Description: 

Uses WMI to set the debugger for a target binary on a remote machine to be cmd.exe or a stager.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Binary** | Binary to set for the debugger. | False | C:\Windows\System32\cmd.exe |
| **Cleanup** | Switch. Disable the debugger for the specified TargetBinary. | False |  |
| **ComputerName** | Host[s] to execute the stager on, comma separated. | True |  |
| **CredID** | CredID from the store to use. | False |  |
| **Listener** | Listener to use. | False |  |
| **Password** | Password to use to execute command. | False |  |
| **RegPath** | Registry location to store the script code. Last element is the key name. | False | HKLM:Software\Microsoft\Network\debug |
| **TargetBinary** | Target binary to set the debugger for (sethc.exe, Utilman.exe, osk.exe, Narrator.exe, or Magnify.exe) | True | sethc.exe |
| **UserName** | [domain\]username to use to execute command. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## jenkins_script_console

### Description: 

Exploit unauthenticated Jenkins Script consoles.

### Author:

@luxcupitor

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Port** | Specify the port to use. | True | 8080 |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **Rhost** | Specify the remote jenkins server to exploit. | True |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

Deploys an Empire agent to a windows Jenkins server with unauthenticated access to script console.

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 
*****

## new_gpo_immediate_task

### Description: 

Builds an 'Immediate' schtask to push out through a specified GPO.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to query for the GPOs, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **GPODisplayName** | The GPO display name to build the task for. | False |  |
| **GPOname** | The GPO name to build the task for. | False |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **Remove** | Switch. Remove the immediate schtask. | False | default |
| **TaskAuthor** | Name for the schtask to create. | True | NT AUTHORITY\System |
| **TaskDescription** | Name for the schtask to create. | False | Debugging functionality. |
| **TaskName** | Name for the schtask to create. | True | Debug |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | lateral_movement |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement) Code

Back to [Index](#index)





 

***

## powershell - management

 - [disable_rdp](#disable_rdp)
 - [downgrade_account](#downgrade_account)
 - [enable_multi_rdp](#enable_multi_rdp)
 - [enable_rdp](#enable_rdp)
 - [get_domain_sid](#get_domain_sid)
 - [honeyhash](#honeyhash)
 - [invoke_script](#invoke_script)
 - [lock](#lock)
 - [logoff](#logoff)
 - [mailraider/disable_security](#mailraider/disable_security)
 - [mailraider/get_emailitems](#mailraider/get_emailitems)
 - [mailraider/get_subfolders](#mailraider/get_subfolders)
 - [mailraider/mail_search](#mailraider/mail_search)
 - [mailraider/search_gal](#mailraider/search_gal)
 - [mailraider/send_mail](#mailraider/send_mail)
 - [mailraider/view_email](#mailraider/view_email)
 - [psinject](#psinject)
 - [reflective_inject](#reflective_inject)
 - [restart](#restart)
 - [runas](#runas)
 - [sid_to_user](#sid_to_user)
 - [spawn](#spawn)
 - [spawnas](#spawnas)
 - [switch_listener](#switch_listener)
 - [timestomp](#timestomp)
 - [user_to_sid](#user_to_sid)
 - [vnc](#vnc)
 - [wdigest_downgrade](#wdigest_downgrade)
 - [zipfolder](#zipfolder)
 
*****

## disable_rdp

### Description: 

Disables RDP on the remote machine.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## downgrade_account

### Description: 

Set reversible encryption on a given domain account and then force the password to be set on next user login.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to query for objects, defaults to the current domain. | False |  |
| **Name** | The name of the domain object you're manipulating. | False |  |
| **Repair** | Switch. Unset the reversible encryption flag and force password reset flag. | False |  |
| **SamAccountName** | The SamAccountName of the domain object you're manipulating. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## enable_multi_rdp

### Description: 

[!] WARNING: Experimental! Runs PowerSploit's Invoke-Mimikatz function to patch the Windows terminal service to allow multiple users to establish simultaneous RDP connections.

### Author:

@gentilkiwi, @JosephBialek

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://blog.gentilkiwi.com

http://clymb3r.wordpress.com/

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## enable_rdp

### Description: 

Enables RDP on the remote machine and adds a firewall exception.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## get_domain_sid

### Description: 

Returns the SID for the current of specified domain.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | Domain to resolve SID for, defaults to the current domain. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## honeyhash

### Description: 

Inject artificial credentials into LSASS.

### Author:

@mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | Specifies the fake domain. | True |  |
| **Password** | Specifies the fake password. | True |  |
| **UserName** | Specifies the fake user name. | True |  |

### Comments:

https://isc.sans.edu/diary/Detecting+Mimikatz+Use+On+Your+Network/19311/

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## invoke_script

### Description: 

Run a custom script. Useful for mass-taskings or script autoruns.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ScriptCmd** | Script command (Invoke-X) from file to run, along with any specified arguments. | True |  |
| **ScriptPath** | Full path to the PowerShell script.ps1 to run (on attacker machine) | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## lock

### Description: 

Locks the workstation's display.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://poshcode.org/1640

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## logoff

### Description: 

Logs the current user (or all users) off the machine.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **AllUsers** | Switch. Log off all current users. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## mailraider/disable_security

### Description: 

This function checks for the ObjectModelGuard, PromptOOMSend, and AdminSecurityMode registry keys for Outlook security. This function must be run in an administrative context in order to set the values for the registry keys.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **AdminPassword** | Optional AdminPassword credentials to use for registry changes. | False |  |
| **AdminUser** | Optional AdminUser credentials to use for registry changes. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Reset** | Switch. Reset security settings to default values. | False |  |
| **Version** | The version of Microsoft Outlook. | True |  |

### Comments:

https://github.com/xorrior/EmailRaider

http://www.xorrior.com/phishing-on-the-inside/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/mailraider) Code

Back to [Index](#index)





 
*****

## mailraider/get_emailitems

### Description: 

Returns all of the items for the specified folder.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **FolderName** | The Name of the Outlook Default Folder. | True | Inbox |
| **MaxEmails** | Maximum number of emails to grab. | True | 100 |

### Comments:

https://github.com/xorrior/EmailRaider

http://www.xorrior.com/phishing-on-the-inside/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/mailraider) Code

Back to [Index](#index)





 
*****

## mailraider/get_subfolders

### Description: 

Returns a list of all the folders in the specified top level folder.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **DefaultFolder** | Folder to search in. | True | Inbox |

### Comments:

https://github.com/xorrior/EmailRaider

http://www.xorrior.com/phishing-on-the-inside/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/mailraider) Code

Back to [Index](#index)





 
*****

## mailraider/mail_search

### Description: 

Searches the given Outlook folder for items (Emails, Contacts, Tasks, Notes, etc. *Depending on the folder*) and returns any matches found.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **DefaultFolder** | Folder to search in. | True | Inbox |
| **File** | Path to results file (instead of stdout). | False |  |
| **Keywords** | Keyword/s to search for. | True |  |
| **MaxResults** | Maximum number of results to return. | False | 100 |
| **MaxSearch** | Maximum number of emails to search through. | False |  |
| **MaxThreads** | Maximum number of threads to use when searching. | True | 15 |

### Comments:

https://github.com/xorrior/EmailRaider

http://www.xorrior.com/phishing-on-the-inside/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/mailraider) Code

Back to [Index](#index)





 
*****

## mailraider/search_gal

### Description: 

returns any exchange users that match the specified search criteria. Searchable fields are FirstName, LastName, JobTitle, Email-Address, and Department.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Dept** | Department to search for. | False |  |
| **Email** | EMail address to search for. | False |  |
| **FullName** | Full Name to search for. | True | Inbox |
| **JobTitle** | Job Title to search for. | True |  |
| **MaxThreads** | Maximum number of threads to use when searching. | True | 15 |

### Comments:

https://github.com/xorrior/EmailRaider

http://www.xorrior.com/phishing-on-the-inside/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/mailraider) Code

Back to [Index](#index)





 
*****

## mailraider/send_mail

### Description: 

Sends emails using a custom or default template to specified target email addresses.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Attachment** | Full path to the file to use as a payload. | False |  |
| **Body** | Body of the email. | False |  |
| **Subject** | Subject of the email. | False |  |
| **TargetList** | List of email addresses read from a file. | False |  |
| **Targets** | Array of target email addresses. If Targets or TargetList parameter are not specified, a list of 100 email addresses will be randomly selected from the Global Address List. | False |  |
| **Template** | Full path to the template html file. | False |  |
| **URL** | URL to include in the email. | False |  |

### Comments:

https://github.com/xorrior/EmailRaider

http://www.xorrior.com/phishing-on-the-inside/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/mailraider) Code

Back to [Index](#index)





 
*****

## mailraider/view_email

### Description: 

Selects the specified folder and then outputs the email item at the specified index.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **FolderName** | The Name of the Outlook Default Folder. | True | Inbox |
| **Index** | Index of the Email item within the selected folder to display. | True | 0 |

### Comments:

https://github.com/xorrior/EmailRaider

http://www.xorrior.com/phishing-on-the-inside/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/mailraider) Code

Back to [Index](#index)





 
*****

## psinject

### Description: 

Utilizes Powershell to to inject a Stephen Fewer formed ReflectivePick which executes PS codefrom memory in a remote process

### Author:

@harmj0y, @sixdub, leechristensen (@tifkin_)

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **ProcId** | ProcessID to inject into. | False |  |
| **ProcName** | Process name to inject into. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

http://sixdub.net

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## reflective_inject

### Description: 

Utilizes Powershell to to inject a Stephen Fewer formed ReflectivePick which executes PS codefrom memory in a remote process

### Author:

@harmj0y, @sixdub, leechristensen (@tifkin_), james fitts

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Arch** | Architecture of the .dll to generate (x64 or x86). | False | x64 |
| **Listener** | Listener to use. | True |  |
| **ProcName** | Process name to inject into. (I.E calc, chrome, powershell) | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UploadPath** | Path to drop dll (C:\Users\Administrator\Desktop). | False |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

http://sixdub.net

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## restart

### Description: 

Restarts the specified machine.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## runas

### Description: 

Runas knockoff. Will bypass GPO path restrictions.

### Author:

rvrsh3ll (@424f424f)

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Arguments** | Optional arguments for the supplied binary. | False |  |
| **Cmd** | Command to run. | True | notepad.exe |
| **CredID** | CredID from the store to use. | False |  |
| **Domain** | Optional domain. | False |  |
| **Password** | Password for the specified username. | False |  |
| **ShowWindow** | Switch. Show the window for the created process instead of hiding it. | False |  |
| **UserName** | Username to run the command as. | False |  |

### Comments:

https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/RunAs.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## sid_to_user

### Description: 

Converts a specified domain sid to a user.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **SID** | Domain SID to translate. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## spawn

### Description: 

Spawns a new agent in a new powershell.exe process.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **SysWow64** | Switch. Spawn a SysWow64 (32-bit) powershell.exe. | False |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## spawnas

### Description: 

Spawn an agent with the specified logon credentials.

### Author:

rvrsh3ll (@424f424f), @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CredID** | CredID from the store to use. | False |  |
| **Domain** | Optional domain. | False |  |
| **Listener** | Listener to use. | True |  |
| **Password** | Password for the specified username. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |
| **UserName** | Username to run the command as. | False |  |

### Comments:

https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/RunAs.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## switch_listener

### Description: 

Overwrites the listener controller logic with the agent with the logic from generate_comms() for the specified listener.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to switch agent comms to. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## timestomp

### Description: 

Executes time-stomp like functionality by invoking Set-MacAttribute.

### Author:

@obscuresec

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Accessed** | Set accessed time (01/03/2006 12:12 pm). | False |  |
| **Agent** | Agent to run module on. | True |  |
| **All** | Set all MAC attributes to value (01/03/2006 12:12 pm). | False |  |
| **Created** | Set created time (01/03/2006 12:12 pm). | False |  |
| **FilePath** | File path to modify. | True |  |
| **Modified** | Set modified time (01/03/2006 12:12 pm). | False |  |
| **OldFile** | Old file path to clone MAC from. | False |  |

### Comments:

http://obscuresecurity.blogspot.com/2014/05/touch.html

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## user_to_sid

### Description: 

Converts a specified domain\user to a domain sid.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | Domain name for translation. | True |  |
| **User** | Username for translation. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## vnc

### Description: 

Invoke-Vnc executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. Password authentication is supported.

### Author:

@n00py

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ConType** | Connection type, choose "bind" or "reverse". | True | bind |
| **IpAddress** | IP Address to use for reverse connection. | False |  |
| **Password** | Password to use. | True | password |
| **Port** | Port to Use. | True | 5900 |

### Comments:

https://github.com/artkond/Invoke-Vnc

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## wdigest_downgrade

### Description: 

Sets wdigest on the machine to explicitly use logon credentials. Counters kb2871997.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Cleanup** | Switch. Disable the registry key. | False |  |
| **NoLock** | Switch. Don't lock the workstation after registry change. | False |  |

### Comments:

https://www.trustedsec.com/april-2015/dumping-wdigest-creds-with-meterpreter-mimikatzkiwi-in-windows-8-1/

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 
*****

## zipfolder

### Description: 

Zips up a target folder for later exfiltration.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Folder** | Folder path to zip. | True |  |
| **ZipFileName** | Zip name/path to create. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management) Code

Back to [Index](#index)





 

***

## powershell - persistence

 - [elevated/registry](#elevated/registry)
 - [elevated/schtasks](#elevated/schtasks)
 - [elevated/wmi](#elevated/wmi)
 - [elevated/wmi_updater](#elevated/wmi_updater)
 - [misc/add_netuser](#misc/add_netuser)
 - [misc/add_sid_history](#misc/add_sid_history)
 - [misc/debugger](#misc/debugger)
 - [misc/disable_machine_acct_change](#misc/disable_machine_acct_change)
 - [misc/get_ssps](#misc/get_ssps)
 - [misc/install_ssp](#misc/install_ssp)
 - [misc/memssp](#misc/memssp)
 - [misc/skeleton_key](#misc/skeleton_key)
 - [powerbreach/deaduser](#powerbreach/deaduser)
 - [powerbreach/eventlog](#powerbreach/eventlog)
 - [powerbreach/resolver](#powerbreach/resolver)
 - [userland/backdoor_lnk](#userland/backdoor_lnk)
 - [userland/registry](#userland/registry)
 - [userland/schtasks](#userland/schtasks)
 
*****

## elevated/registry

### Description: 

Persist a stager (or script) via the HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key. This has an easy detection/removal rating.

### Author:

@mattifestation, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSPath** | Alternate-data-stream location to store the script code. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Cleanup** | Switch. Cleanup the trigger and any script from specified location. | False |  |
| **ExtFile** | Use an external file for the payload instead of a stager. | False |  |
| **KeyName** | Key name for the run trigger. | True | Updater |
| **Listener** | Listener to use. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **RegPath** | Registry location to store the script code. Last element is the key name. | False | HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Debug |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/elevated) Code

Back to [Index](#index)





 
*****

## elevated/schtasks

### Description: 

Persist a stager (or script) using schtasks running as SYSTEM. This has a moderate detection/removal rating.

### Author:

@mattifestation, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSPath** | Alternate-data-stream location to store the script code. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Cleanup** | Switch. Cleanup the trigger and any script from specified location. | False |  |
| **DailyTime** | Daily time to trigger the script (HH:mm). | False | 09:00 |
| **ExtFile** | Use an external file for the payload instead of a stager. | False |  |
| **IdleTime** | User idle time (in minutes) to trigger script. | False |  |
| **Listener** | Listener to use. | False |  |
| **OnLogon** | Switch. Trigger script on user logon. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **RegPath** | Registry location to store the script code. Last element is the key name. | False | HKLM:\Software\Microsoft\Network\debug |
| **TaskName** | Name to use for the schtask. | True | Updater |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/elevated) Code

Back to [Index](#index)





 
*****

## elevated/wmi

### Description: 

Persist a stager (or script) using a permanent WMI subscription. This has a difficult detection/removal rating.

### Author:

@mattifestation, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **AtStartup** | Switch. Trigger script (within 5 minutes) of system startup. | False | True |
| **Cleanup** | Switch. Cleanup the trigger and any script from specified location. | False |  |
| **DailyTime** | Daily time to trigger the script (HH:mm). | False |  |
| **ExtFile** | Use an external file for the payload instead of a stager. | False |  |
| **Listener** | Listener to use. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **SubName** | Name to use for the event subscription. | True | Updater |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/elevated) Code

Back to [Index](#index)





 
*****

## elevated/wmi_updater

### Description: 

Persist a stager (or script) using a permanent WMI subscription. This has a difficult detection/removal rating.

### Author:

@mattifestation, @harmj0y, @tristandostaler

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **AtStartup** | Switch. Trigger script (within 5 minutes) of system startup. | False | True |
| **Cleanup** | Switch. Cleanup the trigger and any script from specified location. | False |  |
| **DailyTime** | Daily time to trigger the script (HH:mm). | False |  |
| **ExtFile** | Use an external file for the payload instead of a stager. | False |  |
| **Launcher** | Launcher string. | True | powershell -noP -sta -w 1 -enc  |
| **SubName** | Name to use for the event subscription. | True | AutoUpdater |
| **WebFile** | The location of the launcher.bat file to fetch over the network/web | True | http://127.0.0.1/launcher.bat |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/elevated) Code

Back to [Index](#index)





 
*****

## misc/add_netuser

### Description: 

Adds a domain user or a local user to the current (or remote) machine, if permissions allow,

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Hostname to add the local user to. | False | localhost |
| **Domain** | Specified domain to add the user to. | False |  |
| **GroupName** | Group to optionally add the user to. | False | Administrators |
| **Password** | The password to set for the added user. | False | Password123! |
| **UserName** | The username to add. | False | backdoor |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/misc) Code

Back to [Index](#index)





 
*****

## misc/add_sid_history

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to execute misc::addsid to add sid history for a user. ONLY APPLICABLE ON DOMAIN CONTROLLERS!

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Groups** | Groups/users to add to the sidhistory of the target user (COMMA-separated). | True |  |
| **User** | User to add sidhistory for. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/misc) Code

Back to [Index](#index)





 
*****

## misc/debugger

### Description: 

Sets the debugger for a specified target binary to be cmd.exe, another binary of your choice, or a listern stager. This can be launched from the ease-of-access center (ctrl+U).

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Cleanup** | Switch. Disable the Utilman.exe debugger. | False |  |
| **Listener** | Listener to use. | False |  |
| **RegPath** | Registry location to store the script code. Last element is the key name. | False | HKLM:Software\Microsoft\Network\debug |
| **TargetBinary** | Target binary to set the debugger for (sethc.exe, Utilman.exe, osk.exe, Narrator.exe, or Magnify.exe) | True | sethc.exe |
| **TriggerBinary** | Binary to set for the debugger. | False | C:\Windows\System32\cmd.exe |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/misc) Code

Back to [Index](#index)





 
*****

## misc/disable_machine_acct_change

### Description: 

Disables the machine account for the target system from changing its password automatically.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CleanUp** | Switch. Re-enable machine password changes. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/misc) Code

Back to [Index](#index)





 
*****

## misc/get_ssps

### Description: 

Enumerates all loaded security packages (SSPs).

### Author:

@mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/misc) Code

Back to [Index](#index)





 
*****

## misc/install_ssp

### Description: 

Installs a security support provider (SSP) dll.

### Author:

@mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Path** | Path of the SSP .dll (on the target machine) to install. | True |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/misc) Code

Back to [Index](#index)





 
*****

## misc/memssp

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to execute misc::memssp to log all authentication events to C:\Windows\System32\mimisla.log.

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/misc) Code

Back to [Index](#index)





 
*****

## misc/skeleton_key

### Description: 

Runs PowerSploit's Invoke-Mimikatz function to execute misc::skeleton to implant a skeleton key w/ password 'mimikatz'. ONLY APPLICABLE ON DOMAIN CONTROLLERS!

### Author:

@JosephBialek, @gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://clymb3r.wordpress.com/

http://blog.gentilkiwi.com

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/misc) Code

Back to [Index](#index)





 
*****

## powerbreach/deaduser

### Description: 

Backup backdoor for a backdoor user.

### Author:

@sixdub

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | Switch. Check the current domain for the user account. | False |  |
| **Listener** | Listener to use. | True |  |
| **OutFile** | Output the backdoor to a file instead of tasking to an agent. | False |  |
| **Sleep** | Time (in seconds) to sleep between checks. | True | 30 |
| **Timeout** | Time (in seconds) to run the backdoor. Defaults to 0 (run forever). | True | 0 |
| **Username** | User account to check for existence. | True |  |

### Comments:

http://sixdub.net

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/powerbreach) Code

Back to [Index](#index)





 
*****

## powerbreach/eventlog

### Description: 

Starts the event-loop backdoor.

### Author:

@sixdub

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **OutFile** | Output the backdoor to a file instead of tasking to an agent. | False |  |
| **Sleep** | Time (in seconds) to sleep between checks. | True | 30 |
| **Timeout** | Time (in seconds) to run the backdoor. Defaults to 0 (run forever). | True | 0 |
| **Trigger** | The unique value to look for in every event packet. | True | HACKER |

### Comments:

http://sixdub.net

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/powerbreach) Code

Back to [Index](#index)





 
*****

## powerbreach/resolver

### Description: 

Starts the Resolver Backdoor.

### Author:

@sixdub

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Hostname** | Hostname to routinely check for a trigger. | True |  |
| **Listener** | Listener to use. | True |  |
| **OutFile** | Output the backdoor to a file instead of tasking to an agent. | False |  |
| **Sleep** | Time (in seconds) to sleep between checks. | True | 30 |
| **Timeout** | Time (in seconds) to run the backdoor. Defaults to 0 (run forever). | True | 0 |
| **Trigger** | The IP Address that the backdoor is looking for. | True | 127.0.0.1 |

### Comments:

http://sixdub.net

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/powerbreach) Code

Back to [Index](#index)





 
*****

## userland/backdoor_lnk

### Description: 

Backdoor a specified .LNK file with a version that launches the original binary and then an Empire stager.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Cleanup** | Switch. Restore the original .LNK settings. | False |  |
| **ExtFile** | Use an external file for the payload instead of a stager. | False |  |
| **Listener** | Listener to use. | True |  |
| **LNKPath** | Full path to the .LNK to backdoor. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **RegPath** | Registry location to store the script code. Last element is the key name. | True | HKCU:\Software\Microsoft\Windows\debug |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

http://windowsitpro.com/powershell/working-shortcuts-windows-powershell

http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html

https://github.com/samratashok/nishang

http://blog.trendmicro.com/trendlabs-security-intelligence/black-magic-windows-powershell-used-again-in-new-attack/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/userland) Code

Back to [Index](#index)





 
*****

## userland/registry

### Description: 

Persist a stager (or script) via the HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key. This has an easy detection/removal rating.

### Author:

@mattifestation, @harmj0y, @enigma0x3

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSPath** | Alternate-data-stream location to store the script code. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Cleanup** | Switch. Cleanup the trigger and any script from specified location. | False |  |
| **EventLogID** | Store the script in the Application event log under the specified EventID. The ID needs to be unique/rare! | False |  |
| **ExtFile** | Use an external file for the payload instead of a stager. | False |  |
| **KeyName** | Key name for the run trigger. | True | Updater |
| **Listener** | Listener to use. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **RegPath** | Registry location to store the script code. Last element is the key name. | False | HKCU:Software\Microsoft\Windows\CurrentVersion\Debug |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/userland) Code

Back to [Index](#index)





 
*****

## userland/schtasks

### Description: 

Persist a stager (or script) using schtasks. This has a moderate detection/removal rating.

### Author:

@mattifestation, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSPath** | Alternate-data-stream location to store the script code. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Cleanup** | Switch. Cleanup the trigger and any script from specified location. | False |  |
| **DailyTime** | Daily time to trigger the script (HH:mm). | False | 09:00 |
| **ExtFile** | Use an external file for the payload instead of a stager. | False |  |
| **IdleTime** | User idle time (in minutes) to trigger script. | False |  |
| **Listener** | Listener to use. | False |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **RegPath** | Registry location to store the script code. Last element is the key name. | False | HKCU:\Software\Microsoft\Windows\CurrentVersion\debug |
| **TaskName** | Name to use for the schtask. | True | Updater |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Persistence/Persistence.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/userland) Code

Back to [Index](#index)





 

***

## powershell - privesc

 - [ask](#ask)
 - [bypassuac](#bypassuac)
 - [bypassuac_env](#bypassuac_env)
 - [bypassuac_eventvwr](#bypassuac_eventvwr)
 - [bypassuac_fodhelper](#bypassuac_fodhelper)
 - [bypassuac_sdctlbypass](#bypassuac_sdctlbypass)
 - [bypassuac_tokenmanipulation](#bypassuac_tokenmanipulation)
 - [bypassuac_wscript](#bypassuac_wscript)
 - [getsystem](#getsystem)
 - [gpp](#gpp)
 - [mcafee_sitelist](#mcafee_sitelist)
 - [ms16-032](#ms16-032)
 - [ms16-135](#ms16-135)
 - [powerup/allchecks](#powerup/allchecks)
 - [powerup/find_dllhijack](#powerup/find_dllhijack)
 - [powerup/service_exe_restore](#powerup/service_exe_restore)
 - [powerup/service_exe_stager](#powerup/service_exe_stager)
 - [powerup/service_exe_useradd](#powerup/service_exe_useradd)
 - [powerup/service_stager](#powerup/service_stager)
 - [powerup/service_useradd](#powerup/service_useradd)
 - [powerup/write_dllhijacker](#powerup/write_dllhijacker)
 - [tater](#tater)
 
*****

## ask

### Description: 

Leverages Start-Process' -Verb runAs option inside a YES-Required loop to prompt the user for a high integrity context before running the agent code. UAC will report Powershell is requesting Administrator privileges. Because this does not use the BypassUAC DLLs, it should not trigger any AV alerts.

### Author:

Jack64

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ask.rb

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## bypassuac

### Description: 

Runs a BypassUAC attack to escape from a medium integrity process to a high integrity process. This attack was originally discovered by Leo Davidson. Empire uses components of MSF's bypassuac injection implementation as well as an adapted version of PowerSploit's Invoke--Shellcode.ps1 script for backend lifting.

### Author:

Leo Davidson, @meatballs__, @TheColonial, @mattifestation, @harmyj0y, @sixdub

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke--Shellcode.ps1

https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/bypassuac_injection.rb

https://github.com/rapid7/metasploit-framework/tree/master/external/source/exploits/bypassuac_injection/dll/src

http://www.pretentiousname.com/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## bypassuac_env

### Description: 

Bypasses UAC (even with Always Notify level set) by by performing an registry modification of the "windir" value in "Environment" based on James Forshaw findings(https://tyranidslair.blogspot.cz/2017/05/exploiting-environment-variables-in.html)

### Author:

Petr Medonos

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://tyranidslair.blogspot.cz/2017/05/exploiting-environment-variables-in.html

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## bypassuac_eventvwr

### Description: 

Bypasses UAC by performing an image hijack on the .msc file extension and starting eventvwr.exe. No files are dropped to disk, making this opsec safe.

### Author:

@enigma0x3

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## bypassuac_fodhelper

### Description: 

Bypasses UAC by performing an registry modification for FodHelper (based onhttps://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)

### Author:

Petr Medonos

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## bypassuac_sdctlbypass

### Description: 

Bypasses UAC by performing an registry modification for sdclt (based onhttps://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)

### Author:

Petr Medonos

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## bypassuac_tokenmanipulation

### Description: 

Bypass UAC module based on the script released by Matt Nelson @enigma0x3 at Derbycon 2017

### Author:

@enigma0x3,@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to elevate from. | True |  |
| **Host** | Host or IP where stager is served. | True |  |
| **Port** | Port to connect to where stager is served | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **Stager** | Stager file that you have hosted. | True | update.php |
| **UserAgent** | UserAgent for staging process | False | Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko |

### Comments:

comment

https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/master/Invoke-TokenDuplication.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## bypassuac_wscript

### Description: 

Drops wscript.exe and a custom manifest into C:\Windows\ and then proceeds to execute VBScript using the wscript executablewith the new manifest. The VBScript executed by C:\Windows\wscript.exe will run elevated.

### Author:

@enigma0x3, @harmyj0y, Vozzie

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

http://seclist.us/uac-bypass-vulnerability-in-the-windows-script-host.html

https://github.com/Vozzie/uacscript

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## getsystem

### Description: 

Gets SYSTEM privileges with one of two methods.

### Author:

@harmj0y, @mattifestation

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **PipeName** | Optional pipe name to used for 'NamedPipe' impersonation. | False |  |
| **RevToSelf** | Switch. Reverts the current thread privileges. | False |  |
| **ServiceName** | Optional service name to used for 'NamedPipe' impersonation. | False |  |
| **Technique** | Technique to use, 'NamedPipe' for service named pipe impersonation or 'Token' for adjust token privs. | False | NamedPipe |
| **WhoAmI** | Switch. Display the credentials for the current PowerShell thread. | False |  |

### Comments:

https://github.com/rapid7/meterpreter/blob/2a891a79001fc43cb25475cc43bced9449e7dc37/source/extensions/priv/server/elevate/namedpipe.c

https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot

http://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/

http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## gpp

### Description: 

Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

### Author:

@obscuresec

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## mcafee_sitelist

### Description: 

Retrieves the plaintext passwords for found McAfee's SiteList.xml files.

### Author:

@harmj0y, @funoverip

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/funoverip/mcafee-sitelist-pwd-decryption/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## ms16-032

### Description: 

Spawns a new Listener as SYSTEM by leveraging the MS16-032 local exploit. Note: ~1/6 times the exploit won't work, may need to retry.

### Author:

@FuzzySec, @leoloobeek

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

Credit to James Forshaw (@tiraniddo) for exploit discovery and

to Ruben Boonen (@FuzzySec) for PowerShell PoC

https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html

https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## ms16-135

### Description: 

Spawns a new Listener as SYSTEM by leveraging the MS16-135 local exploit. This exploit is for x64 only and only works on unlocked session. Note: the exploit performs fast windows switching, victim's desktop may flash. A named pipe is also created. Thus, opsec is not guaranteed

### Author:

@TinySecEx, @FuzzySec, ThePirateWhoSmellsOfSunflowers (github)

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

Credit to TinySec (@TinySecEx) for the initial PoC and

to Ruben Boonen (@FuzzySec) for PowerShell PoC

https://github.com/tinysec/public/tree/master/CVE-2016-7255

https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135

https://security.googleblog.com/2016/10/disclosing-vulnerabilities-to-protect.html

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 
*****

## powerup/allchecks

### Description: 

Runs all current checks for Windows privesc vectors.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/powerup) Code

Back to [Index](#index)





 
*****

## powerup/find_dllhijack

### Description: 

Finds generic .DLL hijacking opportunities.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ExcludeOwned** | Switch. Exclude processes the current user owns. | False |  |
| **ExcludeProgramFiles** | Switch. Exclude paths from C:\Program Files\* and C:\Program Files (x86)\* | False |  |
| **ExcludeWindows** | Switch. Exclude paths from C:\Windows\* instead of just C:\Windows\System32\* | False |  |

### Comments:

https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/powerup) Code

Back to [Index](#index)





 
*****

## powerup/service_exe_restore

### Description: 

Restore a backed up service binary.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **BackupPath** | The service name to manipulate. | False |  |
| **ServiceName** | The service name to manipulate. | True |  |

### Comments:

https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/powerup) Code

Back to [Index](#index)





 
*****

## powerup/service_exe_stager

### Description: 

Backs up a service's binary and replaces the original with a binary that launches a stager.bat.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Delete** | Switch. Have the launcher.bat delete itself after running. | False | True |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **ServiceName** | The service name to manipulate. | True |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/powerup) Code

Back to [Index](#index)





 
*****

## powerup/service_exe_useradd

### Description: 

Backs up a service's binary and replaces the original with a binary that creates/adds a local administrator.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **LocalGroup** | Local group to add the user to. | False | Administrators |
| **Password** | Password to set for the added user. | False | Password123! |
| **ServiceName** | The service name to manipulate. | True |  |
| **UserName** | The username to add. | False | john |

### Comments:

https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/powerup) Code

Back to [Index](#index)





 
*****

## powerup/service_stager

### Description: 

Modifies a target service to execute an Empire stager.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **ServiceName** | The service name to manipulate. | True |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/powerup) Code

Back to [Index](#index)





 
*****

## powerup/service_useradd

### Description: 

Modifies a target service to create a local user and add it to the local administrators.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **LocalGroup** | Local group to add the user to. | False | Administrators |
| **Password** | Password to set for the added user. | False | Password123! |
| **ServiceName** | The service name to manipulate. | True |  |
| **UserName** | The username to add. | False | john |

### Comments:

https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/powerup) Code

Back to [Index](#index)





 
*****

## powerup/write_dllhijacker

### Description: 

Writes out a hijackable .dll to the specified path along with a stager.bat that's called by the .dll. wlbsctrl.dll works well for Windows 7. The machine will need to be restarted for the privesc to work.

### Author:

leechristensen (@tifkin_), @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **DllPath** | The output path for the hijackable .dll. | True |  |
| **Listener** | Listener to use. | True |  |
| **Proxy** | Proxy to use for request (default, none, or other). | False | default |
| **ProxyCreds** | Proxy credentials ([domain\]username:password) to use for request (default, none, or other). | False | default |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/powerup) Code

Back to [Index](#index)





 
*****

## tater

### Description: 

Tater is a PowerShell implementation of the Hot Potato Windows Privilege Escalation exploit from @breenmachine and @foxglovesec.

### Author:

Kevin Robertson

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Command** | Command to execute during privilege escalation. Do not wrap in quotes and use PowerShell character escapes where necessary. | True |  |
| **ExhaustUDP** | Enable/Disable UDP port exhaustion to force all DNS lookups to fail in order to fallback to NBNS resolution (Y/N). | False | N |
| **Hostname** | Hostname to spoof. WPAD.DOMAIN.TLD may be required by Windows Server 2008. | False | WPAD |
| **HTTPPort** | TCP port for the HTTP listener. | False | 80 |
| **IP** | Specific local IP address for NBNS spoofer. | False |  |
| **NBNS** | Enable/Disable NBNS bruteforce spoofing (Y/N). | False | Y |
| **NBNSLimit** | Enable/Disable NBNS bruteforce spoofer limiting to stop NBNS spoofing while hostname is resolving correctly (Y/N). | False | Y |
| **RunTime** | Run time duration in minutes. | False |  |
| **SpooferIP** | IP address included in NBNS response. This is needed when using two hosts to get around an in-use port 80 on the privesc target. | False |  |
| **TaskDelete** | Enable/Disable scheduled task deletion for trigger 2. If enabled, a random string will be added to the taskname to avoid failures after multiple trigger 2 runs. | False | Y |
| **Taskname** | Scheduled task name to use with trigger 2. If you observe that Tater does not work after multiple trigger 2 runs, try changing the taskname. | False | Empire |
| **Trigger** | Trigger type to use in order to trigger HTTP to SMB relay. 0 = None, 1 = Windows Defender Signature Update, 2 = Windows 10 Webclient/Scheduled Task | False | 1 |
| **WPADDirectHosts** | Comma separated list of hosts to include as direct in the wpad.dat file. Note that localhost is always listed as direct. Add the Empire host to avoid catching Empire HTTP traffic. | False |  |
| **WPADPort** | Proxy server port to be included in the wpad.dat file. | False | 80 |

### Comments:

https://github.com/Kevin-Robertson/Tater

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | privesc |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc) Code

Back to [Index](#index)





 

***

## powershell - recon

 - [find_fruit](#find_fruit)
 - [get_sql_server_login_default_pw](#get_sql_server_login_default_pw)
 - [http_login](#http_login)
 
*****

## find_fruit

### Description: 

Searches a network range for potentially vulnerable web services.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **FoundOnly** | Switch. Show only found sites | False | True |
| **Path** | Specify the path to a dictionary file. | False |  |
| **Port** | Specify the port to scan. | False |  |
| **Rhosts** | Specify the CIDR range or host to scan. | True |  |
| **ShowAll** | Switch. Show all results (default is to only show 200s). | False |  |
| **Threads** | The maximum concurrent threads to execute. | False | 10 |
| **Timeout** | Set timeout for each connection in milliseconds | False | 50 |
| **UseSSL** | Force SSL useage. | False |  |

### Comments:

Inspired by mattifestation Get-HttpStatus in PowerSploit

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | recon |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/recon) Code

Back to [Index](#index)





 
*****

## get_sql_server_login_default_pw

### Description: 

Based on the instance name, test if SQL Server is configured with default passwords.

### Author:

@_nullbind, @0xbadjuju

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CheckAll** | Check all systems retrieved by Get-SQLInstanceDomain. | False |  |
| **Instance** | SQL Server instance to connection to. | False |  |
| **Password** | SQL Server or domain account password to authenticate with. Only used for CheckAll | False |  |
| **Username** | SQL Server or domain account to authenticate with. Only used for CheckAll | False |  |

### Comments:

https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1

https://github.com/pwnwiki/pwnwiki.github.io/blob/master/tech/db/mssql.md

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | recon |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/recon) Code

Back to [Index](#index)





 
*****

## http_login

### Description: 

Tests credentials against Basic Authentication.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Dictionary** | Set the password dictionary file. | False |  |
| **Directory** | Specify the path to authentication (e.g. /manager/html) | False |  |
| **NoPing** | Switch. Disable ping check. | False |  |
| **Password** | Set the password to test. | False |  |
| **Port** | Specify the port to scan. | False |  |
| **Rhosts** | Specify the CIDR range or host to scan. | True |  |
| **Threads** | The maximum concurrent threads to execute. | False |  |
| **Username** | Set the username to test. | False |  |
| **UseSSL** | Force SSL useage. | False |  |

### Comments:

http://www.rvrsh3ll.net

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | recon |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/recon) Code

Back to [Index](#index)





 

***

## powershell - situational_awareness

 - [host/antivirusproduct](#host/antivirusproduct)
 - [host/computerdetails](#host/computerdetails)
 - [host/dnsserver](#host/dnsserver)
 - [host/findtrusteddocuments](#host/findtrusteddocuments)
 - [host/get_pathacl](#host/get_pathacl)
 - [host/get_proxy](#host/get_proxy)
 - [host/get_uaclevel](#host/get_uaclevel)
 - [host/monitortcpconnections](#host/monitortcpconnections)
 - [host/paranoia](#host/paranoia)
 - [host/winenum](#host/winenum)
 - [network/arpscan](#network/arpscan)
 - [network/bloodhound](#network/bloodhound)
 - [network/get_exploitable_system](#network/get_exploitable_system)
 - [network/get_spn](#network/get_spn)
 - [network/get_sql_instance_domain](#network/get_sql_instance_domain)
 - [network/get_sql_server_info](#network/get_sql_server_info)
 - [network/portscan](#network/portscan)
 - [network/powerview/find_computer_field](#network/powerview/find_computer_field)
 - [network/powerview/find_foreign_group](#network/powerview/find_foreign_group)
 - [network/powerview/find_foreign_user](#network/powerview/find_foreign_user)
 - [network/powerview/find_gpo_computer_admin](#network/powerview/find_gpo_computer_admin)
 - [network/powerview/find_gpo_location](#network/powerview/find_gpo_location)
 - [network/powerview/find_localadmin_access](#network/powerview/find_localadmin_access)
 - [network/powerview/find_managed_security_group](#network/powerview/find_managed_security_group)
 - [network/powerview/find_user_field](#network/powerview/find_user_field)
 - [network/powerview/get_cached_rdpconnection](#network/powerview/get_cached_rdpconnection)
 - [network/powerview/get_computer](#network/powerview/get_computer)
 - [network/powerview/get_dfs_share](#network/powerview/get_dfs_share)
 - [network/powerview/get_domain_controller](#network/powerview/get_domain_controller)
 - [network/powerview/get_domain_policy](#network/powerview/get_domain_policy)
 - [network/powerview/get_domain_trust](#network/powerview/get_domain_trust)
 - [network/powerview/get_fileserver](#network/powerview/get_fileserver)
 - [network/powerview/get_forest](#network/powerview/get_forest)
 - [network/powerview/get_forest_domain](#network/powerview/get_forest_domain)
 - [network/powerview/get_gpo](#network/powerview/get_gpo)
 - [network/powerview/get_gpo_computer](#network/powerview/get_gpo_computer)
 - [network/powerview/get_group](#network/powerview/get_group)
 - [network/powerview/get_group_member](#network/powerview/get_group_member)
 - [network/powerview/get_localgroup](#network/powerview/get_localgroup)
 - [network/powerview/get_loggedon](#network/powerview/get_loggedon)
 - [network/powerview/get_object_acl](#network/powerview/get_object_acl)
 - [network/powerview/get_ou](#network/powerview/get_ou)
 - [network/powerview/get_rdp_session](#network/powerview/get_rdp_session)
 - [network/powerview/get_session](#network/powerview/get_session)
 - [network/powerview/get_site](#network/powerview/get_site)
 - [network/powerview/get_subnet](#network/powerview/get_subnet)
 - [network/powerview/get_user](#network/powerview/get_user)
 - [network/powerview/map_domain_trust](#network/powerview/map_domain_trust)
 - [network/powerview/process_hunter](#network/powerview/process_hunter)
 - [network/powerview/set_ad_object](#network/powerview/set_ad_object)
 - [network/powerview/share_finder](#network/powerview/share_finder)
 - [network/powerview/user_hunter](#network/powerview/user_hunter)
 - [network/reverse_dns](#network/reverse_dns)
 - [network/smbautobrute](#network/smbautobrute)
 - [network/smbscanner](#network/smbscanner)
 
*****

## host/antivirusproduct

### Description: 

Get antivirus product information.

### Author:

@mh4x0f, Jan Egil Ring

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Computername to run the module on, defaults to localhost. | False |  |

### Comments:

http://blog.powershell.no/2011/06/12/use-windows-powershell-to-get-antivirus-product-information/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/computerdetails

### Description: 

Enumerates useful information on the system. By default, all checks are run.

### Author:

@JosephBialek

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **4624** | Switch. Only return 4624 logon information (logons to this machine). | False |  |
| **4648** | Switch. Only return 4648 logon information (RDP to another machine). | False |  |
| **Agent** | Agent to run module on. | True |  |
| **AppLocker** | Switch. Only return AppLocker logs. | False |  |
| **Limit** | Limit the number of event log entries returned. Defaults to 100 | False | 100 |
| **PSScripts** | Switch. Only return PowerShell scripts run from operational log. | False |  |
| **SavedRDP** | Switch. Only return saved RDP connections. | False |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-ComputerDetails.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/dnsserver

### Description: 

Enumerates the DNS Servers used by a system.

### Author:

DarkOperator

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/findtrusteddocuments

### Description: 

This module will enumerate the appropriate registry keys to determine what, if any, trusted documents exist on the host.  It will also enumerate trusted locations.

### Author:

@jamcut

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to enumerate trusted documents from. | True |  |

### Comments:

Original .ps1 file

https://github.com/jamcut/one-offs/blob/master/Find-TrustedDocuments.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/get_pathacl

### Description: 

Enumerates the ACL for a given file path.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Path** | The local/remote (UNC) path to enumerate the ACLs for. | True |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/get_proxy

### Description: 

Enumerates the proxy server and WPAD conents for the current user. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | The computername to enumerate proxy settings on. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/get_uaclevel

### Description: 

Enumerates UAC level

### Author:

Petr Medonos

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://gallery.technet.microsoft.com/How-to-switch-UAC-level-0ac3ea11

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/monitortcpconnections

### Description: 

Monitors hosts for TCP connections to a specified domain name or IPv4 address. Useful for session hijacking and finding users interacting with sensitive services.

### Author:

@erikbarzdukas

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to monitor from. | True |  |
| **CheckInterval** | Interval in seconds to check for the connection | True | 15 |
| **TargetDomain** | Domain name or IPv4 address of target service. | True |  |

### Comments:

Based on code from Tim Ferrell.

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/paranoia

### Description: 

Continuously check running processes for the presence of suspicious users, members of groups, process names, and for any processes running off of USB drives.

### Author:

pasv

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to deploy Paranoia on. | True |  |
| **WatchGroups** | AD Groups to watch out for (Default is 'Domain Admins') | False |  |
| **WatchProcesses** | Process names to watch out for. Default list is already appended. | False |  |
| **WatchUsers** | Users to watch out for in the form of domain\user, domain\user2, localuser | False |  |

### Comments:

http://shell.fishing/code/Invoke-Paranoia.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## host/winenum

### Description: 

Collects revelant information about a host and the current user context.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Keywords** | Array of keywords to use in file searches. | False |  |
| **UserName** | UserName to enumerate. Defaults to the current user context. | False |  |

### Comments:

https://github.com/xorrior/RandomPS-Scripts/blob/master/Invoke-WindowsEnum.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host) Code

Back to [Index](#index)





 
*****

## network/arpscan

### Description: 

Performs an ARP scan against a given range of IPv4 IP Addresses.

### Author:

DarkOperator

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CIDR** | CIDR to ARP scan. | False |  |
| **Range** | Range to ARP scan. | False |  |

### Comments:

https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/bloodhound

### Description: 

Execute BloodHound data collection.

### Author:

@harmj0y, @_wald0, @cptjesus

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CollectionMethod** | The method to collect data. 'Group', 'ComputerOnly', 'LocalGroup', 'GPOLocalGroup', 'Session', 'LoggedOn', 'Trusts, 'Stealth', or 'Default'. | True | Default |
| **ComputerADSpath** | The LDAP source to search through for computers, e.g. "LDAP://OU=secret,DC=testlab,DC=local" | False |  |
| **ComputerName** | Array of one or more computers to enumerate | False |  |
| **CSVFolder** | The CSV folder to use for output, defaults to the current folder location. | False | $(Get-Location) |
| **CSVPrefix** | A prefix for all CSV files. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **GlobalCatalog** | The global catalog location to resolve user memberships from. | False |  |
| **SearchForest** | Switch. Search all domains in the forest. | False |  |
| **SkipGCDeconfliction** | Switch. Skip global catalog enumeration for session deconfliction | False |  |
| **Threads** | The maximum concurrent threads to execute. | True | 20 |
| **Throttle** | The number of cypher queries to queue up for neo4j RESTful API ingestion. | True | 1000 |
| **URI** | The BloodHound neo4j URL location (http://host:port/) | False |  |
| **UserADSPath** | The LDAP source to search through for users/groups, e.g. "LDAP://OU=secret,DC=testlab,DC=local" | False |  |
| **UserPass** | The "user:password" for the BloodHound neo4j instance | False |  |

### Comments:

https://bit.ly/getbloodhound

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/get_exploitable_system

### Description: 

Queries Active Directory for systems likely vulnerable to various Metasploit exploits.

### Author:

Scott Sutherland (@_nullbind)

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Return computers with a specific name, wildcards accepted. | False |  |
| **Domain** | The domain to query for computers, defaults to the current domain. | False |  |
| **Filter** | A customized ldap filter string to use, e.g. "(description=*admin*)" | False |  |
| **OperatingSystem** | Return computers with a specific operating system, wildcards accepted. | False |  |
| **Ping** | Switch. Ping each host to ensure it's up before enumerating. | False |  |
| **SPN** | Return computers with a specific service principal name, wildcards accepted. | False |  |

### Comments:

https://github.com/nullbind/Powershellery/blob/master/Stable-ish/ADS/Get-ExploitableSystems.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/get_spn

### Description: 

Displays Service Principal Names (SPN) for domain accounts based on SPN service name, domain account, or domain group via LDAP queries.

### Author:

@_nullbind

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Search** | Search string for group, username, or service name. Wildcards accepted. | False | MSSQL* |
| **Type** | 'group', 'user', or 'service' | False | service |

### Comments:

https://raw.githubusercontent.com/nullbind/Powershellery/master/Stable-ish/Get-SPN/Get-SPN.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/get_sql_instance_domain

### Description: 

Returns a list of SQL Server instances discovered by querying a domain controller for systems with registered MSSQL service principal names. The function will default to the current user's domain and logon server, but an alternative domain controller can be provided. UDP scanning of management servers is optional.

### Author:

@_nullbind, @0xbadjuju

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CheckMgmt** | Performs UDP scan of servers managing SQL Server clusters. | False | False |
| **ComputerName** | Computer name to filter for. | False |  |
| **DomainController** | Domain controller for Domain and Site that you want to query against. | False |  |
| **DomainServiceAccount** | Domain account to filter for. | False |  |
| **Password** | SQL Server or domain account password to authenticate with. | False |  |
| **UDPTimeOut** | Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate. | False | 3 |
| **Username** | SQL Server or domain account to authenticate with. | False |  |

### Comments:

https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/get_sql_server_info

### Description: 

Returns basic server and user information from target SQL Servers.

### Author:

@_nullbind, @0xbadjuju

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CheckAll** | Check all systems retrieved by Get-SQLInstanceDomain | False |  |
| **Instance** | SQL Server instance to connection to. | False |  |
| **Password** | SQL Server or domain account password to authenticate with. | False |  |
| **Username** | SQL Server or domain account to authenticate with. | False |  |

### Comments:

https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/portscan

### Description: 

Does a simple port scan using regular sockets, based (pretty) loosely on nmap.

### Author:

Rich Lundeen

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **AllformatsOut** | Output file of all formats. | False |  |
| **ExcludeHosts** | Exclude thsee comma separated hosts. | False |  |
| **GrepOut** | Greppable (.gnmap) output file. | False |  |
| **HostFile** | Input hosts from file (on the target) | False |  |
| **Hosts** | Hosts to scan. | False |  |
| **Open** | Switch. Only show hosts with open ports. | False | True |
| **PingOnly** | Switch. Ping only, don't scan for ports. | False |  |
| **Ports** | Comma separated ports to scan for. | False |  |
| **ReadableOut** | Readable (.nmap) output file. | False |  |
| **SkipDiscovery** | Switch. Treat all hosts as online. | False |  |
| **TopPorts** | Scan for X top ports, default 50. | False |  |
| **XmlOut** | .XML output file. | False |  |

### Comments:

https://github.com/mattifestation/PowerSploit/blob/master/Recon/Invoke-Portscan.ps1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/powerview/find_computer_field

### Description: 

Searches computer object fields for a given word (default *pass*). Default field being searched is 'description'. Part of PowerView.

### Author:

@obscuresec, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **SearchField** | Field to search in, default of "description". | False |  |
| **SearchTerm** | Term to search for, default of "pass". | False |  |

### Comments:

http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/find_foreign_group

### Description: 

Enumerates all the members of a given domain's groups and finds users that are not in the queried domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **GroupName** | Groupname to filter results for, wildcards accepted. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/find_foreign_user

### Description: 

Enumerates users who are in groups outside of their principal domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **UserName** | Username to filter results for, wildcards accepted. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/find_gpo_computer_admin

### Description: 

Takes a computer (or GPO) object and determines what users/groups have administrative access over it. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | The computer to determine local administrative access to. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **LocalGroup** | The local group to check access against, "Administrators", "RDP/Remote Desktop Users", or a custom SID. Defaults to "Administrators". | False |  |
| **OUName** | OU name to determine who has local adminisrtative acess to computers within it. | False |  |
| **Recurse** | Switch. If a returned member is a group, recurse and get all members. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/find_gpo_location

### Description: 

Takes a user/group name and optional domain, and determines the computers in the domain the user/group has local admin (or RDP) rights to. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **GroupName** | A (single) group name name to query for access. | False |  |
| **LocalGroup** | The local group to check access against, "Administrators", "RDP/Remote Desktop Users", or a custom SID. Defaults to "Administrators". | False |  |
| **UserName** | A (single) user name name to query for access. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/find_localadmin_access

### Description: 

Finds machines on the local domain where the current user has local administrator access. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerFilter** | Host filter name to query AD for, wildcards accepted. | False |  |
| **ComputerName** | Hosts to enumerate, comma separated. | False |  |
| **Delay** | Delay between enumerating hosts, defaults to 0. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **NoPing** | Don't ping each host to ensure it's up before enumerating. | False |  |
| **Threads** | The maximum concurrent threads to execute. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/find_managed_security_group

### Description: 

This function retrieves all security groups in the domain and identifies ones that have a manager set. It also determines whether the manager has the ability to add or remove members from the group. Part of PowerView.

### Author:

@ukstufus

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/https://github.com/PowerShellEmpire/Empire/pull/119

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/find_user_field

### Description: 

Searches user object fields for a given word (default *pass*). Default field being searched is 'description'. Part of PowerView.

### Author:

@obscuresec, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **SearchField** | Field to search in, default of "description". | False |  |
| **SearchTerm** | Term to search for, default of "pass". | False |  |

### Comments:

http://obscuresecurity.blogspot.com/2014/04/ADSISearcher.html

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_cached_rdpconnection

### Description: 

Uses remote registry functionality to query all entries for the Windows Remote Desktop Connection Client" on a machine. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | The hostname or IP to query for local group users. | False | localhost |
| **RemotePassword** | The password to use for the WMI call on a remote system. | False |  |
| **RemoteUserName** | The "domain\username" to use for the WMI call on the remote system. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_computer

### Description: 

Queries the domain for current computer objects. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Return computers with a specific name, wildcards accepted. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **Filter** | A customized ldap filter string to use, e.g. "(description=*admin*)" | False |  |
| **FullData** | Switch. Return full computer objects instead of just system names (the default). | False |  |
| **OperatingSystem** | Return computers with a specific operating system, wildcards accepted. | False |  |
| **Ping** | Switch. Ping each host to ensure it's up before enumerating. | False |  |
| **Printers** | Switch. Return only printers. | False |  |
| **SPN** | Return computers with a specific service principal name, wildcards accepted. | False |  |
| **Unconstrained** | Switch. Return computer objects that have unconstrained delegation. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_dfs_share

### Description: 

Returns a list of all fault-tolerant distributed file systems for a given domain. Part of PowerView.

### Author:

@meatballs__

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain whose trusts to enumerate, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_domain_controller

### Description: 

Returns the domain controllers for the current domain or the specified domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to query for domain controllers. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **LDAP** | Switch. Use LDAP queries to determine the domain controllers. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_domain_policy

### Description: 

Returns the default domain or DC policy for a given domain or domain controller. Part of PowerView.

### Author:

@harmj0y, @DisK0nn3cT, @OrOneEqualsOne

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to query for default policies, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **ExpandObject** | Expand a specific object from the domain policy. For example 'System Access', entered without quotes | False |  |
| **FullData** | Switch. Return full subnet objects instead of just object names (the default). | False |  |
| **ResolveSids** | Switch. Resolve Sids from a DC policy to object names. | False |  |
| **Source** | Extract Domain or DC (domain controller) policies. | True | Domain |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_domain_trust

### Description: 

Return all domain trusts for the current domain or a specified domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain whose trusts to enumerate, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **LDAP** | Switch. Use LDAP queries to enumerate the trusts instead of direct domain connections. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_fileserver

### Description: 

Returns a list of all file servers extracted from user homedirectory, scriptpath, and profilepath fields. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain whose trusts to enumerate, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_forest

### Description: 

Return information about a given forest, including the root domain and SID. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Forest** | The forest name to query domain for, defaults to the current forest. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_forest_domain

### Description: 

Return all domains for a given forest. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Forest** | The forest name to query domain for, defaults to the current forest. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_gpo

### Description: 

Gets a list of all current GPOs in a domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSpath** | The LDAP source to search through. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Return all GPO objects applied to a given computer (FQDN). | False |  |
| **DisplayName** | The GPO display name to query for, wildcards accepted. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **GPOname** | The GPO name to query for, wildcards accepted. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_gpo_computer

### Description: 

Takes a GPO GUID and returns the computers the GPO is applied to. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **GUID** | The GUID of the GPO to enumerate. | True |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_group

### Description: 

Gets a list of all current groups in a domain, or all the groups a given user/group object belongs to. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **AdminCount** | Switch. Return groups with adminCount=1 (i.e. privileged groups). | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **Filter** | A customized ldap filter string to use, e.g. "(description=*admin*)" | False |  |
| **FullData** | Return full group objects instead of just object names (the default). | False |  |
| **GroupName** | The group name to query for, wildcards accepted. | False |  |
| **SID** | The group SID to query for. | False |  |
| **UserName** | The user name (or group name) to query for all effective groups of. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_group_member

### Description: 

Returns the members of a given group, with the option to "Recurse" to find all effective group members. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **Filter** | A customized ldap filter string to use, e.g. "(description=*admin*)" | False |  |
| **FullData** | Return full group objects instead of just object names (the default). | False |  |
| **GroupName** | The group name to query for users. | False | "Domain Admins" |
| **Recurse** | Switch. If the group member is a group, recursively try to query its members as well. | False |  |
| **SID** | The Group SID to query for users. | False |  |
| **UseMatchingRule** | Switch. Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query when -Recurse is specified. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_localgroup

### Description: 

Returns a list of all current users in a specified local group on a local or remote machine. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **API** | Switch. Use API calls instead of the WinNT service provider. Less information, but the results are faster. | False |  |
| **ComputerName** | The hostname or IP to query for local group users. | False | localhost |
| **GroupName** | The local group name to query for users, defaults to "Administrators". | False | Administrators |
| **ListGroups** | Switch. List all the local groups instead of their members. | False |  |
| **Recurse** | Switch. If the local member member is a domain group, recursively try to resolve its members to get a list of domain users who can access this machine. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_loggedon

### Description: 

Execute the NetWkstaUserEnum Win32API call to query a given host for actively logged on users. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | The hostname or IP to query for local group users. | False | localhost |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_object_acl

### Description: 

Returns the ACLs associated with a specific active directory object. Part of PowerView. WARNING: specify a specific object, otherwise a huge amount of data will be returned.

### Author:

@harmj0y, @pyrotek3

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSpath** | The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local" | False |  |
| **ADSprefix** | Prefix to set for the searcher (like "CN=Sites,CN=Configuration") | False |  |
| **Agent** | Agent to run module on. | True |  |
| **DistinguishedName** | Object distinguished name to filter for. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **Filter** | A customized ldap filter string to use, e.g. "(description=*admin*)" | False |  |
| **Name** | Object Name to filter for. | False |  |
| **ResolveGUIDs** | Switch. Resolve GUIDs to their display names. | False | True |
| **RightsFilter** | Only return results with the associated rights, "All", "ResetPassword","ChangePassword","WriteMembers" | False |  |
| **SamAccountName** | Object SamAccountName to filter for. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_ou

### Description: 

Gets a list of all current OUs in a domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSpath** | The LDAP source to search through. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **FullData** | Switch. Return full OU objects instead of just object names (the default). | False |  |
| **GUID** | Only return OUs with the specified GUID in their gplink property. | False |  |
| **OUName** | The OU name to query for, wildcards accepted. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_rdp_session

### Description: 

Query a given RDP remote service for active sessions and originating IPs (replacement for qwinsta). Note: needs admin rights on the remote server you're querying

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | The hostname to query for active RDP sessions. | True | localhost |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_session

### Description: 

Execute the NetSessionEnum Win32API call to query a given host for active sessions on the host. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | The hostname or IP to query for local group users. | False | localhost |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_site

### Description: 

Gets a list of all current sites in a domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSpath** | The LDAP source to search through. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **FullData** | Switch. Return full site objects instead of just object names (the default). | False |  |
| **GUID** | Only return site with the specified GUID in their gplink property. | False |  |
| **SiteName** | Site filter string, wildcards accepted. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_subnet

### Description: 

Gets a list of all current subnets in a domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **ADSpath** | The LDAP source to search through. | False |  |
| **Agent** | Agent to run module on. | True |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **FullData** | Switch. Return full subnet objects instead of just object names (the default). | False |  |
| **SiteName** | Only return subnets from the specified SiteName. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/get_user

### Description: 

Query information for a given user or users in the specified domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **AdminCount** | Switch. Return users with adminCount=1 (i.e. privileged users). | False |  |
| **ADSpath** | The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local" | False |  |
| **Agent** | Agent to run module on. | True |  |
| **AllowDelegation** | Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **Filter** | A customized ldap filter string to use, e.g. "(description=*admin*)" | False |  |
| **SPN** | Switch. Only return user objects with non-null service principal names. | False |  |
| **UserName** | Username filter string, wildcards accepted. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/map_domain_trust

### Description: 

Maps all reachable domain trusts with .CSV output. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **LDAP** | Switch. Use LDAP for domain queries (less accurate). | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/process_hunter

### Description: 

Query the process lists of remote machines, searching for processes with a specific name or owned by a specific user. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerFilter** | Host filter name to query AD for, wildcards accepted. | False |  |
| **ComputerName** | Hosts to enumerate. | False |  |
| **Delay** | Delay between enumerating hosts, defaults to 0. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **GroupName** | Group name to query for target users. | False |  |
| **NoPing** | Don't ping each host to ensure it's up before enumerating. | False |  |
| **ProcessName** | The name of the process to hunt, or a comma separated list of names. | False |  |
| **StopOnSuccess** | Switch. Stop hunting after finding after finding a target user. | False |  |
| **TargetServer** | Hunt for users who are effective local admins on a target server. | False |  |
| **Threads** | The maximum concurrent threads to execute. | False |  |
| **UserFilter** | A customized ldap filter string to use for user enumeration, e.g. "(description=*admin*)" | False |  |
| **UserName** | Specific username to search for. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/set_ad_object

### Description: 

Takes a SID, name, or SamAccountName to query for a specified domain object, and then sets a specified "PropertyName" to a specified "PropertyValue". Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ClearValue** | Switch. Clear the value of PropertyName. | False |  |
| **Domain** | The domain to query for objects, defaults to the current domain. | False |  |
| **Name** | The name of the domain object you're querying for. | False |  |
| **PropertyName** | The property name to set. | False |  |
| **PropertyValue** | The value to set for PropertyName. | False |  |
| **PropertyXorValue** | Integer calue to binary xor (-bxor) with the current int value. | False |  |
| **SamAccountName** | The SamAccountName of the domain object you're querying for | False |  |
| **SID** | The SID of the domain object you're querying for. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/share_finder

### Description: 

Finds shares on machines in the domain. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CheckShareAccess** | Switch. Only display found shares that the local user has access to. | False |  |
| **ComputerFilter** | Host filter name to query AD for, wildcards accepted. | False |  |
| **ComputerName** | Hosts to enumerate. | False |  |
| **Delay** | Delay between enumerating hosts, defaults to 0. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **NoPing** | Don't ping each host to ensure it's up before enumerating. | False |  |
| **Threads** | The maximum concurrent threads to execute. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/powerview/user_hunter

### Description: 

Finds which machines users of a specified group are logged into. Part of PowerView.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CheckAccess** | Switch. Check if the current user has local admin access to found machines. | False |  |
| **ComputerFilter** | Host filter name to query AD for, wildcards accepted. | False |  |
| **ComputerName** | Hosts to enumerate. | False |  |
| **Delay** | Delay between enumerating hosts, defaults to 0. | False |  |
| **Domain** | The domain to use for the query, defaults to the current domain. | False |  |
| **DomainController** | Domain controller to reflect LDAP queries through. | False |  |
| **GroupName** | Group name to query for target users. | False |  |
| **NoPing** | Don't ping each host to ensure it's up before enumerating. | False |  |
| **ShowAll** | Switch. Return all user location results without filtering. | False |  |
| **Stealth** | Switch. Only enumerate sessions from connonly used target servers. | False |  |
| **StopOnSuccess** | Switch. Stop hunting after finding after finding a target user. | False |  |
| **TargetServer** | Hunt for users who are effective local admins on a target server. | False |  |
| **Threads** | The maximum concurrent threads to execute. | False |  |
| **UserFilter** | A customized ldap filter string to use for user enumeration, e.g. "(description=*admin*)" | False |  |
| **UserName** | Specific username to search for. | False |  |

### Comments:

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview) Code

Back to [Index](#index)





 
*****

## network/reverse_dns

### Description: 

Performs a DNS Reverse Lookup of a given IPv4 IP Range.

### Author:

DarkOperator

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **CIDR** | CIDR to perform reverse DNS on. | False |  |
| **Range** | Range to perform reverse DNS on. | False |  |

### Comments:

https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/smbautobrute

### Description: 

Runs an SMB brute against a list of usernames/passwords. Will check the DCs to interrogate the bad password count of the users and will keep bruting until either a valid credential is discoverd or the bad password count reaches one below the threshold. Run "shell net accounts" on a valid agent to determine the lockout threshold. VERY noisy! Generates a ton of traffic on the DCs.

### Author:

@curi0usJack

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run smbautobrute from. | True |  |
| **Delay** | Amount of time to wait (in milliseconds) between attempts. Default 100. | False |  |
| **LockoutThreshold** | The max number of bad password attempts until the account locks. Autobrute will try till one less than this setting. | True |  |
| **PasswordList** | Comma separated list of passwords to test. Wrap in double quotes. | True |  |
| **ShowVerbose** | Show failed attempts & skipped accounts in addition to success. | False |  |
| **StopOnSuccess** | Quit running after the first successful authentication. | False |  |
| **UserList** | File of users to brute (on the target), one per line. If not specified, autobrute will query a list of users with badpwdcount < LockoutThreshold - 1 for each password brute. Wrap path in double quotes. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/smbscanner

### Description: 

Tests a username/password combination across a number of machines.

### Author:

@obscuresec, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ComputerName** | Comma-separated hostnames to try username/password combinations against. Otherwise enumerate the domain for machines. | False |  |
| **CredID** | CredID from the store to use. | False |  |
| **NoPing** | Switch. Don't ping hosts before enumeration. | False |  |
| **Password** | Password to test. | True |  |
| **UserName** | [domain\]username to test. | True |  |

### Comments:

https://gist.github.com/obscuresec/df5f652c7e7088e2412c

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network) Code

Back to [Index](#index)





 

***

## powershell - trollsploit

 - [beeptune](#beeptune)
 - [get_schwifty](#get_schwifty)
 - [message](#message)
 - [process_killer](#process_killer)
 - [rick_ascii](#rick_ascii)
 - [rick_astley](#rick_astley)
 - [thunderstruck](#thunderstruck)
 - [voicetroll](#voicetroll)
 - [wallpaper](#wallpaper)
 - [wlmdr](#wlmdr)
 
*****

## beeptune

### Description: 

Play Various Beep Tunes (at Loopable Interval)

### Author:

@SadProcessor

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **Loop** | Switch Endless Loop -> True/False | False | False |
| **Sleep** | Sleep between loops -> 1 to 3600 sec | False | 1 |
| **Tune** | Select Tune -> Vador/Sergei/Rick/Mario/Tom | False | Vador |

### Comments:

No Comments

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## get_schwifty

### Description: 

Play's a hidden version of Rick and Morty Get Schwifty video while maxing out a computer's volume.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **VideoURL** | Other YouTube video URL to play instead of Get Schwifty. | False |  |

### Comments:

https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## message

### Description: 

Displays a specified message to the user.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **IconType** | Critical, Question, Exclamation, or Information | True | Critical |
| **MsgText** | Message text to display. | True | Lost contact with the Domain Controller. |
| **Title** | Title of the message box to display. | True | ERROR - 0xA801B720 |

### Comments:

http://blog.logrhythm.com/security/do-you-trust-your-computer/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## process_killer

### Description: 

Kills any process starting with a particular name.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **ProcessName** | Process name to kill on starting (wildcards accepted). | True |  |
| **Silent** | Switch. Don't output kill messages. | False |  |
| **Sleep** | Time to sleep between checks. | True | 1 |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## rick_ascii

### Description: 

Spawns a a new powershell.exe process that runs Lee Holmes' ASCII Rick Roll.

### Author:

@lee_holmes, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

http://www.leeholmes.com/blog/2011/04/01/powershell-and-html5/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## rick_astley

### Description: 

Runs @SadProcessor's beeping rickroll.

### Author:

@SadProcessor, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |

### Comments:

https://gist.github.com/SadProcessor/3e413f9542b01ee90979

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## thunderstruck

### Description: 

Play's a hidden version of AC/DC's Thunderstruck video while maxing out a computer's volume.

### Author:

@obscuresec

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **VideoURL** | Other YouTube video URL to play instead of Thunderstruck. | False |  |

### Comments:

https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## voicetroll

### Description: 

Reads text aloud via synthesized voice on target.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **VoiceText** | Text to synthesize on target. | True |  |

### Comments:

http://www.instructables.com/id/Make-your-computer-talk-with-powershell/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## wallpaper

### Description: 

Uploads a .jpg image to the target and sets it as the desktop wallpaper.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **LocalImagePath** | Local image path to set the agent wallpaper as. | True |  |

### Comments:

https://social.technet.microsoft.com/forums/scriptcenter/en-US/9af1769e-197f-4ef3-933f-83cb8f065afb/background-change

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 
*****

## wlmdr

### Description: 

Displays a balloon reminder in the taskbar.

### Author:

@benichmt1

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run module on. | True |  |
| **IconType** | Critical, Exclamation, Information, Key, or None | True | Key |
| **Message** | Message text to display. | True | You are using a pirated version of Microsoft Windows. |
| **Title** | Title of the message box to display. | True | Windows Explorer |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | True |
| **Category**    | trollsploit |
| **Language**    | powershell |
| **Min Version** | 2 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/data/module_source/trollsploit) Code

Back to [Index](#index)





 

***

# python

Back to [Index](#index) 

***

## python - collection

 - [linux/hashdump](#linux/hashdump)
 - [linux/keylogger](#linux/keylogger)
 - [linux/mimipenguin](#linux/mimipenguin)
 - [linux/pillage_user](#linux/pillage_user)
 - [linux/sniffer](#linux/sniffer)
 - [linux/xkeylogger](#linux/xkeylogger)
 - [osx/browser_dump](#osx/browser_dump)
 - [osx/clipboard](#osx/clipboard)
 - [osx/hashdump](#osx/hashdump)
 - [osx/imessage_dump](#osx/imessage_dump)
 - [osx/kerberosdump](#osx/kerberosdump)
 - [osx/keychaindump](#osx/keychaindump)
 - [osx/keychaindump_chainbreaker](#osx/keychaindump_chainbreaker)
 - [osx/keylogger](#osx/keylogger)
 - [osx/native_screenshot](#osx/native_screenshot)
 - [osx/pillage_user](#osx/pillage_user)
 - [osx/prompt](#osx/prompt)
 - [osx/screensaver_alleyoop](#osx/screensaver_alleyoop)
 - [osx/screenshot](#osx/screenshot)
 - [osx/search_email](#osx/search_email)
 - [osx/sniffer](#osx/sniffer)
 - [osx/webcam](#osx/webcam)
 
*****

## linux/hashdump

### Description: 

Extracts the /etc/passwd and /etc/shadow, unshadowing the result.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/linux) Code

Back to [Index](#index)





 
*****

## linux/keylogger

### Description: 

Logs keystrokes to the specified file. Ruby based and heavily adapted from MSF's osx/capture/keylog_recorder. Kill the resulting PID when keylogging is finished and download the specified LogFile.

### Author:

joev, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to keylog. | True |  |
| **LogFile** | Text file to log keystrokes out to. | True | /tmp/debug.db |

### Comments:

https://github.com/amoffat/pykeylogger

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/linux) Code

Back to [Index](#index)





 
*****

## linux/mimipenguin

### Description: 

Port of huntergregal mimipenguin. Harvest's current user's cleartext credentials.

### Author:

@rvrsh3ll

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/linux) Code

Back to [Index](#index)





 
*****

## linux/pillage_user

### Description: 

Pillages the current user for their bash_history, ssh known hosts, recent folders, etc. 

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **AllUsers** | Switch. Run for all users (needs root privileges!) | False | False |
| **Sleep** | Switch. Sleep the agent's normal interval between downloads, otherwise use one blast. | False | True |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/linux) Code

Back to [Index](#index)





 
*****

## linux/sniffer

### Description: 

This module will sniff all interfaces on the target, and write in pcap format.

### Author:

@Killswitch_GUI

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run sniffer on. | True |  |
| **InMemory** | Store binary data in memory, never drop to disk (WARNING: set MaxSize). | False | True |
| **IpFilter** | Set IP to filter on (dst & src). | False | 0 |
| **MaxPackets** | Set max packets to capture. | True | 100 |
| **MaxSize** | Set max file size to save to disk/memory (MB). | True | 1 |
| **PortFilter** | Set port to filter on (dst & src). | False | 0 |
| **SavePath** | Path of the  file to save (Not used if InMemory is True. | True | /tmp/debug.pcap |

### Comments:

For full comments and code: https://gist.github.com/killswitch-GUI/314e79581f2619a18d94c81d53e5466f

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** |pcap |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/linux) Code

Back to [Index](#index)





 
*****

## linux/xkeylogger

### Description: 

X userland keylogger based on pupy

### Author:

Nikaiw

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to keylog. | True |  |

### Comments:

WIP, might miss some keys, can't kill agent sometimes

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/linux) Code

Back to [Index](#index)





 
*****

## osx/browser_dump

### Description: 

This module will dump browser history from Safari and Chrome.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to keylog. | True |  |
| **Number** | Number of URLs to return. | True | 3 |

### Comments:

https://gist.github.com/dropmeaword/9372cbeb29e8390521c2

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/clipboard

### Description: 

This module will write log output of clipboard to stdout (or disk).

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to grab clipboard from. | True |  |
| **MonitorTime** | Optional for how long you would like to monitor clipboard in (s). | True | 0 |
| **OutFile** | Optional file to save the clipboard output to. | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/hashdump

### Description: 

Extracts found user hashes out of /var/db/dslocal/nodes/Default/users/*.plist

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |

### Comments:

http://apple.stackexchange.com/questions/186893/os-x-10-9-where-are-password-hashes-stored

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/imessage_dump

### Description: 

This module will enumerate the entire chat and IMessage SQL Database.

### Author:

Alex Rymdeko-Harvey, @Killswitch-GUI

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run from. | True |  |
| **Debug** | Enable a find keyword to search for within the iMessage Database. | True | False |
| **Messages** | The number of messages to enumerate from most recent. | True | 10 |
| **Search** | Enable a find keyword to search for within the iMessage Database. | False |  |

### Comments:

Using SQLite3 iMessage has a decent standard to correlate users to messages and isnt encrypted.

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/kerberosdump

### Description: 

This module will dump ccache kerberostickets to the specified directory

### Author:

@424f424f,@gentilkiwi

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to grab a tickets from. | True |  |

### Comments:

Thanks to @gentilkiwi for pointing this out!

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/keychaindump

### Description: 

Searches for keychain candidates and attempts to decrypt the user's keychain.

### Author:

Juuso Salonen

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **KeyChain** | Manual location of keychain to decrypt, otherwise default. | False |  |
| **TempDir** | Temporary directory to drop the keychaindump binary. | True | /tmp/ |

### Comments:

https://github.com/juuso/keychaindump

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/keychaindump_chainbreaker

### Description: 

A keychain dump module that allows for decryption via known password.

### Author:

@n0fate, @Killswitch-GUI

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **KeyChain** | Manual location of keychain to decrypt, otherwise default. | True | /Users/USERNAME/Library/Keychains/login.keychain |
| **MasterKey** | Master key candidate used in memory to decrypt keychain (recovered via mem-dump). | False |  |
| **Password** | Known user password to attempt to decrypt the Keychain. | True |  |

### Comments:

https://github.com/n0fate/chainbreaker

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/keylogger

### Description: 

Logs keystrokes to the specified file. Ruby based and heavily adapted from MSF's osx/capture/keylog_recorder. Kill the resulting PID when keylogging is finished and download the specified LogFile.

### Author:

joev, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to keylog. | True |  |
| **LogFile** | Text file to log keystrokes out to. | True | /tmp/debug.db |

### Comments:

https://github.com/gojhonny/metasploit-framework/blob/master/modules/post/osx/capture/keylog_recorder.rb

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/native_screenshot

### Description: 

Takes a screenshot of an OSX desktop using the Python Quartz libraries and returns the data.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** |png |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/pillage_user

### Description: 

Pillages the current user for their keychain, bash_history, ssh known hosts, recent folders, etc. For logon.keychain, use https://github.com/n0fate/chainbreaker .For other .plist files, check https://davidkoepi.wordpress.com/2013/07/06/macforensics5/

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **AllUsers** | Switch. Run for all users (needs root privileges!) | False | False |
| **Sleep** | Switch. Sleep the agent's normal interval between downloads, otherwise use one blast. | False | True |

### Comments:

https://davidkoepi.wordpress.com/2013/07/06/macforensics5/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/prompt

### Description: 

Launches a specified application with an prompt for credentials with osascript.

### Author:

@FuzzyNop, @harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **AppName** | The name of the application to launch. | True | App Store |
| **ListApps** | Switch. List applications suitable for launching. | False |  |
| **SandboxMode** | Switch. Launch a sandbox safe prompt | False |  |

### Comments:

https://github.com/fuzzynop/FiveOnceInYourLife

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/screensaver_alleyoop

### Description: 

Launches a screensaver with a prompt for credentials with osascript. This locks the user out until the password can unlock the user keychain. This allows you to prevent Sudo/su failed logon attempts. (credentials till I get them!)

### Author:

@FuzzyNop, @harmj0y, @enigma0x3, @Killswitch-GUI

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **ExitCount** | Exit Screensaver after # of attempts | True | 15 |
| **Verbose** | Agent to execute module on. | True | False |

### Comments:

https://github.com/fuzzynop/FiveOnceInYourLife

https://github.com/enigma0x3/Invoke-LoginPrompt

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/screenshot

### Description: 

Takes a screenshot of an OSX desktop using screencapture and returns the data.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **SavePath** | Path of the temporary screenshot file to save. | True | /tmp/out.png |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** |png |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/search_email

### Description: 

Searches for Mail .emlx messages, optionally only returning messages with the specified SeachTerm.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **SearchTerm** | Term to grep for in email messages. | False |  |

### Comments:

https://davidkoepi.wordpress.com/2013/07/06/macforensics5/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/sniffer

### Description: 

This module will do a full network stack capture.

### Author:

Alex Rymdeko-Harvey, @Killswitch-GUI

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run from. | True |  |
| **CaptureInterface** | Set interface name ie. en0 (Auto resolve by default) | False |  |
| **Debug** | Enable to get verbose message status (Dont enable OutputExtension for this). | True | False |
| **LibcDylib** | Path of the std C Dylib (Defualt) | True | /usr/lib/libSystem.B.dylib |
| **MaxPackets** | Set max packets to capture. | True | 100 |
| **PcapDylib** | Path of the Pcap Dylib (Defualt) | True | /usr/lib/libpcap.A.dylib |
| **SavePath** | Path of the  file to save | True | /tmp/debug.pcap |

### Comments:

Using libpcap.dylib we can perform full pcap on a remote host.

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** |pcap |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 
*****

## osx/webcam

### Description: 

Takes a picture of a person through OSX's webcam with an ImageSnap binary.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **TempDir** | Temporary directory to drop the ImageSnap binary and picture. | True | /tmp/ |

### Comments:

http://iharder.sourceforge.net/current/macosx/imagesnap/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | collection |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** |png |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/collection/osx) Code

Back to [Index](#index)





 

***

## python - exploit

 - [web/jboss_jmx](#web/jboss_jmx)
 
*****

## web/jboss_jmx

### Description: 

Exploit JBoss java serialization flaw. Requires upload of ysoserial payload.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute on. | True |  |
| **Payload** | Path to ysoserial payload. | True |  |
| **URL** | URL to JMXInvoker | True | http://127.0.0.1:8080/invoker/JMXInvokerServlet |

### Comments:

Generate Payload with https://github.com/frohoff/ysoserial

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | exploit |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/exploit/web) Code

Back to [Index](#index)





 

***

## python - lateral_movement

 - [multi/ssh_command](#multi/ssh_command)
 - [multi/ssh_launcher](#multi/ssh_launcher)
 
*****

## multi/ssh_command

### Description: 

This module will send a command via ssh.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to use ssh from. | True |  |
| **Command** | Command | True | id |
| **Login** | user@127.0.0.1 | True |  |
| **Password** | Password | True |  |

### Comments:

http://stackoverflow.com/questions/17118239/how-to-give-subprocess-a-password-and-get-stdout-at-the-same-time

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | lateral_movement |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/lateral_movement/multi) Code

Back to [Index](#index)





 
*****

## multi/ssh_launcher

### Description: 

This module will send an launcher via ssh.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to use ssh from. | True |  |
| **Listener** | Listener to use. | True |  |
| **Login** | user@127.0.0.1 | True |  |
| **Password** | Password | True |  |
| **SafeChecks** | Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. | True | True |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

http://stackoverflow.com/questions/17118239/how-to-give-subprocess-a-password-and-get-stdout-at-the-same-time

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | lateral_movement |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/lateral_movement/multi) Code

Back to [Index](#index)





 

***

## python - management

 - [multi/kerberos_inject](#multi/kerberos_inject)
 - [multi/socks](#multi/socks)
 - [multi/spawn](#multi/spawn)
 - [osx/screen_sharing](#osx/screen_sharing)
 - [osx/shellcodeinject64](#osx/shellcodeinject64)
 
*****

## multi/kerberos_inject

### Description: 

Generates a kerberos keytab and injects it into the current runspace.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Hash** | NTLM Hash for the principal. | True |  |
| **Keytab** | Keytab file to create. | True | user.keytab |
| **Principal** | The service principal name. user@HACKME.COM | True |  |

### Comments:

Thanks to @passingthehash for bringing this up.

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | management |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/management/multi) Code

Back to [Index](#index)





 
*****

## multi/socks

### Description: 

Extend a SOCKSv5 proxy into your target network

### Author:

@klustic

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to proxy through | True |  |
| **HOST** | Host running the AlmondRocks server | True |  |
| **NoSSL** | Disable SSL (NOT RECOMMENDED!) | False | false |
| **PORT** | AlmondRocks server port | True |  |

### Comments:

Modified from: https://github.com/klustic/AlmondRocks

Use the server found in that Github repo with this module.

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | management |
| **Language**    | python |
| **Min Version** | 2.7 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/management/multi) Code

Back to [Index](#index)





 
*****

## multi/spawn

### Description: 

Spawns a new Empire agent.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/management/multi) Code

Back to [Index](#index)





 
*****

## osx/screen_sharing

### Description: 

Enables ScreenSharing to allow you to connect to the host via VNC.

### Author:

@n00py

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Password** | User password for sudo. | True |  |
| **VNCpass** | Password to use for VNC | True |  |

### Comments:

https://www.unix-ninja.com/p/Enabling_macOS_screen_sharing_VNC_via_command_line

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/management/osx) Code

Back to [Index](#index)





 
*****

## osx/shellcodeinject64

### Description: 

Inject shellcode into a x64 bit process

### Author:

@xorrior, @midnite_runr

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on | True |  |
| **PID** | Process ID | True |  |
| **Shellcode** | local path to bin file containing x64 shellcode | True |  |

### Comments:

comment

https://github.com/secretsquirrel/osx_mach_stuff/blob/master/inject.c

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | management |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/management/osx) Code

Back to [Index](#index)





 

***

## python - persistence

 - [multi/crontab](#multi/crontab)
 - [osx/CreateHijacker](#osx/CreateHijacker)
 - [osx/launchdaemonexecutable](#osx/launchdaemonexecutable)
 - [osx/loginhook](#osx/loginhook)
 - [osx/mail](#osx/mail)
 - [osx/RemoveDaemon](#osx/RemoveDaemon)
 
*****

## multi/crontab

### Description: 

This module establishes persistence via crontab

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to grab a screenshot from. | True |  |
| **FileName** | File name for the launcher. | True |  |
| **Hour** | Hour to callback. 24hr format. | False |  |
| **Hourly** | Hourly persistence. | False |  |
| **Remove** | Remove Persistence. True/False | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/persistence/multi) Code

Back to [Index](#index)





 
*****

## osx/CreateHijacker

### Description: 

Configures and Empire dylib for use in a Dylib hijack, given the path to a legitimate dylib of a vulnerable application. The architecture of the dylib must match the target application. The configured dylib will be copied local to the hijackerPath

### Author:

@patrickwardle,@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Arch** | Arch: x86/x64 | True | x86 |
| **LegitimateDylibPath** | Full path to the legitimate dylib of the vulnerable application | True |  |
| **Listener** | Listener to use. | True |  |
| **SafeChecks** | Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. | True | True |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |
| **VulnerableRPATH** | Full path to where the hijacker should be planted. This will be the RPATH in the Hijack Scanner module. | True |  |

### Comments:

comment

https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x

### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/persistence/osx) Code

Back to [Index](#index)





 
*****

## osx/launchdaemonexecutable

### Description: 

Installs an Empire launchDaemon.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **DaemonLocation** | The full path of where the Empire launch daemon should be located. | True |  |
| **DaemonName** | Name of the Launch Daemon to install. Name will also be used for the plist file. | True | com.proxy.initialize |
| **Listener** | Listener to use. | True |  |
| **SafeChecks** | Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. | True | True |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/persistence/osx) Code

Back to [Index](#index)





 
*****

## osx/loginhook

### Description: 

Installs Empire agent via LoginHook.

### Author:

@Killswitch-GUI

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **LoginHookScript** | Full path of the script to be executed/ | True | /Users/Username/Desktop/kill-me.sh |
| **Password** | User password for sudo. | True |  |

### Comments:

https://support.apple.com/de-at/HT2420

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/persistence/osx) Code

Back to [Index](#index)





 
*****

## osx/mail

### Description: 

Installs a mail rule that will execute an AppleScript stager when a trigger word is present in the Subject of an incoming mail.

### Author:

@n00py

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **RuleName** | Name of the Rule. | True | Spam Filter |
| **SafeChecks** | Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. | True | True |
| **Trigger** | The trigger word. | True |  |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

https://github.com/n00py/MailPersist

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/persistence/osx) Code

Back to [Index](#index)





 
*****

## osx/RemoveDaemon

### Description: 

Remove an Empire Launch Daemon.

### Author:

@xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **PlistPath** | Full path to the plist file to remove. | True |  |
| **ProgramPath** | Full path to the bash script/ binary file to remove. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | persistence |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/persistence/osx) Code

Back to [Index](#index)





 

***

## python - privesc

 - [linux/linux_priv_checker](#linux/linux_priv_checker)
 - [linux/unix_privesc_check](#linux/unix_privesc_check)
 - [multi/bashdoor](#multi/bashdoor)
 - [multi/sudo_spawn](#multi/sudo_spawn)
 - [osx/dyld_print_to_file](#osx/dyld_print_to_file)
 - [osx/piggyback](#osx/piggyback)
 - [windows/get_gpppasswords](#windows/get_gpppasswords)
 
*****

## linux/linux_priv_checker

### Description: 

This script is intended to be executed locally ona Linux box to enumerate basic system info, and search for commonprivilege escalation vectors with pure python.

### Author:

@Killswitch_GUI, @SecuritySift

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |

### Comments:

For full comments and code: www.securitysift.com/download/linuxprivchecker.py

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/privesc/linux) Code

Back to [Index](#index)





 
*****

## linux/unix_privesc_check

### Description: 

This script is intended to be executed locally ona Linux box to enumerate basic system info, and search for commonprivilege escalation vectors with a all in one shell script.

### Author:

@Killswitch_GUI, @pentestmonkey

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **Ip** | IP to curl script from (Default  is local webserver inside agent). | True | 127.0.0.1 |
| **Port** | Port to setup server and curl from (Default is 8089). | True | 8089 |
| **PrivSetting** | Setting to run unix-privesc-check with (standard or detailed). | True | standard |
| **ServeCount** | Value to set GET request count of webserver (Can be helpful if multiple agents, only host webserver once). | True | 1 |

### Comments:

For full comments and code: http://pentestmonkey.net/tools/audit/unix-privesc-check

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/privesc/linux) Code

Back to [Index](#index)





 
*****

## multi/bashdoor

### Description: 

Creates an alias in the .bash_profile to cause the sudo command to execute a stager and pass through the origional command back to sudo

### Author:

@n00py

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **SafeChecks** | Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. | True | True |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/privesc/multi) Code

Back to [Index](#index)





 
*****

## multi/sudo_spawn

### Description: 

Spawns a new Empire agent using sudo.

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **Password** | User password for sudo. | True |  |
| **SafeChecks** | Enable SafeChecks. | True | True |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/privesc/multi) Code

Back to [Index](#index)





 
*****

## osx/dyld_print_to_file

### Description: 

This modules takes advantage of the environment variable DYLD_PRINT_TO_FILE in order to escalate privileges on all versions Mac OS X YosemiteWARNING: In order for this exploit to be performed files will be overwritten and deleted. This can set off endpoint protection systems and as of initial development, minimal testing has been performed.

### Author:

@checky_funtime

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent used to Privesc from | True |  |
| **FileName** | The filename to use when the temporary file is dropped to disk. | True | error.log |
| **Listener** | Listener to use. | True |  |
| **SafeChecks** | Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. | True | True |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |
| **WriteablePath** | Full path to where the file should be written. Defaults to /tmp/. | True | /tmp/ |

### Comments:

References:

https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/osx/local/dyld_print_to_file_root.rb

http://www.sektioneins.com/en/blog/15-07-07-dyld_print_to_file_lpe.html

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/privesc/osx) Code

Back to [Index](#index)





 
*****

## osx/piggyback

### Description: 

Spawns a new Empire agent using an existing sudo session.  This works up until El Capitan.

### Author:

@n00py

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Listener** | Listener to use. | True |  |
| **SafeChecks** | Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. | True | True |
| **UserAgent** | User-agent string to use for the staging request (default, none, or other). | False | default |

### Comments:

Inspired by OS X Incident Response by Jason Bradley

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/privesc/osx) Code

Back to [Index](#index)





 
*****

## windows/get_gpppasswords

### Description: 

This module will attempt to pull group policy preference passwords from SYSVOL

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **password** | Password to connect to LDAP | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | privesc |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/privesc/windows) Code

Back to [Index](#index)





 

***

## python - situational_awareness

 - [host/multi/SuidGuidSearch](#host/multi/SuidGuidSearch)
 - [host/multi/WorldWriteableFileSearch](#host/multi/WorldWriteableFileSearch)
 - [host/osx/HijackScanner](#host/osx/HijackScanner)
 - [host/osx/situational_awareness](#host/osx/situational_awareness)
 - [network/active_directory/dscl_get_groupmembers](#network/active_directory/dscl_get_groupmembers)
 - [network/active_directory/dscl_get_groups](#network/active_directory/dscl_get_groups)
 - [network/active_directory/dscl_get_users](#network/active_directory/dscl_get_users)
 - [network/active_directory/get_computers](#network/active_directory/get_computers)
 - [network/active_directory/get_domaincontrollers](#network/active_directory/get_domaincontrollers)
 - [network/active_directory/get_fileservers](#network/active_directory/get_fileservers)
 - [network/active_directory/get_groupmembers](#network/active_directory/get_groupmembers)
 - [network/active_directory/get_groupmemberships](#network/active_directory/get_groupmemberships)
 - [network/active_directory/get_groups](#network/active_directory/get_groups)
 - [network/active_directory/get_ous](#network/active_directory/get_ous)
 - [network/active_directory/get_userinformation](#network/active_directory/get_userinformation)
 - [network/active_directory/get_users](#network/active_directory/get_users)
 - [network/dcos/chronos_api_add_job](#network/dcos/chronos_api_add_job)
 - [network/dcos/chronos_api_delete_job](#network/dcos/chronos_api_delete_job)
 - [network/dcos/chronos_api_start_job](#network/dcos/chronos_api_start_job)
 - [network/dcos/etcd_crawler](#network/dcos/etcd_crawler)
 - [network/dcos/marathon_api_create_start_app](#network/dcos/marathon_api_create_start_app)
 - [network/dcos/marathon_api_delete_app](#network/dcos/marathon_api_delete_app)
 - [network/find_fruit](#network/find_fruit)
 - [network/gethostbyname](#network/gethostbyname)
 - [network/http_rest_api](#network/http_rest_api)
 - [network/port_scan](#network/port_scan)
 - [network/smb_mount](#network/smb_mount)
 
*****

## host/multi/SuidGuidSearch

### Description: 

This module can be used to identify suid or guid bit set on files.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |
| **Path** | Path to start the search from. Default is /  | True | / |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/host/multi) Code

Back to [Index](#index)





 
*****

## host/multi/WorldWriteableFileSearch

### Description: 

This module can be used to identify world writeable files.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |
| **Path** | Path to start the search from. Default is /  | True | / |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/host/multi) Code

Back to [Index](#index)





 
*****

## host/osx/HijackScanner

### Description: 

This module can be used to identify applications vulnerable to dylib hijacking on a target system. This has been modified from the original to remove the dependancy for the macholib library.

### Author:

@patrickwardle, @xorrior

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run the module on. | True |  |
| **LoadedProcesses** | Scan only loaded process executables | True | False |
| **Path** | Scan all binaries recursively, in a specific path. | False |  |

### Comments:

Heavily adapted from @patrickwardle's script: https://github.com/synack/DylibHijack/blob/master/scan.py

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/host/osx) Code

Back to [Index](#index)





 
*****

## host/osx/situational_awareness

### Description: 

This module will enumerate the basic items needed for OP.

### Author:

Alex Rymdeko-Harvey, @Killswitch-GUI

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run from. | True |  |
| **Debug** | Enable a find keyword to search for within the iMessage Database. | True | False |
| **HistoryCount** | The number of messages to enumerate from most recent. | True | 10 |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/host/osx) Code

Back to [Index](#index)





 
*****

## network/active_directory/dscl_get_groupmembers

### Description: 

This module will use the current user context to query active directory for a list of users in a group.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **Group** | Group | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/dscl_get_groups

### Description: 

This module will use the current user context to query active directory for a list of Groups.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **Domain** | Domain | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/dscl_get_users

### Description: 

This module will use the current user context to query active directory for a list of users.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **Domain** | Domain | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_computers

### Description: 

This module will list all computer objects from active directory

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_domaincontrollers

### Description: 

This module will list all domain controllers from active directory

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_fileservers

### Description: 

This module will list file servers

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_groupmembers

### Description: 

This module will return a list of group members

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **groupname** | Group to check which users are a member of | False | Domain Admins |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_groupmemberships

### Description: 

This module check what groups a user is member of

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |
| **user** | User to check group memberships of | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_groups

### Description: 

This module will list all groups in active directory

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to grab run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_ous

### Description: 

This module will list all OUs from active directory

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to grab run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_userinformation

### Description: 

This module will return the user profile specified

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |
| **user** | User to check group memberships of | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/active_directory/get_users

### Description: 

This module list users found in Active Directory

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to grab run on. | True |  |
| **BindDN** | user@penlab.local | True |  |
| **LDAPAddress** | LDAP IP/Hostname | True |  |
| **Password** | Password to connect to LDAP | False |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/active_directory) Code

Back to [Index](#index)





 
*****

## network/dcos/chronos_api_add_job

### Description: 

Add a Chronos job using the HTTP API service for the Chronos Framework

### Author:

@TweekFawkes

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Command** | The command to run. | True | id |
| **Description** | The description of the job. | True | Scheduled Job 001 |
| **LastSuccess** | The last successful run for the job (optional). | False |  |
| **Name** | The name of the chronos job. | True | scheduledJob001 |
| **Owner** | The owner of the job. | True | admin@example.com |
| **OwnerName** | The owner name of the job. | True | admin |
| **Port** | The port to connect to. | True | 8080 |
| **Schedule** | The schedule for the job. | True | R/2016-07-15T00:08:35Z/PT24H |
| **Target** | FQDN, domain name, or hostname to lookup on the remote target. | True | chronos.mesos |

### Comments:

Docs: https://mesos.github.io/chronos/docs/api.html

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/dcos) Code

Back to [Index](#index)





 
*****

## network/dcos/chronos_api_delete_job

### Description: 

Delete a Chronos job using the HTTP API service for the Chronos Framework

### Author:

@TweekFawkes

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Name** | The name of the chronos job. | True | scheduledJob001 |
| **Port** | The port to connect to. | True | 8080 |
| **Target** | FQDN, domain name, or hostname to lookup on the remote target. | True | chronos.mesos |

### Comments:

Docs: https://mesos.github.io/chronos/docs/api.html

urllib2 DELETE method credits to: http://stackoverflow.com/questions/21243834/doing-put-using-python-urllib2

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/dcos) Code

Back to [Index](#index)





 
*****

## network/dcos/chronos_api_start_job

### Description: 

Start a Chronos job using the HTTP API service for the Chronos Framework

### Author:

@TweekFawkes

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Name** | The name of the chronos job. | True | scheduledJob001 |
| **Port** | The port to connect to. | True | 8080 |
| **Target** | FQDN, domain name, or hostname to lookup on the remote target. | True | chronos.mesos |

### Comments:

Docs: https://mesos.github.io/chronos/docs/api.html

urllib2 PUT method credits to: http://stackoverflow.com/questions/21243834/doing-put-using-python-urllib2

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/dcos) Code

Back to [Index](#index)





 
*****

## network/dcos/etcd_crawler

### Description: 

Pull keys and values from an etcd configuration store

### Author:

@scottjpack, @TweekFawkes

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Depth** | How far into the ETCD hierarchy to recurse.  0 for root keys only, "-1" for no limitation | True | -1 |
| **Port** | The etcd client communication port, typically 2379 or 1026. | True | 1026 |
| **Target** | FQDN, domain name, or hostname to lookup on the remote target. | True | etcd.mesos |

### Comments:

Docs: https://coreos.com/etcd/docs/latest/api.html

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/dcos) Code

Back to [Index](#index)





 
*****

## network/dcos/marathon_api_create_start_app

### Description: 

Create and Start a Marathon App using Marathon's REST API

### Author:

@TweekFawkes

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Cmd** | The command to run. | True | env && sleep 300 |
| **CPUs** | The number of CPUs to assign to the app. | True | 1 |
| **Disk** | The Disk Space (MiB) to assign to the app. | True | 0 |
| **ID** | The id of the marathon app. | True | app001 |
| **Instances** | The number of instances to assign to the app. | True | 1 |
| **Mem** | The Memory (MiB) to assign to the app. | True | 128 |
| **Port** | The port to connect to. | True | 8080 |
| **Target** | FQDN, domain name, or hostname to lookup on the remote target. | True | marathon.mesos |

### Comments:

Marathon REST API documentation version 2.0: https://mesosphere.github.io/marathon/docs/generated/api.html

Marathon REST API: https://mesosphere.github.io/marathon/docs/rest-api.html

Marathon REST API: https://open.mesosphere.com/advanced-course/marathon-rest-api/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/dcos) Code

Back to [Index](#index)





 
*****

## network/dcos/marathon_api_delete_app

### Description: 

Delete a Marathon App using Marathon's REST API

### Author:

@TweekFawkes

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **ID** | The id of the marathon app. | True | app001 |
| **Port** | The port to connect to. | True | 8080 |
| **Target** | FQDN, domain name, or hostname to lookup on the remote target. | True | marathon.mesos |

### Comments:

Marathon REST API documentation version 2.0: https://mesosphere.github.io/marathon/docs/generated/api.html

Marathon REST API: https://mesosphere.github.io/marathon/docs/rest-api.html

Marathon REST API: https://open.mesosphere.com/advanced-course/marathon-rest-api/

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network/dcos) Code

Back to [Index](#index)





 
*****

## network/find_fruit

### Description: 

Searches for low-hanging web applications.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Port** | The port to scan on. | True | 8080 |
| **SSL** | True/False to force SSL | False | False |
| **Target** | IP Address or CIDR to scan. | True |  |

### Comments:

CIDR Parser credits to http://bibing.us.es/proyectos/abreproy/12106/fichero/ARCHIVOS%252Fservidor_xmlrpc%252Fcidr.py

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/gethostbyname

### Description: 

Uses Python's socket.gethostbyname("example.com") function to resolve host names on a remote agent.

### Author:

@TweekFawkes

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Target** | FQDN, domain name, or hostname to lookup using the remote target. | True |  |

### Comments:

none

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/http_rest_api

### Description: 

Interacts with a HTTP REST API and returns the results back to the screen.

### Author:

@TweekFawkes, @scottjpack

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Path** | The path. | True | /v1/version |
| **Port** | The port to connect to. | True | 8123 |
| **Protocol** | Protocol or Scheme to use. | True | http |
| **RequMethod** | The HTTP request method to use. | True | GET |
| **Target** | FQDN, domain name, or hostname of the remote target. | True | master.mesos |

### Comments:

Docs: https://mesos.github.io/chronos/docs/api.html

urllib2 DELETE method credits to: http://stackoverflow.com/questions/21243834/doing-put-using-python-urllib2

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/port_scan

### Description: 

Simple Port Scanner.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Port** | The port to scan for. | True | 8080 |
| **Target** | Targets to scan in single, range 0-255 or CIDR format. | True |  |

### Comments:

CIDR Parser credits to http://bibing.us.es/proyectos/abreproy/12106/fichero/ARCHIVOS%252Fservidor_xmlrpc%252Fcidr.py

### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | True |
| **Background**  | True |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network) Code

Back to [Index](#index)





 
*****

## network/smb_mount

### Description: 

This module will attempt mount an smb share and execute a command on it.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **Command** | Command to run. | True |  |
| **Domain** | Domain | False |  |
| **MountPoint** | Directory to mount on target. | True |  |
| **Password** | Password | False |  |
| **ShareName** | Share to mount. e.g. 192.168.1.1/c$ | True |  |
| **UserName** | Username | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | situational_awareness |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/situational_awareness/network) Code

Back to [Index](#index)





 

***

## python - trollsploit

 - [osx/change_background](#osx/change_background)
 - [osx/login_message](#osx/login_message)
 - [osx/say](#osx/say)
 - [osx/thunderstruck](#osx/thunderstruck)
 
*****

## osx/change_background

### Description: 

Change the login message for the user.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **Desktop** | True/False to change the desktop background. | False | False |
| **Image** | Location of the image to use. | True |  |
| **Login** | True/False to change the login background. | False | False |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | trollsploit |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/trollsploit/osx) Code

Back to [Index](#index)





 
*****

## osx/login_message

### Description: 

Change the login message for the user.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |
| **Message** | Message to display | False |  |
| **Remove** | True/False to remove login message. | True | False |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | True |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | trollsploit |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/trollsploit/osx) Code

Back to [Index](#index)





 
*****

## osx/say

### Description: 

Performs text to speech using "say".

### Author:

@harmj0y

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to execute module on. | True |  |
| **Text** | The text to speak. | True |  |
| **Voice** | The voice to use. | True | alex |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | trollsploit |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/trollsploit/osx) Code

Back to [Index](#index)





 
*****

## osx/thunderstruck

### Description: 

Open Safari in the background and play Thunderstruck.

### Author:

@424f424f

### Options:

| Param | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| **Agent** | Agent to run on. | True |  |

### Comments:



### Info:

| :--- | :--- |
| **Needs Admin** | False |
| **Opsec Safe**  | False |
| **Background**  | False |
| **Category**    | trollsploit |
| **Language**    | python |
| **Min Version** | 2.6 |
| **Out Extension** | |


View [Source](https://github.com/EmpireProject/Empire/blob/master/lib/modules/python/trollsploit/osx) Code

Back to [Index](#index)







***

***

Generated on Friday, February 2, 2018 1:38:03 PM
