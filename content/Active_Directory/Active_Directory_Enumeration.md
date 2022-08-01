
The commands listed below either use PowerView or the AD module, unless otherwise noted.

## General Domain Enumeration

```powershell
#Get current domain
Get-NetDomain (PowerView)
Get-ADDomain (ActiveDirectory Module)


#Get object of another domain
Get-NetDomain -Domain example.local (PowerView)
Get-ADDomain -Identity example.local


#Get domain SID for the current domain
Get-DomainSID (PowerView)
(Get-ADDomain).DomainSID


#Get domain policy for the current domain
Get-DomainPolicy
(Get-DomainPolicy)."system access"


#Get domain policy for another domain
(Get-DomainPolicy -domain example.local)."system access"


#Get domain controllers for the current domain
Get-NetDomainController Get-ADDomainController


#Get domain controllers for another domain
Get-NetDomainController -Domain example.local
Get-ADDomainController -DomainName example.local -Discover
```



## User Enumeration
```powershell
#Get a list of users in the current domain
Get-NetUser
Get-NetUser -Username username
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity username -Properties *


#Get list of all properties for users in the current domain
Get-UserProperty
Get-UserProperty -Properties pwdlastset
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}


#Search for a particular string in a user's attributes:
Find-UserField -SearchField Description -SearchTerm "built"
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

## Computers Enumeration
```powershell
#Get a list of computers in the current domain
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *


#Get actively logged users on a computer (needs local admin rights on the target)
Get-NetLoggedon -ComputerName <servername>


#Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
Get-LoggedonLocal -ComputerName dc.abc.example.local


#Get the last logged user on a computer (needs administrative rights and remote registry on the target)
Get-LastLoggedOn -ComputerName <servername>
```


## Group Enumeration
```powershell
#Get all the groups in the current domain
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData
Get-ADGroup -Filter * | select Name Get-ADGroup -Filter * -Properties *

#Get all groups containing the word "admin" in group name
Get-NetGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name


#Get all the members of the Domain Admins group
Get-NetGroupMember -GroupName "Domain Admins" -Recurse 
Get-ADGroupMember -Identity "Domain Admins" -Recursive
#In order to query a group such as Enterprise Administrators which is present only in the root domain
#We need to query the root domain
Get-NetGroupMember -GroupName "Enterprise Admins" -Domain example.local


#Get the group membership for a user:
Get-NetGroup -UserName "username"
Get-ADPrincipalGroupMembership -Identity username


#List all the local groups on a machine (needs administrator privs on non-dc machines) :
Get-NetLocalGroup -ComputerName dc.abc.example.local -ListGroups


#Get members of all the local groups on a machine (needs administrator privs on non-dc machines)
Get-NetLocalGroup -ComputerName dc.abc.example.local -Recurse
```

## File/Share Enumeration
```powershell
#Find shares on hosts in current domain. 
Invoke-ShareFinder -Verbose

#Find sensitive files on computers in the domain 
Invoke-FileFinder -Verbose

#Get all fileservers of the domain
Get-NetFileServer
```

## Service Accounts
```powershell
#To see where a service account is being used in a domain
gwmi win32_service -filter "startname='example\\svcadmin'" -ComputerName mgmt
```

## GPO Enumeration
```powershell
#Get list of GPO in current domain.
Get-NetGPO
Get-NetGPO -ComputerName username.abc.example.local 
Get-GPO -All (GroupPolicy module)
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html (Provides RSoP)


#Get GPO(s) which use Restricted Groups or groups.xml for interesting users
Get-NetGPOGroup


#Get users which are in a local group of a machine using GPO
Find-GPOComputerAdmin -Computername username.abc.example.local


#Get machines where the given user is member of a specific group 
Find-GPOLocation -UserName username -Verbose


#Get the GPO applied to a certain OU
(Get-NetOU StudentMachines -FullData).gplink
#take this output 'LDAP://cn={3E04167E-C2B6-4A9A-8FB7-C811158DC97C},cn=policies,cn=system,DC=abc,DC=example,DC=local' and use it in the following comand
Get-NetGPO -ADSpath 'LDAP://cn={3E04167E-C2B6-4A9A-8FB7-C811158DC97C},cn=policies,cn=system,DC=abc,DC=example,DC=local'

#do the same thing in  one command
Get-NetGPO -ADSpath ((Get-NetOU StudentMachines -FullData).gplink.split(";")[0] -replace "^.")
```

## OU Enumeration
```powershell
#Get OUs in a domain
Get-NetOU -FullData
Get-ADOrganizationalUnit -Filter * -Properties *

#List computers within a OU, studentmachines
Get-NetOU StudentMachines| %{Get-NetComputer -ADSPath $_}

#Get GPO applied on an OU. Read GPOname from gplink attribute from
Get-NetOU
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}"
Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081 (GroupPolicy module)
```

## ACL Enumeration
Access Control Model - Enables control on the ability of a process to access objects and other recources in active directory based on:

	- Access Tokens (security context of a process - identity and privs of user)

	- Security Descriptors (SID of the owner, Discretionary ACL (DACL) and System ACL (SACL))

Access Control List - is a list of Access Control Entries (ACE) - ACE corresponds to individual permissions or audits access.

	Two Types:

	- DACL - Defines the permissions trustees (a user or group) have on an object

	- SACL - Logs success and failure audit messages when an object is accessed

	ACLs are vital to security architecture of AD
	
```powershell
#Get the ACLs associated with the specified object
Get-ObjectAcl -SamAccountName username -ResolveGUIDs
Get-ObjectACL -SamAccountName "Domain Admins" -ResolveGUIDs -Verbose


#Get the ACLs associated with the specified prefix to be used for search
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose


#We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=abc,DC=example ,DC=local').Access


#Get the ACLs associated with the specified LDAP path to be used for search
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=abc,DC=example,DC=local" -ResolveGUIDs -Verbose

#Search for interesting ACLs
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "student30"} 
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RDPUsers"}

#Get the ACLs associated with the specified path
Get-PathAcl -Path "\\dc.abc.example.local\sysvol"
```

## Trust Enumeration
Transitive - Can be extended to establish trust relationships with other domains
	- All the default intra-forest trust relationships (Tree-root, Parent-Child) between domains within the same forest are transitive two-way trusts
	
Nontransitive - Cannot be extended to other domains in the forest. Can be two-way or one-way
	- This is the default trust (called external trust) between two domains in different forests when there is no trust relationship

Automatic Trusts
	- Parent-Child trust - It is created automatically between the new domains the the domain that precedes it in the namespace heirarchy, whenever a new domains is added in a tree. For example abc.example.local is a child of example.local
	- This trust is always two-way transitive
	
	- Tree-Root trust - It is created automatically between whenever a new domain tree is added to a forest root
	- This trust is always two-way transitive
	
Shortcut Trusts - Used to reduce access times in complex trust scenarios
	- can be one-way or two-way transitive
	
External Trusts - Between two domains in different forests when there is no default trust relationship
	- can be one-way or two-way and is nontransitive
	
Forest Trusts - Between forest root domain
	- cannot be extended to a third forest (no implicit trust)
	- can be one-way or two-way and transitive or nontransitive
```powershell
Domain Trust Mapping
#Get a list of all domain trusts for the current domain
Get-NetDomainTrust
Get-NetDomainTrust -Domain us.abc.example.local
Get-ADTrust
Get-ADTrust -Identity us.abc.example.local
Get-NetForestDomain -Verbose | Get-NetDomainTrust
#only external trustt
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
#AD module get external trusts
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}

Forest Mapping
#Get details about the current forest
Get-NetForest
Get-NetForest -Forest external.local
Get-ADForest
Get-ADForest -Identity external.local
#if bidirectional trust or one way trust to an external domain is there 
 Get-ADTrust -Filter * -Server external.local

#Get all domains in the current forest
Get-NetForestDomain
Get-NetForestDomain -Forest external.local
(Get-ADForest).Domains


#Get all global catalogs for the current forest
Get-NetForestCatalog
Get-NetForestCatalog -Forest external.local
Get-ADForest | select -ExpandProperty GlobalCatalogs


#Map trusts of a forest
Get-NetForestTrust
Get-NetForestTrust -Forest external.local
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
Get-ADTrust -Filter *
```

## User Hunting
```powershell
#Find all machines on the current domain where the current user has local admin access
#This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Invoke-CheckLocalAdminAccess on each machine.
Find-LocalAdminAccess -Verbose
#This can also be done with the help of remote administration tools like WMI and PowerShell remoting. Pretty useful in cases ports (RPC and SMB) used by Find-LocalAdminAccess are blocked.
#See Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1


#Find local admins on all machines of the domain (needs administrator privs on non-dc machines).
#This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Get-NetLocalGroup on each machine.
Invoke-EnumerateLocalAdmin -Verbose


#Find computers where a domain admin (or specified user/group) has sessions:
#This function queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using Get-NetGroupMember, gets a list of computers (Get-NetComputer) and list sessions and logged on users (Get-NetSession/Get-NetLoggedon) from each machine.
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
#To confirm admin access
Invoke-UserHunter -CheckAccess


#Find computers where a domain admin is logged-in. 
#This option queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using Get-NetGroupMember, gets a list _only_ of high traffic servers (DC, File Servers and Distributed File servers) for less traffic generation and list sessions and logged on users (Get-NetSession/Get-NetLoggedon) from each machine.
Invoke-UserHunter -Stealth
```









