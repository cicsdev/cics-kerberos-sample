> [!WARNING]
> **This repository has been archived**
> 
> IBM Legacy Public Repository Disclosure: All content in this repository including code has been provided by IBM under the associated open source software license and IBM is under no obligation to provide enhancements, updates, or support.
> IBM developers produced this code as an open source project (not as an IBM product), and IBM makes no assertions as to the level of quality nor security, and will not be maintaining this code going forward.


# CICS Kerberos sample client
Sample Java program that can be used to test a simple CICS Kerberos configuration.
This is a simple Java test 'hello world' program that uses CICS web services and 
Kerberos. It is based on the test client used in the in the CICS SupportPac CA1P: 
Web services samples for CICS TS (http://www-01.ibm.com/support/docview.wss?uid=swg24020774).
It can be used to validate CICS Kerberos configrations.

The jar can be invoked with a command such as:
```
java -cp cicstest.jar cics.Requester  <host:port> <echoString> 
<clientPrincipalName> <clientPassword> <servicePrincipalName>
```



## License
This project is licensed under [Apache License Version 2.0](LICENSE).




