# Kernel-Cactus
It's pointy and it hurts!


##Usage 
```
--help								Display usage 

--etw 0/1							Disable/Enable ETW

--ppl PID 0/1							Disable/Enable PPL from any process 

--terminate	PID						Terminate single Process:
								this is aimed mostly for protected processes. 
								but will work for any process that provieds you with PROCESS_QUERY_LIMITED_INFORMATION in its ACL.
							        (in case you do not hold such right, you are more then welcome to use '--token PID current --terminate PID in order to recive one :D )

--delete PATH							Delete any file that provides you with ANY handle access ;)


--token srcPID dstPID						copy a token via kernel from one process to another. works both on local AND domain purposes ;)
								(use 'current' on dstPID in order to change the current process token)

--tokenspawn PID						spawn a new CMD shell with the chosen process token.						

--destroyservice path\to\pids.txt path\to\files.txt		WARNING, USE WITH RESPONSIBILLITY!
								ALL FILES DELETED ARE NOT RESTORABLE, MAKE A COPY PRIOR TO DELETING IF YOU NEED TO...
								Will kill all processes in pid list (line seperated) 
								Will delete all Files in the File list (line seperated)
								this module is aimed for services that own a WatchDog service. 
								deleting and killing all files is only in case that the lowest handle access
								is available to you by ACL, so again feel free to use --token to elevate privs. 

--tinject PID \path\to\shellcode				Perform RemoteThreadInjection to any process that provides you ANY handle , including protected processes 

--thijack PID \path\to\shellcode				Perform ThreadHijacking via kernel operations to any process that provides you ANY handle , including protected processes 
									
(shellcode must be in binary format )
```
