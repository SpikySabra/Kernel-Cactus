# Kernel-Cactus
It's pointy and it hurts!

`Kernel Cactus` is a C written framework to utilize perform attacks on Windows OS while utilising CVE-2021-21551 (dbutil_2_3.sys). 

# Description
Please Read our full [article](https://spikysabra.gitbook.io/kernelcactus/) to further understand the ins and outs of all the offensive and defensive code in this repo. 

# Pre - Reqs 
In order for Kernel Cactus to work it is required that you will have Dbutil_2_3.sys installed and its service started. 
how to do so? its your choice really. anything from sc.exe to 3rd party driver loaders is good. 

# Disclaimer 
This is a new framework still mostly at POC level for abusing CVE-2021-21551. 
As such, this framework tempers with danegrous variables in the kernel , which may cause BSOD from time to time. 
USING THIS IN PRODUCTION ENVIORNMENT IS RISKY! use it with all the cuation you can!
Fixes to stabilize possible BSOD's will come in the next update, although its mostly safe to use at the moment. 
if you are not familiar with the nature of this CVE please reffer to https://spikysabra.gitbook.io/kernelcactus/.


# Usage 
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
# Authors 
[Itamar Medyoni (@T045T3)](https://www.linkedin.com/in/itamar-medyoni-b6aba6179/)
[Matan Haim Guez (@0xs0ns3)](https://www.linkedin.com/in/matan-haim-guez-6905131b4/)

# TODO 
* Stabilize the attacks by adding refferences to kernel objects
* Stabilize the Process hiding feature already hiding in this code 
* Re-Factor the code to work with other types of vulnerable drivers in factory method
* Add support for older versions of windows. 
* Hope the indutry patches this up :).

# Honorable Mentions 
* Master of endless inspiration- https://github.com/br-sn/CheekyBlinder
* Functional masters and elegant code writers- https://github.com/wavestone-cdt/EDRSandblast
* Amazing story teller and absolute monster- https://connormcgarr.github.io/cve-2020-21551-sploit/
