# NlsCodeInjectionThroughRegistry
Dll injection through registry modification of NLS code page ID.

It requieres administrator privileges, but it definetely works.
 
# How does it work?
It is based on jonas lykk discovery here: https://twitter.com/jonaslyk/status/1352729173631135751?lang=en

Here I used functions such as SetConsoleCp  or SetConsoleOutputCP, you dont care about exports at all.

If the process is not console based, you can allocate one with AllocConsole, payload will still get triggered.

For this reason, to make it to work, I had to create position independent shellcode and inject it to a remote process, which works as a stager to the actual loading of the dll.
This is just meant for demostration purposes.

(Writeup will be updated soon)

# How to use?
Compile the project in release x64, it uses the default jonas payload, which spawns a shell when loaded.
ShellcodeInjection is just an additional project I used to convert C to shellcode, using hasherezade method described here:
https://github.com/vxunderground/VXUG-Papers/blob/main/From%20a%20C%20project%20through%20assembly%20to%20shellcode.pdf

Only x64, tested in Windows 11.
