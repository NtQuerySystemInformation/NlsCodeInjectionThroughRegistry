# NlsCodeInjectionThroughRegistry
 Inject code injection through Registry 
# How does it work?
It is based on jonas lykk discovery here: https://twitter.com/jonaslyk/status/1352729173631135751?lang=en
There is two ways to accomplish this: 
Either call SetThreadLocale and set up an export function named NlsDllCodePageTranslation, where your main payload is in.
Or the second method, which is actually implemented here, it is possible to execute using functions such as SetConsoleCp  or SetConsoleOutputCP, you dont care about exports at all.

If the process is not console based, you can allocate one with AllocConsole, payload gets triggered.

For this reason, to make it to work, I had to create position independent shellcode and inject it to a remote process.
This is just meant for demostration purposes.

One day in the future I will reverse a little bit better how this works, if i have time.
