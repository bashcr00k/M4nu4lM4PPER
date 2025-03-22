# M4nu4lM4PPER
Manual Mapping Dll Injection POC

This Is My first poc it was kinda hard and i struggled a lot to write this

at first at i tried to write a reflective dll injection poc but since i kept running into issues with no reliable way to debug em i had to first make sure i got the basics right and since manual mapping is very similar to reflective dll injection i decided to write a poc for it but actually inject a stub into the target process to simulate reflective dll injection and it worked !!! 


## How Does It Work

The Normal dll injection happens by first writing the dll path into the target process then calling createremotethread with loadlibraryA and the dll path as an argument, this method is so basic and gets flagged easily by any av or edr since it uses a high level winapi function (loadlibraryA), In Order to avoid detection we load the dll but without using loadlibraryA . 

So in order to load the dll we have to do everything loadlibraryA does manually .
 ### What do we have to do

 - First we read the dll into our process's memory so we can parse its headers
   
 - Next We start by writing the headers first into the target process
   
 - Then we write the sections each on its virtual address (at first i was just randomly writing them into the target process which makes all offsets wrong)
   
 - after writing everything here comes the tricky part, now we want to preform base relocations and resolve imports, to do so we need to be inside the process it self , Why ? this is the main problem i had if we want to resolve imports need to first load kernel32.dll then get the address of both loadlibraryA then GetProcAddress and we have to do this inside the target process and this is the problem we didn't resolve any imports so we can't use loadlibrary or getprocaddress, there are 2 ways i could think of first is parsing the PEB of the target process and get the address then remotly parse the iat and look for both loadlibrary and getprocaddress and replace the their addresses with the address we found, this method is pretty complicated and i couldn't really tell when the code didn't work whether it was because of this or something else so i had to find another way, the way i used here is similar to reflective dll injection where we use a stub that is responsible for resolving imports and fixing base relocations but here we make the injector write it into the target process  (not the dll) thats why this is still a manual mapping dll injection.
   
 - we first get all the informations the stub needs to resolve imports and preform base relocations and the important part is we actually give it the address of loadlibraryA and GetProcAddress, why does that work ? because usually kenel32.dll is loaded by default in all processes with the same address so we can use the address we get from our injector in this stub.
   
 - we allocate space for the stub then we write it into the target process, we first write the infos then right after it we write the stub
   
 - finally we call createremotethread at where the stub is with the infos we wrote right before it as params.

this was a very educative experience that iv really learned a lot from i got this idea from a forgotten project here on github but i can't really find the page to include it 

## whats next 


now that we managed to write a poc for manual mapping dll injection i have a solid start where i can now try to actually prefom a reflective dll injection but for now il focus on writing other pocs.
#important notes

- it only injects x64 processes i might fix that in the future
  
- the path must have double backslashes (\\) instead of one
  
- there is one problem i still didn't manage to fix which is the stub size here i used a dirty trick where i create a function right after the function i wanna get its size then i substract them from each other to get the size, this method is very unrelaiable and doesn't always work + the stub size is always negative which causes an overflow since its an unsigned int which makes writeprocessmemory write a lot more than it has to, i tried to fix it but whenever i do the injector stops working il try to fix this in the future.

# ScreenShot

<img width="1280" alt="manualmappingpoc" src="https://github.com/user-attachments/assets/6dcf1777-9763-4dbb-bc61-30b868b92991" />

# HAPPY HACKING
