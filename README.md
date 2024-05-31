I develop 11 exploits for 6 Linux kernel cves using Page-UAF technics.

I didn't provide the file system for testing, you need to build using `create-image.sh`and download the appropriate FUSE library on your own if the exploit need（in my exploits，only two exploits in CVE-2023-5345 use FUSE）. You need to modify the file system path in the `run.sh` or `start.sh`,`compress.sh` file to the path of your own built file system and use `compress.sh` to compile and package an exploit, and then start QEMU to simulate the kernel.

If you receive the message 'Not found two pipe' when running the exp, it means that we haven't successfully tampered with the target structure. However, this won't affect the normal data structure of the kernel. You can proceed with executing the exp until the exploitation is successful. 

Due to time constraints, I apologize for not optimizing each exp. By the way,  almost all the exploits do not require bypassing KASLR.



