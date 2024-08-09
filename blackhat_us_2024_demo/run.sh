gcc exp.c -o ./rootfs/exp/exp -static -masm=intel
cd rootfs
find . | cpio -o --format=newc > ../rootfs.cpio
cd ..
qemu-system-x86_64 \
    -kernel bzImage \
    -cpu qemu64,+smep,+smap,+rdrand \
    -m 512M \
    -initrd rootfs.cpio \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on page_alloc.shuffle=1 nokaslr" \
        -drive file=/flag,if=virtio,format=raw,readonly=on \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
    -s
