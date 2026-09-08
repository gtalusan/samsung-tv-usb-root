set pagination off
set confirm off
target remote localhost:1234
# exfat_core.ko is not mapped until insmod; stop first on a kernel symbol that
# is only reached once the volume is mounted and userspace calls getdents.
break iterate_dir
continue
delete
printf "\n=== modules are loaded; exfat_core.ko core base is 0xbe800000 (guest printed 'exfat_core mod ld(0xbe800000)'); .text is at +0 (verified: FsReadDir+0x54 = 0xbe80741c) ===\n"
# ffsReadDir epilogue:  .text+0x26ac  sub sp,fp,#40
#                       .text+0x26b0  ldm sp,{r4,r5,r6,r7,r8,r9,sl,fp,sp,pc}
break *0xbe8026b0
continue
printf "\n=== stopped at ffsReadDir epilogue ldm ===\n"
x/1i $pc
printf "sp (= fp-40, base of the reload) = %#x\n", $sp
printf "these ten words are about to become r4,r5,r6,r7,r8,r9,sl,fp,sp,pc:\n"
x/10wx $sp
printf "\nuni_name buffer starts at sp-520 = %#x\n", $sp-520
x/8wx $sp-520
stepi
printf "\n=== after the ldm ===\n"
info registers r4 r5 r6 r7 r8 r9 r10 r11 sp pc
kill
quit
