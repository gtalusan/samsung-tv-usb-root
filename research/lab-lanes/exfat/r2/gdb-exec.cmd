set pagination off
set confirm off
target remote localhost:1237
break iterate_dir
continue
delete
# ffsReadDir epilogue ldm, exfat_core.ko .text+0x26b0, module base 0xbe800000
break *0xbe8026b0
continue
printf "\n=== at ffsReadDir epilogue; the ten words about to be reloaded ===\n"
x/10wx $sp
stepi
printf "\n=== after the ldm: pc, sp, and what the cpu is now executing ===\n"
info registers pc sp
info symbol $pc
x/6i $pc
printf "\n=== single-stepping the attacker-chosen kernel function ===\n"
stepi
info registers pc
x/1i $pc
stepi
info registers pc
x/1i $pc
stepi
info registers pc
x/1i $pc
kill
quit
