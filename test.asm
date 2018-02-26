
; test.asm

.686p
.model flat

.data

.code

myadd proc c
mov ax, 5
add ax, 6
ret
myadd endp

end
