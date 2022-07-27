.arm
.syntax unified

.global _start

.text
_start:
    BL main
    MOV R7, 0xff000000
    SVC 0
    
.data
.global errno
errno: .word 0
