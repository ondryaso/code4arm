.arm
.syntax unified

.global _start

_start:
    BL main
    MOV R7, 0xff000000
    SVC 0
