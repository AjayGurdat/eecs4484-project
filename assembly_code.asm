.CODE
_same_jump PROC
    jz loc_123+1
    jnz loc_123+1

loc_123:
    db 0E8h
    xor eax, eax
    ret
_same_jump ENDP
END
