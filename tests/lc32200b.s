ADD $at, $zero, $k0         ! 0000 0001 0000 0000000000000000 1100
ADDI $v0, $a0, -1           ! 0001 0010 0011 11111111111111111111
NAND $a2, $t0, $t1          ! 0010 0101 0110 0000000000000000 0111
JALR $t2, $s0               ! 0100 1001 1000 00000000000000000000
                            ! 0000 0000 0000 0000000000000000 0000

LDR $s1, -1($s2)            ! 0101 1010 1011 11111111111111111111
STR $sp, 15($fp)            ! 0111 1101 1110 0000000000000000 1111

shifting:
SHFLL $ra, $ra, -1          ! 1000 1111 1111 00 0000000000000 11111
SHFRL $ra, $ra, -1          ! 1000 1111 1111 01 0000000000000 11111
SHFRA $zero, $zero, -1      ! 1000 0000 0000 11 0000000000000 11111

branch:
BEQ $v0, $a0, shifting      ! 0011 0010 0011 11111111111111111100
                            ! 0000 0000 0000 0000000000000000 0000

jump:
LEA $ra, jump               ! 0110 1111 0000 111111111111111111111
HALT                        ! 1111 0000000000000000000000000000
.fill -1                    ! 1111111111111111111111111111111111

ret                         ! 0100 0000 1111 000000000000000000000