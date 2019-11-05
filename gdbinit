# .gdbinit by sha0coder

source /home/sha0/soft/gdb_automatization/reversing.py 

define golib
	set pagination off
	while ($eip < 0x10000000)
		si
	end
	set pagination on
end


define gobin
	set pagination off
	while ($eip > 0x10000000)
		si
	end
	set pagination on
end



define finder
	set $str = $arg0
	set $sz = sizeof($str)-1
	set $off = $arg1
	set $max = 0xffff

	printf "Looking for %s ...\n",  $str
	set $ptr = $off	
	
	while ($ptr < ($off+$max))
		printf "%s>>0x%x\r", $str,(unsigned long *)$ptr
		set $l = 0
		set $sim = 0

		while ($l < $sz)
			set $c = *((unsigned char *)($ptr+$l))
			set $cc = *((unsigned char *)($str+$l))


              		if ($c == $cc)
	                	set $sim++
                	else
                       	end 

                        set $l++
		end

                if ($sim == $sz)
                        printf "\rFound at 0x%x\n",(unsigned long *)$ptr
                end
		set $ptr++
	end	

	printf "\n\n"
	
end
document finder
	Look for strings.
	USAGE:   locate [string] [address]
end

define repag
    set $mask = 0xfffff000
    set $where = $arg0 & $mask
    set $test = $pc & $mask


    print "target:"
    p/x $where

    while $test != $where
        si
        set $test = $pc & $mask
        p/x $test
    end 

    print "end."
end

define cls
    shell clear
end

define gocall
	set confirm off
	while (*(unsigned char *)$eip != 0xe8)
		si
	end
	set confirm on
end



define w
	disas $eip
end

define ww
        set $max=50
        set $c=0
        x/i $eip+$c
        while ($c++ < $max)
                x/i
        end
end



# from ibm http://www.ibm.com/developerworks/aix/library/au-gdb.html
define ascii_char
	set $_c=*(unsigned char *)($arg0)
	if ( $_c < 0x20 || $_c > 0x7E )
		printf "."
	else
		printf "%c", $_c
	end
end
document ascii_char
	Print the ASCII value of arg0 or '.' if value is unprintable
end



define hex_quad
	printf "%02X %02X %02X %02X  %02X %02X %02X %02X",                          \
               *(unsigned char*)($arg0), *(unsigned char*)($arg0 + 1),      \
               *(unsigned char*)($arg0 + 2), *(unsigned char*)($arg0 + 3),  \
               *(unsigned char*)($arg0 + 4), *(unsigned char*)($arg0 + 5),  \
               *(unsigned char*)($arg0 + 6), *(unsigned char*)($arg0 + 7)
end
document hex_quad
	Print eight hexadecimal bytes starting at arg0
end

define hexdump
	printf "%08X : ", $arg0
	hex_quad $arg0
	printf " - "
	hex_quad ($arg0+8)
	printf " "

	ascii_char ($arg0)
	ascii_char ($arg0+1)
	ascii_char ($arg0+2)
	ascii_char ($arg0+3)
	ascii_char ($arg0+4)
	ascii_char ($arg0+5)
	ascii_char ($arg0+6)
	ascii_char ($arg0+7)
	ascii_char ($arg0+8)
	ascii_char ($arg0+9)
	ascii_char ($arg0+0xA)
	ascii_char ($arg0+0xB)
	ascii_char ($arg0+0xC)
	ascii_char ($arg0+0xD)
	ascii_char ($arg0+0xE)
	ascii_char ($arg0+0xF)
	
	printf "\n"
end
document hexdump
	Display a 16-byte hex/ASCII dump of arg0
end

define ddump
	printf "[%04X:%08X]------------------------", $ds, $data_addr
	printf "---------------------------------[ data]\n"
	set $_count=0
	while ( $_count < $arg0 )
		set $_i=($_count*0x10)
		hexdump ($data_addr+$_i)
		set $_count++
	end
end
document ddump
	Display $arg0 lines of hexdump for address $data_addr
end

define dd
	if ( ($arg0 & 0x40000000) || ($arg0 & 0x08000000) || ($arg0 & 0xBF000000) )
		set $data_addr=$arg0
		ddump 0x10
	else
		printf "Invalid address: %08X\n", $arg0
	end
end
document dd
	Display 16 lines of a hex dump for $arg0
end

define datawin
	if ( ($esi & 0x40000000) || ($esi & 0x08000000) || ($esi & 0xBF000000) )
		set $data_addr=$esi
	else
		if ( ($edi & 0x40000000) || ($edi & 0x08000000) || ($edi & 0xBF000000) )
			set $data_addr=$edi
		else
			if ( ($eax & 0x40000000) || ($eax & 0x08000000) || \
      				($eax & 0xBF000000) )
				set $data_addr=$eax
			else
				set $data_addr=$esp
			end
		end
	end
	ddump 2
end
document datawin
	Display esi, edi, eax, or esp in the data window
end


# by @taviso
define assemble
 # dont enter routine again if user hits enter
 dont-repeat
 if ($argc)
  if (*$arg0 = *$arg0)
    # check if we have a valid address by dereferencing it,
    # if we havnt, this will cause the routine to exit.
  end
  printf "Instructions will be written to %#x.\n", $arg0
 else
  printf "Instructions will be written to stdout.\n"
 end
 printf "Type instructions, one per line.\n"
 printf "End with a line saying just \"end\".\n"
 if ($argc)
  # argument specified, assemble instructions into memory
  # at address specified.
  shell nasm -f bin -o /dev/stdout /dev/stdin \
    <<< "$( echo "BITS 32"; while read -ep '>' r && test "$r" != end; \
                do echo -E "$r"; done )" | hexdump -ve \
        '1/1 "set *((unsigned char *) $arg0 + %#2_ax) = %#02x\n"' \
            > ~/.gdbassemble
  # load the file containing set instructions
  source ~/.gdbassemble
  # all done.
  shell rm -f ~/.gdbassemble
 else
  # no argument, assemble instructions to stdout
  shell nasm -f bin -o /dev/stdout /dev/stdin \
    <<< "$( echo "BITS 32"; while read -ep '>' r && test "$r" != end; \
                do echo -E "$r"; done )" | ndisasm -i -b32 /dev/stdin
 end
end
document assemble
Assemble instructions using nasm.
Type a line containing "ead" to indicate thesend.
end

#http://reverse.put.as/wp-content/uploads/2010/04/gdbinit73
define dumpjump
 set $_byte1 = *(unsigned char *)$pc
 set $_byte2 = *(unsigned char *)($pc+1)
## and now check what kind of jump we have (in case it's a jump instruction)
## I changed the flags routine to save the flag into a variable, so we don't need to repeat the process :) (search for "define flags")

## opcode 0x77: JA, JNBE (jump if CF=0 and ZF=0)
## opcode 0x0F87: JNBE, JA
 if ( ($_byte1 == 0x77) || ($_byte1 == 0x0F && $_byte2 == 0x87) )
 	# cf=0 and zf=0
 	if ($_cf_flag == 0 && $_zf_flag == 0)
		echo \033[31m
   		printf "  Jump is taken (c=0 and z=0)"
  	else
	# cf != 0 or zf != 0
   		echo \033[31m
   		printf "  Jump is NOT taken (c!=0 or z!=0)"
  	end 
 end

## opcode 0x73: JAE, JNB, JNC (jump if CF=0)
## opcode 0x0F83: JNC, JNB, JAE (jump if CF=0)
 if ( ($_byte1 == 0x73) || ($_byte1 == 0x0F && $_byte2 == 0x83) )
 	# cf=0
 	if ($_cf_flag == 0)
		echo \033[31m
   		printf "  Jump is taken (c=0)"
  	else
	# cf != 0
   		echo \033[31m
   		printf "  Jump is NOT taken (c!=0)"
  	end 
 end
 	
## opcode 0x72: JB, JC, JNAE (jump if CF=1)
## opcode 0x0F82: JNAE, JB, JC
 if ( ($_byte1 == 0x72) || ($_byte1 == 0x0F && $_byte2 == 0x82) )
 	# cf=1
 	if ($_cf_flag == 1)
		echo \033[31m
   		printf "  Jump is taken (c=1)"
  	else
	# cf != 1
   		echo \033[31m
   		printf "  Jump is NOT taken (c!=1)"
  	end 
 end

## opcode 0x76: JBE, JNA (jump if CF=1 or ZF=1)
## opcode 0x0F86: JBE, JNA
 if ( ($_byte1 == 0x76) || ($_byte1 == 0x0F && $_byte2 == 0x86) )
 	# cf=1 or zf=1
 	if (($_cf_flag == 1) || ($_zf_flag == 1))
		echo \033[31m
   		printf "  Jump is taken (c=1 or z=1)"
  	else
	# cf != 1 or zf != 1
   		echo \033[31m
   		printf "  Jump is NOT taken (c!=1 or z!=1)"
  	end 
 end

## opcode 0xE3: JCXZ, JECXZ, JRCXZ (jump if CX=0 or ECX=0 or RCX=0)
 if ($_byte1 == 0xE3)
 	# cx=0 or ecx=0
 	if (($ecx == 0) || ($cx == 0))
		echo \033[31m
   		printf "  Jump is taken (cx=0 or ecx=0)"
  	else
	#
   		echo \033[31m
   		printf "  Jump is NOT taken (cx!=0 or ecx!=0)"
  	end 
 end

## opcode 0x74: JE, JZ (jump if ZF=1)
## opcode 0x0F84: JZ, JE, JZ (jump if ZF=1)
 if ( ($_byte1 == 0x74) || ($_byte1 == 0x0F && $_byte2 == 0x84) )
 # ZF = 1
  	if ($_zf_flag == 1)
   		echo \033[31m
   		printf "  Jump is taken (z=1)"
  	else
 # ZF = 0
   		echo \033[31m
   		printf "  Jump is NOT taken (z!=1)"
  	end 
 end

## opcode 0x7F: JG, JNLE (jump if ZF=0 and SF=OF)
## opcode 0x0F8F: JNLE, JG (jump if ZF=0 and SF=OF)
 if ( ($_byte1 == 0x7F) || ($_byte1 == 0x0F && $_byte2 == 0x8F) )
 # zf = 0 and sf = of
  	if (($_zf_flag == 0) && ($_sf_flag == $_of_flag))
   		echo \033[31m
   		printf "  Jump is taken (z=0 and s=o)"
  	else
 #
   		echo \033[31m
   		printf "  Jump is NOT taken (z!=0 or s!=o)"
  	end 
 end

## opcode 0x7D: JGE, JNL (jump if SF=OF)
## opcode 0x0F8D: JNL, JGE (jump if SF=OF)
 if ( ($_byte1 == 0x7D) || ($_byte1 == 0x0F && $_byte2 == 0x8D) )
 # sf = of
  	if ($_sf_flag == $_of_flag)
   		echo \033[31m
   		printf "  Jump is taken (s=o)"
  	else
 #
   		echo \033[31m
   		printf "  Jump is NOT taken (s!=o)"
  	end 
 end

## opcode: 0x7C: JL, JNGE (jump if SF != OF)
## opcode: 0x0F8C: JNGE, JL (jump if SF != OF)
 if ( ($_byte1 == 0x7C) || ($_byte1 == 0x0F && $_byte2 == 0x8C) )
 # sf != of
  	if ($_sf_flag != $_of_flag)
   		echo \033[31m
   		printf "  Jump is taken (s!=o)"
  	else
 #
   		echo \033[31m
   		printf "  Jump is NOT taken (s=o)"
  	end 
 end

## opcode 0x7E: JLE, JNG (jump if ZF = 1 or SF != OF)
## opcode 0x0F8E: JNG, JLE (jump if ZF = 1 or SF != OF)
 if ( ($_byte1 == 0x7E) || ($_byte1 == 0x0F && $_byte2 == 0x8E) )
 # zf = 1 or sf != of
  	if (($_zf_flag == 1) || ($_sf_flag != $_of_flag))
   		echo \033[31m
   		printf "  Jump is taken (zf=1 or sf!=of)"
  	else
 #
   		echo \033[31m
   		printf "  Jump is NOT taken (zf!=1 or sf=of)"
  	end 
 end

## opcode 0x75: JNE, JNZ (jump if ZF = 0)
## opcode 0x0F85: JNE, JNZ (jump if ZF = 0)
 if ( ($_byte1 == 0x75) || ($_byte1 == 0x0F && $_byte2 == 0x85) )
 # ZF = 0
  	if ($_zf_flag == 0)
   		echo \033[31m
   		printf "  Jump is taken (z=0)"
  	else
 # ZF = 1
   		echo \033[31m
   		printf "  Jump is NOT taken (z!=0)"
  	end 
 end
 
## opcode 0x71: JNO (OF = 0)
## opcode 0x0F81: JNO (OF = 0)
 if ( ($_byte1 == 0x71) || ($_byte1 == 0x0F && $_byte2 == 0x81) )
 # OF = 0
	if ($_of_flag == 0)
   		echo \033[31m
   		printf "  Jump is taken (o=0)"
	else
 # OF != 0
   		echo \033[31m
   		printf "  Jump is NOT taken (o!=0)"
  	end 
 end

## opcode 0x7B: JNP, JPO (jump if PF = 0)
## opcode 0x0F8B: JPO (jump if PF = 0)
 if ( ($_byte1 == 0x7B) || ($_byte1 == 0x0F && $_byte2 == 0x8B) )
 # PF = 0
  	if ($_pf_flag == 0)
   		echo \033[31m
   		printf "  Jump is NOT taken (p=0)"
  	else
 # PF != 0
   		echo \033[31m
   		printf "  Jump is taken (p!=0)"
  	end 
 end

## opcode 0x79: JNS (jump if SF = 0)
## opcode 0x0F89: JNS (jump if SF = 0)
 if ( ($_byte1 == 0x79) || ($_byte1 == 0x0F && $_byte2 == 0x89) )
 # SF = 0
  	if ($_sf_flag == 0)
   		echo \033[31m
   		printf "  Jump is taken (s=0)"
  	else
 # SF != 0
   		echo \033[31m
   		printf "  Jump is NOT taken (s!=0)"
  	end 
 end

## opcode 0x70: JO (jump if OF=1)
## opcode 0x0F80: JO (jump if OF=1)
 if ( ($_byte1 == 0x70) || ($_byte1 == 0x0F && $_byte2 == 0x80) )
 # OF = 1
	if ($_of_flag == 1)
		echo \033[31m
   		printf "  Jump is taken (o=1)"
  	else
 # OF != 1
   		echo \033[31m
   		printf "  Jump is NOT taken (o!=1)"
  	end 
 end

## opcode 0x7A: JP, JPE (jump if PF=1)
## opcode 0x0F8A: JP, JPE (jump if PF=1)
 if ( ($_byte1 == 0x7A) || ($_byte1 == 0x0F && $_byte2 == 0x8A) )
 # PF = 1
  	if ($_pf_flag == 1)
   		echo \033[31m
   		printf "  Jump is taken (p=1)"
  	else
 # PF = 0
   		echo \033[31m
   		printf "  Jump is NOT taken (p!=1)"
  	end 
 end

## opcode 0x78: JS (jump if SF=1)
## opcode 0x0F88: JS (jump if SF=1)
 if ( ($_byte1 == 0x78) || ($_byte1 == 0x0F && $_byte2 == 0x88) )
 # SF = 1
	if ($_sf_flag == 1)
   		echo \033[31m
   		printf "  Jump is taken (s=1)"
  	else
 # SF != 1
   		echo \033[31m
   		printf "  Jump is NOT taken (s!=1)"
  	end 
 end

# end of dumpjump function
end
document dumpjump
	Display if conditional jump will be taken or not end
	If an address is specified, insert instructions at that address.
	If no address is specified, assembled instructions are printed to stdout.
	Use the pseudo instruction "org ADDR" to set the base address.
end
