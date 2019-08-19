# pwn-cheat-sheet

### (code) Format string - write value into address
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
### (code) Pack (int to str)
###### taken from http://docs.pwntools.com/en/stable/util/packing.html
```
p32(0x12345678)         # 4 byte value
p64(0x1234567812345678) # 8 byte value
```

### (code) Unpack (str to int)
###### taken from http://docs.pwntools.com/en/stable/util/packing.html
```
u = make_unpacker(32, endian='little', sign='unsigned') # 4 byte value
u = make_unpacker(64, endian='little', sign='unsigned') # 8 byte value
```

### (tool) ROPgadget
###### taken from https://github.com/JonathanSalwan/ROPgadget
###### clone date:  13.8.2019
This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation. ROPgadget supports ELF, PE and Mach-O format on x86, x64, ARM, ARM64, PowerPC, SPARC and MIPS architectures.

### (tool) one_gadget
###### clone date:  13.8.2019
###### taken from https://github.com/david942j/one_gadget
Tool for finding one gadget RCE in libc

### (tool) libc-database
###### taken from https://github.com/niklasb/libc-database
###### clone date:  13.8.2019
Database of libc functions offsets

### (heap) bins (fast, small, large, unsorted)
1.  Fast bins
    - 10 fast bin linked list
    - single linked list
    - LIFO addition deletion
    - each bin list contains same size chunks (16,24,32.......88)
    - never coalesce together
2.  Unsorted bins
    - 1 unsorted bin linked list
    - small & arge bins deleting to this bin and than move to small/large bins
    - acts like cache layer
3.  Small bins
    - 62 small bins
    - double linked list
    - FIFO
    - may be coalesced toghether beofre ending up in unsorted bins
    - each bin has chunks of the same size
    - bins sizes 16,24....504
4.  Large bins
    - 63 bins
    - double linked list
    - sorted in decreasing order (largest at the head)
    - Insertions and removals happen at any position 
    - may be coalesced toghether beofre ending up in unsorted bins
    

### (heap, tip) Safe heap managements
* After free(X) set X value to 0
* After malloc(size) reset the memory region you got, or initialize the memory with default safe values

**Without these operations the code may be vulnarble !! (UAF, Double Free, etc..)**

### (heap, tip) Heap Exploitation tips & techniques
* tcache - no Modern Heap Security Checks
* unsorted bin - chunk->fd/bk may contains (in specific nodes) libc address (main_arena + 96), may lean to **info leak**
* `__malloc_hook` function, a good target to overwrite to trigger code execution (one gadgets ;) )


###### taken from https://github.com/shellphish/how2heap

| File | Technique | Glibc-Version |Applicable CTF Challenges |
|------|-----------|---------------|--------------------------|
| [first_fit.c](first_fit.c) | Demonstrating glibc malloc's first-fit behavior. | | |
| [fastbin_dup.c](fastbin_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. | | |
| [fastbin_dup_into_stack.c](glibc_2.25/fastbin_dup_into_stack.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. | latest | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [fastbin_dup_consolidate.c](glibc_2.25/fastbin_dup_consolidate.c) | Tricking malloc into returning an already-allocated heap pointer by putting a pointer on both fastbin freelist and unsorted bin freelist. | latest | [Hitcon 2016 SleepyHolder](https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder) |
| [unsafe_unlink.c](glibc_2.26/unsafe_unlink.c) | Exploiting free on a corrupted chunk to get arbitrary write. | < 2.26 | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](glibc_2.25/house_of_spirit.c) | Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer. | latest | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](glibc_2.25/poison_null_byte.c) | Exploiting a single null byte overflow. | < 2.26 | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb) |
| [house_of_lore.c](glibc_2.26/house_of_lore.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist. | < 2.26 | |
| [overlapping_chunks.c](glibc_2.26/overlapping_chunks.c) | Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk | < 2.26 | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [overlapping_chunks_2.c](glibc_2.25/overlapping_chunks_2.c) | Exploit the overwrite of an in use chunk size in order to make a new allocation overlap with an existing chunk  | latest | |
| [house_of_force.c](glibc_2.25/house_of_force.c) | Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer | < 2.29 | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_into_stack.c](glibc_2.26/unsorted_bin_into_stack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to return a nearly-arbitrary pointer.  | < 2.26 | |
| [unsorted_bin_attack.c](glibc_2.26/unsorted_bin_attack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address  | < 2.26 | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [large_bin_attack.c](glibc_2.26/large_bin_attack.c) | Exploiting the overwrite of a freed chunk on large bin freelist to write a large value into arbitrary address  | < 2.26 | [0ctf 2018-heapstorm2](https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/) |
| [house_of_einherjar.c](glibc_2.26/house_of_einherjar.c) | Exploiting a single null byte overflow to trick malloc into returning a controlled pointer  | < 2.26 | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |
| [house_of_orange.c](glibc_2.25/house_of_orange.c) | Exploiting the Top Chunk (Wilderness) in order to gain arbitrary code execution  | < 2.26 | [Hitcon 2016 houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500) |
| [tcache_dup.c](glibc_2.26/tcache_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the tcache freelist. | 2.26 - 2.28 | |
| [tcache_poisoning.c](glibc_2.26/tcache_poisoning.c) | Tricking malloc into returning a completely arbitrary pointer by abusing the tcache freelist. | > 2.25  | |
| [tcache_house_of_spirit.c](glibc_2.26/tcache_house_of_spirit.c) | Frees a fake chunk to get malloc to return a nearly-arbitrary pointer. | > 2.25 | |





### (heap) Modern Heap Security Checks
###### For more Heap structure/exploitation learn https://heap-exploitation.dhavalkapil.com/
This presents a summary of the security checks introduced in glibc's implementation to detect and prevent heap related attacks.

| Function | Security Check | Error |
| --- | --- | --- |
| unlink | Whether chunk size is equal to the previous size set in the next chunk (in memory) | corrupted size vs. prev\_size |
| unlink | Whether `P->fd->bk == P` and `P->bk->fd == P`\* | corrupted double-linked list |
| \_int\_malloc | While removing the first chunk from fastbin (to service a malloc request), check whether the size of the chunk falls in fast chunk size range | malloc(): memory corruption (fast) |
| \_int\_malloc | While removing the last chunk (`victim`) from a smallbin (to service a malloc request), check whether `victim->bk->fd` and `victim` are equal | malloc(): smallbin double linked list corrupted |
| \_int\_malloc | While iterating in unsorted bin, check whether size of current chunk is within minimum (`2*SIZE_SZ`) and maximum (`av->system_mem`) range | malloc(): memory corruption |
| \_int\_malloc | While inserting last remainder chunk into unsorted bin (after splitting a large chunk), check whether `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)` | malloc(): corrupted unsorted chunks |
| \_int\_malloc | While inserting last remainder chunk into unsorted bin (after splitting a fast or a small chunk), check whether `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)` | malloc(): corrupted unsorted chunks 2 |
| \_int\_free | Check whether `p`\*\* is before `p + chunksize(p)` in the memory (to avoid wrapping) | free(): invalid pointer |
| \_int\_free | Check whether the chunk is at least of size `MINSIZE` or a multiple of `MALLOC_ALIGNMENT` | free(): invalid size |
| \_int\_free | For a chunk with size in fastbin range, check if next chunk's size is between minimum and maximum size (`av->system_mem`) | free(): invalid next size (fast) |
| \_int\_free | While inserting fast chunk into fastbin (at `HEAD`), check whether the chunk already at `HEAD` is not the same | double free or corruption (fasttop) |
| \_int\_free | While inserting fast chunk into fastbin (at `HEAD`), check whether size of the chunk at `HEAD` is same as the chunk to be inserted | invalid fastbin entry (free) |
| \_int\_free | If the chunk is not within the size range of fastbin and neither it is a mmapped chunks, check whether it is not the same as the top chunk | double free or corruption (top) |
| \_int\_free | Check whether next chunk (by memory) is within the boundaries of the arena | double free or corruption (out) |
| \_int\_free | Check whether next chunk's (by memory) previous in use bit is marked | double free or corruption (!prev) |
| \_int\_free | Check whether size of next chunk is within the minimum and maximum size (`av->system_mem`) | free(): invalid next size (normal) |
| \_int\_free | While inserting the coalesced chunk into unsorted bin, check whether `unsorted_chunks(av)->fd->bk == unsorted_chunks(av)` | free(): corrupted unsorted chunks |
