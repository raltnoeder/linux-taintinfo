# Linux kernel taint information utility

**Provides a human-readable description of Linux kernel taint flags**

Building requires the [cppdsaext](https://github.com/raltnoeder/cppdsaext) library.

## Usage

taintinfo current  
taintinfo list  
taintinfo taint=*flags*  
taintinfo value=*number*  

**taintinfo current** shows information about the current taint status of the running kernel:

```
$ taintinfo current
Taint flags:            G...........O.....
Numeric representation: 4096 / 0x0000000000001000

- G Only GPL modules were loaded (1 unset)
- O Externally-built (out-of-tree) module was loaded (4096)
```

**taintinfo list** shows a list of all taint flags known by this program.

**taintinfo taint=*flags*** shows information about the specified taint flags:

```
$ taintinfo taint=pmeol
Taint flags:            P...M.......OEL...
Numeric representation: 28689 / 0x0000000000007011

- P Proprietary modules were loaded (1)
- M Processor reported a Machine Check Exception (hardware error) (16)
- O Externally-built (out-of-tree) module was loaded (4096)
- E Unsigned module was loaded (8192)
- L Soft lockup occurred (16384)
```

**taintinfo value=*number*** shows information about the specified numeric taint:

```
$ taintinfo value=1169
Taint flags:            P...M..D..C.......
Numeric representation: 1169 / 0x0000000000000491

- P Proprietary modules were loaded (1)
- M Processor reported a Machine Check Exception (hardware error) (16)
- D Kernel OOPS or BUG triggered taint (128)
- C Module from drivers/staging was loaded (1024)
```

Output is color-coded: Uncritical taint flags are displayed in green,
taint flags that indicate warnings are displayed in yellow, taint flags that indicate errors are displayed in red.

## Known limitations

**Identification of conflicting taint flags**  
When using the *taint* argument, taintinfo does not identify conflicting flags, e.g. **G** vs. **P**,
which specify the same taint bit (**G** indicates the flag is clear while **P** indicates the flag is set).

**Identification of unmapped taint bit values**  
When using the *value* argument, taintinfo does not identify unmapped (unknown) bit values, and the
numeric representation shows the original input value, not just the numeric representation of those
taint flags that were identified.

**Relation between taint flags and the Linux kernel version**  
The ability of this program to identify taint flags depends on the version of the program, not the
version of the Linux kernel. This means that if there is a mismatch between the version of this
program and the Linux kernel version that produced the taint flags or taint value, some taint flags
may be misinterpreted or not interpreted at all if taint flags have been added, removed or changed
in that version of the Linux kernel. However, it also enables use of this program on various other
operating systems, e.g. for the purpose of interpreting kernel log files from Linux servers on
a workstation that does not run a Linux-based operating system.

