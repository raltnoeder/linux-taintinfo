# Linux kernel taint information utility

**Provides a human-readable description of Linux kernel taint flags**

Building requires the [cppdsaext](https://github.com/raltnoeder/cppdsaext) library.

## Usage

```
taintinfo { current | list | taint=<flags> }
```

`taintinfo current` shows information about the current taint status of the running kernel:

```
$ taintinfo current
Taint flags:            G...........O.....
Numeric representation: 4096 / 0x0000000000001000

- G Only GPL modules were loaded (1 unset)
- O Externally-built (out-of-tree) module was loaded (4096)
```

`taintinfo list` shows a list of all taint flags known by this program.

`taintinfo taint=<flags>` shows information about the specified taint flags:

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

Output is color-coded: Uncritical taint flags are displayed in green, taint flags that indicate warnings are displayed in yellow, taint flags that indicate errors are displayed in red.
