# Trace a missing input in bzip2recover

What happens when bzip2recover cannot open its input file? This walkthrough starts with an error string and follows a reference into executable code. HexScry reads the target as data throughout.

## Identify the sample

The tested binary came from Git for Windows 2.55.0.windows.5, under `mingw64/bin/bzip2recover.exe` in the Git installation. Its package manifest identifies `mingw-w64-x86_64-bzip2 1.0.8-4`. Other builds may have different offsets and function names. The addresses below apply to this SHA-256:

```text
bb4d99af508bcedc555b3a392ad6622761c254265d3f1da5654e8e5d25656b8a
```

Use **Open binary** and check the SHA-256 in the target panel. The string search works with the built-in parser. Following code references requires Ghidra and a compatible JDK.

## Follow the evidence

1. In **Printable strings**, filter for `can't read`. The match at file offset `0x8D74` includes placeholders for the program and input names. The string alone does not tell you when it is printed.
2. Click **Analyze with Ghidra**. In alpha.2 or later, click the matching string to inspect its loaded address directly. In alpha.1, use the manual calculation below. The navigation box accepts virtual addresses. For this build the image base is `0x140000000`. The string is `0x174` bytes into the raw data of the `.rdata` section (file start `0x8C00`, section RVA `0xB000`). Its loaded address is therefore `0x14000B174`.
3. If using alpha.1, enter that address in the navigation box and press Enter. In **Instruction**, Ghidra classifies the location as data. Under **Incoming references** it reports one source, `0x140009399`. Click that source address to move from the text to its use. In alpha.1, enter it in the navigation box instead.
4. Open **Pseudocode** for the containing function, `FUN_140008b00`. Find the first call that opens the input in `rb` mode. The null-result branch formats the error with the input filename and calls `exit(1)`. Another open later in the same function has a different error message.
5. Give the function an analyst alias such as `recover_main`, record your finding in **Comment**, and choose **Save project**. The project records the alias against function address `0x140008b00` and identifies the target by SHA-256.

## Check the interpretation

In the bzip2 1.0.8 source, the corresponding code is in `main`. It sends the message to standard error and exits with status 1 when the first read-only open returns null. A missing file is one way to reach the branch. This evidence does not distinguish it from a permission failure. Ghidra leaves the formatted-output helper unnamed in this build; the source identifies the original operation as `fprintf`. [Compare bzip2recover.c](https://sources.debian.org/src/bzip2/1.0.8-5/bzip2recover.c/)
