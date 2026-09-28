## pixel_loader

This project is now a Ghidra analysis script for Google Pixel ABL bootloader binaries.

Tested on bootloaders from:

  * Pixel 6 / 6 Pro and 6a
  * Pixel 7 / 7 Pro
  * Pixel 8 / 8 Pro

NOTE: the script still does not cover some of the newer ABL changes introduced after June 5th 2024.

### Installation

Copy the script to a Ghidra script directory, for example:

```
$GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts/
```

You can also use any personal script directory configured in Ghidra's Script Manager.

### Usage

1. Extract the bootloader contents with [Jonathan Levin's ImjTool](https://newandroidbook.com/tools/imjtool.html):

   ```
   ./imjtool.ELF64 bootloader-oriole-slider-1.3-10674934.img extract
   ```

2. Import the extracted `abl` binary into Ghidra as a raw binary.
3. Select the AArch64 little-endian language during import.
4. Run `PixelBootloader.py` from Ghidra's Script Manager.

The script will:

  * Rebase the program to the Pixel ABL runtime base address.
  * Locate and label the function table when present.
  * Create and name functions from the loader metadata.
  * Supplement table-based recovery with prologue scanning, or fall back entirely to prologue scanning when the table is missing.

### Notes

This is a post-import Ghidra script rather than a native Ghidra loader extension, which keeps the project simple and avoids a separate Java extension build.
