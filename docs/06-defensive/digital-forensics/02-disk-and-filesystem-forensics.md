---
title: "02 - Disk and Filesystem Forensics"
description: "Creating a bit-for-bit copy of a storage medium."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Digital Forensics", "02 Disk And Filesystem Forensics.Md"]
---

# 02 - Disk and Filesystem Forensics

## File System Artifacts

### NTFS (Windows)
- **`$MFT (Master File Table):** The core of NTFS. Every file and directory on an NTFS volume has at least one entry in the $`MFT.
- **LogFile ($LogFile):** A journal that records metadata changes to the volume, useful for recovering deleted file information.
- **USN Journal (`$Extend\$`UsnJrnl):** Maintains a record of changes made to files on the volume (e.g., creations, deletions, modifications).

### EXT4 (Linux)
- **Inodes:** Data structures that store metadata about files, directories, and other file system objects.

## Raw Disk Imaging
Creating a bit-for-bit copy of a storage medium.

### `dd` (Linux/macOS)
The standard command-line tool for raw copying.

```bash
# Create a raw image of /dev/sdb, saving it to an evidence drive, with 4MB block size
sudo dd if=/dev/sdb of=/mnt/evidence/drive_image.dd bs=4M status=progress
```

### FTK Imager
A popular GUI and CLI tool used to acquire images in raw (DD), SMART, E01, or AFF formats. E01 is commonly used as it supports compression and embedded metadata/hashes.

```bash
# CLI example (Linux) for creating an E01 image
ftkimager /dev/sdb /mnt/evidence/image -e01 --frag 2G --description "Suspect Drive" --examiner "AppSec Atlas"
```

## File Carving
File carving is the process of extracting data (files) from a drive or image without the assistance of a filesystem. It relies on known file signatures (magic numbers/headers and footers).

### Scalpel Example
```bash
# Edit scalpel configuration to uncomment file types to carve (e.g., pdf, jpg)
nano /etc/scalpel/scalpel.conf

# Run scalpel against an image
scalpel -c /etc/scalpel/scalpel.conf -o /mnt/evidence/carved_files/ /mnt/evidence/drive_image.dd
```
