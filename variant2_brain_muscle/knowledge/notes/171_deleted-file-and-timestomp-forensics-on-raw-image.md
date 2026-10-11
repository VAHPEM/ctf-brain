---
tags: forensics ext4 debugfs sleuthkit fls icat carve deleted inode timestamp timestomp binwalk dd
source: distilled/cssctf
---
On a raw filesystem image: debugfs -R 'lsdel' img lists deleted inodes and debugfs -R 'cat <N>' img reads one back; Sleuth Kit fls -rd / icat are the equivalents. debugfs -R 'stat <file>' img shows all four timestamps (atime/mtime/ctime/crtime) - a crtime LATER than mtime, or a too-round ctime, betrays timestomping and points at the real event time. Carve appended/embedded files with binwalk/foremost (data after a file's real EOF, extra PNG chunks, ZIP tails), and reach raw partitions with fdisk -l + dd skip=.. count=.. then grep/regex a magic to find records.
