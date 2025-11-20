## Getting Started with Bandit

### Prerequisites
- **SSH client**: Built into Linux/Mac, use PuTTY/WSL on Windows
- **Basic terminal knowledge**
- **Patience and curiosity!**

### Bandit Level 0

**Level Goal**: Connect to the game via SSH

**Solution**:
```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```
**Password**: `bandit0`

**Writeup**:
- This is the entry point to the Bandit wargame
- Use SSH to connect to the server on port 2220
- The username is `bandit0` and password is `bandit0`
- Once connected, you'll see a command prompt where you can start solving levels

---

### Bandit Level 0 → Level 1

**Level Goal**: Find the password for the next level in the `readme` file

**Solution**:
```bash
❯ ssh bandit0@bandit.labs.overthewire.org -p 2220
....
bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme 
Congratulations on your first steps into the bandit game!!
Please make sure you have read the rules at https://overthewire.org/rules/
If you are following a course, workshop, walkthrough or other educational activity,
please inform the instructor about the rules as well and encourage them to
contribute to the OverTheWire community so we can keep these games free!

The password you are looking for is: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If

bandit0@bandit:~$ 
```
**Password**: `ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If`

**Writeup**:
- After logging in, use `ls` to list files
- You'll see a `readme` file
- Use `cat readme` to display its contents
- The output is the password for level 1

---

### Bandit Level 1 → Level 2

**Level Goal**: The password is in a file named `-`

**Solution**:
```bash
❯ ssh bandit1@bandit.labs.overthewire.org -p 2220
....
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat ./-
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
bandit1@bandit:~$ cat < -
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
bandit1@bandit:~$ 
```
**Password**: `263JGJPfgU6LtdEvgfWU1XP5yac29mFx`

**Writeup**:
- The filename `-` is special in Linux (usually means stdin/stdout)
- Use `./-` to specify the current directory's `-` file
- Alternative: use `cat < -` to redirect input

---

### Bandit Level 2 → Level 3

**Level Goal**: Password in a file with spaces in the filename

**Solution**:
```bash
❯ ssh bandit2@bandit.labs.overthewire.org -p 2220
....
bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ cat "./--spaces in this filename--"
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
bandit2@bandit:~$ cat /home/bandit2/--spaces\ in\ this\ filename--
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
bandit2@bandit:~$ cat -- "--spaces in this filename--"
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
bandit2@bandit:~$ 
```
**Password**: `MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx`

**Writeup**:
- Filenames with spaces need to be quoted or escaped
- Use quotes: `"filename with spaces"`
- Or escape spaces: `filename\ with\ spaces`

---

### Bandit Level 3 → Level 4

**Level Goal**: Password in a hidden file in the **inhere** directory

**Solution**:
```bash
❯ ssh bandit3@bandit.labs.overthewire.org -p 2220
....
bandit3@bandit:~$ ls
inhere
bandit3@bandit:~$ ls -la inhere/
total 12
drwxr-xr-x 2 root    root    4096 Oct 14 09:26 .
drwxr-xr-x 3 root    root    4096 Oct 14 09:26 ..
-rw-r----- 1 bandit4 bandit3   33 Oct 14 09:26 ...Hiding-From-You
bandit3@bandit:~$ cat inhere/...Hiding-From-You 
2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
bandit3@bandit:~$ 
```
**Password**: `2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ`

**Writeup**:
- The filename `...Hiding-From-You` starts with dots, making it a hidden file
- Hidden files don't show with regular `ls` - use `ls -a` to reveal them
- The dots at the beginning are part of the filename, not directory navigation
- Once found, read it normally with `cat`

---

### Bandit Level 4 → Level 5

**Level Goal**: Password in the only human-readable file in the **inhere** directory. Tip: if your terminal is messed up, try the “reset” command.

**Solution**:
```bash
❯ ssh bandit4@bandit.labs.overthewire.org -p 2220
....
bandit4@bandit:~$ ls
inhere
bandit4@bandit:~$ ls inhere/
-file00  -file01  -file02  -file03  -file04  -file05  -file06  -file07  -file08  -file09
bandit4@bandit:~$ cd inhere/
bandit4@bandit:~/inhere$ find . -type f -exec sh -c 'file "$1" | grep -q text && cat "$1"' _ {} \;
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
bandit4@bandit:~/inhere$ file ./* | grep text
./-file07: ASCII text
bandit4@bandit:~/inhere$ cat ./-file07
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
bandit4@bandit:~/inhere$ strings ./-file* | grep -E '^[A-Za-z0-9]{32}$'
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```
**Password**: `4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw`

**Writeup**:
- The filename `...Hiding-From-You` starts with dots, making it a hidden file
- Hidden files don't show with regular `ls` - use `ls -a` to reveal them
- The dots at the beginning are part of the filename, not directory navigation
- Once found, read it normally with `cat`

---

### Bandit Level 5 → Level 6

**Level Goal**: Password in a file somewhere under the **inhere** directory and has all of the following properties:

- human-readable
- 1033 bytes in size
- not executable

**Solution**:
```bash
❯ ssh bandit5@bandit.labs.overthewire.org -p 2220
....
bandit5@bandit:~$ ls
inhere
bandit5@bandit:~$ ls inhere/
maybehere00  maybehere02  maybehere04  maybehere06  maybehere08  maybehere10  maybehere12  maybehere14  maybehere16  maybehere18
maybehere01  maybehere03  maybehere05  maybehere07  maybehere09  maybehere11  maybehere13  maybehere15  maybehere17  maybehere19
bandit5@bandit:~$ find inhere/ -type f -size 1033c -ls
   577028      4 -rw-r-----   1 root     bandit5      1033 Oct 14 09:26 inhere/maybehere07/.file2
bandit5@bandit:~$ 
bandit5@bandit:~$ find inhere/ -type f -readable -size 1033c ! -executable
inhere/maybehere07/.file2
bandit5@bandit:~$ cat inhere/maybehere07/.file2
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
bandit5@bandit:~$ find inhere/ -type f -size 1033c -exec file {} \; | grep text
inhere/maybehere07/.file2: ASCII text, with very long lines (1000)
bandit5@bandit:~$ find inhere/ -type f -size 1033c -exec sh -c 'file "$1" | grep -q text && cat "$1"' _ {} \;
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
bandit5@bandit:~$ 
```
**Password**: `HWasnPhtq9AVKe0dmk45nxy20cvUa6EG`

**Writeup**:
- The `inhere` directory contains 20 subdirectories (`maybehere00` through `maybehere19`)
- Use `find` command with specific criteria to locate the target file:
  - `-type f`: only regular files
  - `-size 1033c`: exactly 1033 bytes in size
  - `-readable`: human-readable content
  - `! -executable`: not executable
- The file is hidden (`.file2`) and located in `maybehere07` subdirectory
- Multiple approaches work: using `-ls`, checking file type with `file`, or direct execution

---

### Bandit Level 6 → Level 7

**Level Goal**: Password **somewhere on the server** and has all of the following properties:
- owned by user bandit7
- owned by group bandit6  
- 33 bytes in size

**Solution**:
```bash
❯ ssh bandit6@bandit.labs.overthewire.org -p 2220
....
bandit6@bandit:~$ find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c -readable 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ ls -la /var/lib/dpkg/info/bandit7.password
-rw-r----- 1 bandit7 bandit6 33 Oct 14 09:26 /var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
bandit6@bandit:~$ 
```
**Password**: `morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj`

**Writeup**:
- Search the entire filesystem using `find /` with specific ownership and size criteria
- File must be owned by user `bandit7` and group `bandit6`
- File must be exactly 33 bytes in size
- Use `2>/dev/null` to suppress permission denied errors
- The file is located in system directory `/var/lib/dpkg/info/`

---

### Bandit Level 7 → Level 8

**Level Goal**: Password stored in the file **data.txt** next to the word **millionth**

**Solution**:
```bash
❯ ssh bandit7@bandit.labs.overthewire.org -p 2220
....
bandit7@bandit:~$ ls
data.txt
bandit7@bandit:~$ ls -lh data.txt
-rw-r----- 1 bandit8 bandit7 4.0M Oct 14 09:26 data.txt
bandit7@bandit:~$ wc -l data.txt
98567 data.txt
bandit7@bandit:~$ grep millionth data.txt
millionth	dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
bandit7@bandit:~$ awk '/millionth/ {print $2}' data.txt
dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
bandit7@bandit:~$ 
```
**Password**: `dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc`

**Writeup**:
- The file **data.txt** is very large (4.0M, 98,567 lines)
- Use `grep` to search for the word "millionth" in the file
- The password appears as the second field on the same line, separated by whitespace
- This teaches efficient searching in large log files

---

### Bandit Level 8 → Level 9

**Level Goal**: Password in the file **data.txt** and is the only line of text that occurs only once

**Solution**:
```bash
❯ ssh bandit8@bandit.labs.overthewire.org -p 2220
....
bandit8@bandit:~$ ls
data.txt
bandit8@bandit:~$ sort data.txt | uniq -u
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
bandit8@bandit:~$ sort data.txt | uniq -c | grep "1 "
      1 4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
bandit8@bandit:~$ awk '{count[$0]++} END {for (line in count) if (count[line] == 1) print line}' data.txt
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
bandit8@bandit:~$ 
```
**Password**: `4CKMh1JI91bUIZZPXDqGanal4xvAg0JM`

**Writeup**:
- The file contains many lines with duplicates
- Use `sort` to organize lines alphabetically (required for `uniq` to work properly)
- Pipe to `uniq -u` to display only unique lines (occur exactly once)
- The unique line contains the password for the next level
- This demonstrates data deduplication techniques

---

### Bandit Level 9 → Level 10

**Level Goal**: Password in the file **data.txt** in one of the few human-readable strings, preceded by several ‘=’ characters.

**Solution**:
```bash
❯ ssh bandit9@bandit.labs.overthewire.org -p 2220
....
bandit9@bandit:~$ ls
data.txt
bandit9@bandit:~$ strings data.txt | grep "=="
========== the
========== password
f\Z'========== is
========== FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
bandit9@bandit:~$ strings data.txt | grep -E "={5,}"
========== the
========== password
f\Z'========== is
========== FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
bandit9@bandit:~$ strings data.txt | grep "===" | tail -1
========== FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
bandit9@bandit:~$ 
```
**Password**: `FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey`

**Writeup**:
- The file **data.txt** contains binary data with embedded text strings
- Use `strings` command to extract human-readable text from binary files
- Look for lines containing multiple '=' characters using `grep`
- The password is preceded by several equals signs and appears as one of the readable strings
- This teaches working with binary files and extracting embedded text

---

### Bandit Level 10 → Level 11

**Level Goal**: Password in the file **data.txt**, which contains base64 encoded data

**Solution**:
```bash
❯ ssh bandit10@bandit.labs.overthewire.org -p 2220
....
bandit10@bandit:~$ ls
data.txt
bandit10@bandit:~$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIGR0UjE3M2ZaS2IwUlJzREZTR3NnMlJXbnBOVmozcVJyCg==
bandit10@bandit:~$ cat data.txt | base64 -d
The password is dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
bandit10@bandit:~$ base64 -d data.txt
The password is dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
bandit10@bandit:~$ which python3
/usr/bin/python3
bandit10@bandit:~$ python3 -c "import base64; print(base64.b64decode(open('data.txt').read()).decode())"
The password is dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr

bandit10@bandit:~$ 
```
**Password**: `dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr`

**Writeup**:
- The file **data.txt** contains base64 encoded data
- Use `base64 -d` command to decode the base64 content
- The decoded output reveals the password in plain text
- Base64 encoding is commonly used to represent binary data as ASCII text
- This introduces basic encoding/decoding techniques

---

### Bandit Level 11 → Level 12

**Level Goal**: Password in the file **data.txt**, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions

**Solution**:
```bash
❯ ssh bandit11@bandit.labs.overthewire.org -p 2220
....
bandit11@bandit:~$ ls
data.txt
bandit11@bandit:~$ cat data.txt 
Gur cnffjbeq vf 7k16JArUVv5LxVuJfsSVdbbtaHGlw9D4
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4
bandit11@bandit:~$ tr 'A-Za-z' 'N-ZA-Mn-za-m' < data.txt
The password is 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4
bandit11@bandit:~$ python3 -c "import codecs; print(codecs.decode(open('data.txt').read(), 'rot13'))"
The password is 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4

bandit11@bandit:~$ 
```
**Password**: `7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4`

**Writeup**:
- The file contains ROT13 encoded text (Caesar cipher with 13-position shift)
- Use `tr` command to perform character substitution
- Map A-Z to N-ZA-M and a-z to n-za-m to reverse the ROT13 encoding
- ROT13 is its own inverse - applying it twice returns the original text
- This introduces basic cryptography and character substitution

---

### Bandit Level 12 → Level 13

**Level Goal**: Password in the file **data.txt**, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work. Use mkdir with a hard to guess directory name. Or better, use the command “mktemp -d”. Then copy the datafile using cp, and rename it using mv (read the manpages!)

**Solution**:
```bash
❯ ssh bandit12@bandit.labs.overthewire.org -p 2220
....
bandit12@bandit:~$ ls
data.txt
bandit12@bandit:~$ mkdir -p /tmp/tempdir
bandit12@bandit:~$ cp data.txt /tmp/tempdir
bandit12@bandit:~$ cd /tmp/tempdir
bandit12@bandit:/tmp/tempdir$ ls
data.txt  file1
bandit12@bandit:/tmp/tempdir$ file file1 
file1: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/tempdir$ xxd -r data.txt > data
bandit12@bandit:/tmp/tempdir$ file data
data: gzip compressed data, was "data2.bin", last modified: Tue Oct 14 09:26:06 2025, max compression, from Unix, original size modulo 2^32 564
bandit12@bandit:/tmp/tempdir$ mv data data.gz
bandit12@bandit:/tmp/tempdir$ gzip -d data.gz
bandit12@bandit:/tmp/tempdir$ ls
data  data.txt  file1
bandit12@bandit:/tmp/tempdir$ file data
data: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/tempdir$ mv data data.bz2
bandit12@bandit:/tmp/tempdir$ bzip2 -d data.bz2
bandit12@bandit:/tmp/tempdir$ ls
data  data.txt  file1
bandit12@bandit:/tmp/tempdir$ file data
data: gzip compressed data, was "data4.bin", last modified: Tue Oct 14 09:26:06 2025, max compression, from Unix, original size modulo 2^32 20480
bandit12@bandit:/tmp/tempdir$ mv data data.gz
bandit12@bandit:/tmp/tempdir$ gzip -d data.gz
bandit12@bandit:/tmp/tempdir$ file data
data: POSIX tar archive (GNU)
bandit12@bandit:/tmp/tempdir$ mv data data.tar
bandit12@bandit:/tmp/tempdir$ tar xf data.tar
bandit12@bandit:/tmp/tempdir$ ls
data5.bin  data.tar  data.txt  file1
bandit12@bandit:/tmp/tempdir$ file data5.bin 
data5.bin: POSIX tar archive (GNU)
bandit12@bandit:/tmp/tempdir$ mv data5.bin data5.tar
bandit12@bandit:/tmp/tempdir$ tar xf data5.tar
bandit12@bandit:/tmp/tempdir$ ls
data5.tar  data6.bin  data.tar  data.txt  file1
bandit12@bandit:/tmp/tempdir$ file data6.bin 
data6.bin: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/tempdir$ mv data6.bin data6.bz2
bandit12@bandit:/tmp/tempdir$ bzip2 -d data6.bz2
bandit12@bandit:/tmp/tempdir$ ls
data5.tar  data6  data.tar  data.txt  file1
bandit12@bandit:/tmp/tempdir$ file data6
data6: POSIX tar archive (GNU)
bandit12@bandit:/tmp/tempdir$ mv data6 data6.tar
bandit12@bandit:/tmp/tempdir$ tar xf data6.tar
bandit12@bandit:/tmp/tempdir$ ls
data5.tar  data6.tar  data8.bin  data.tar  data.txt  file1
bandit12@bandit:/tmp/tempdir$ file data8.bin 
data8.bin: gzip compressed data, was "data9.bin", last modified: Tue Oct 14 09:26:06 2025, max compression, from Unix, original size modulo 2^32 49
bandit12@bandit:/tmp/tempdir$ mv data8.bin data8.gz
bandit12@bandit:/tmp/tempdir$ gzip -d data8.gz
bandit12@bandit:/tmp/tempdir$ ls
data5.tar  data6.tar  data8  data.tar  data.txt  file1
bandit12@bandit:/tmp/tempdir$ file data8
data8: ASCII text
bandit12@bandit:/tmp/tempdir$ cat data8 
The password is FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn
bandit12@bandit:/tmp/tempdir$ 
```
**Password**: `FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn`

**Writeup**:
- Create a temporary working directory in `/tmp` to avoid permission issues
- Copy the data.txt file to the temporary directory
- Use `xxd -r` to reverse the hexdump back to binary data
- Repeatedly use `file` command to identify the compression/archive type
- Use appropriate decompression commands based on file type:
  - `gzip -d` for .gz files
  - `bzip2 -d` for .bz2 files  
  - `tar xf` for tar archives
- Rename files with correct extensions when needed
- Continue decompressing layers until you reach the final ASCII text file
- The password is revealed in the final decompressed file

---

### Bandit Level 13 → Level 14

**Level Goal**: Password in **/etc/bandit_pass/bandit14 and can only be read by user bandit14**. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Look at the commands that logged you into previous bandit levels, and find out how to use the key for this level.

**Solution**:
```bash
❯ ssh bandit13@bandit.labs.overthewire.org -p 2220
....
bandit13@bandit:~$ ls
sshkey.private
bandit13@bandit:~$ file sshkey.private
sshkey.private: PEM RSA private key
bandit13@bandit:~$ cat sshkey.private
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxkkOE83W2cOT7IWhFc9aPaaQmQDdgzuXCv+ppZHa++buSkN+
[ALL THE PRIVATE KEY CONTENT]
-----END RSA PRIVATE KEY-----
bandit13@bandit:~$ exit
logout
Connection to bandit.labs.overthewire.org closed.
❯ scp -P 2220 bandit13@bandit.labs.overthewire.org:sshkey.private .
❯ chmod 600 sshkey.private
❯ ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
....
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
bandit14@bandit:~$ 
```
**Password**: `MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS`

**Writeup**:
- Log into bandit13 to retrieve the SSH private key
- Use `scp` to copy the private key (`sshkey.private`) to your local machine
- Set secure permissions on the private key with `chmod 600`
- Use the private key to SSH directly as bandit14 using the `-i` flag
- Once logged in as bandit14, read the password from `/etc/bandit_pass/bandit14`
- This demonstrates SSH key-based authentication, bypassing password authentication

---

### Bandit Level 14 → Level 15

**Level Goal**: Password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.

**Solution**:
```bash
❯ ssh bandit14@bandit.labs.overthewire.org -p 2220
....
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
bandit14@bandit:~$ echo "MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS" | nc localhost 30000
Correct!
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

bandit14@bandit:~$ cat /etc/bandit_pass/bandit14 | nc localhost 30000
Correct!
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

bandit14@bandit:~$ printf "MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS\n" | nc localhost 30000
Correct!
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

bandit14@bandit:~$ 
```
**Password**: `8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo`

**Writeup**:
- First, retrieve the current level's password from `/etc/bandit_pass/bandit14`
- Use `nc` (netcat) to connect to localhost on port 30000
- Send the current password through the connection
- The service on port 30000 will respond with "Correct!" and the next level's password
- This demonstrates client-server communication over network sockets
- The service validates the current password and returns the next one

---

### Bandit Level 15 → Level 16

**Level Goal**: The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL/TLS encryption.

**Solution**:
```bash
❯ ssh bandit15@bandit.labs.overthewire.org -p 2220
....
bandit15@bandit:~$ cat /etc/bandit_pass/bandit15
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
bandit15@bandit:~$ cat /etc/bandit_pass/bandit15 | openssl s_client -connect localhost:30001 -quiet
Can't use SSL_get_servername
depth=0 CN = SnakeOil
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = SnakeOil
verify return:1
Correct!
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

bandit15@bandit:~$ echo "8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo" | openssl s_client -connect localhost:30001 -quiet
Can't use SSL_get_servername
depth=0 CN = SnakeOil
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = SnakeOil
verify return:1
Correct!
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

bandit15@bandit:~$ echo "8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo" | ncat --ssl localhost 30001
Correct!
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

bandit15@bandit:~$ 
```
**Password**: `kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx`

**Writeup**:
- Retrieve the current level's password from `/etc/bandit_pass/bandit15`
- Use `openssl s_client` with the `-quiet` flag to establish an SSL/TLS connection to localhost:30001
- Pipe the current password directly to the SSL connection
- The service validates the password over the encrypted channel and returns the next level's password
- The `-quiet` flag suppresses certificate warnings and verbose output
- This demonstrates secure client-server communication using SSL/TLS encryption

---

### Bandit Level 16 → Level 17

**Level Goal**: The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL/TLS and which don't. There is only 1 server that will give the next credentials.

**Solution**:
```bash
❯ ssh bandit16@bandit.labs.overthewire.org -p 2220
....
bandit16@bandit:~$ cat /etc/bandit_pass/bandit16
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
bandit16@bandit:~$ nmap -p 31000-32000 localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-14 18:08 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00016s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE SERVICE
31046/tcp open  unknown
31518/tcp open  unknown
31691/tcp open  unknown
31790/tcp open  unknown
31960/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds
bandit16@bandit:~$ netstat -tulpn | grep 31
(No info could be read for "-p": geteuid()=11016 but you should be root.)
netstat: no support for `AF INET (tcp)' on this system.
tcp6       0      0 :::31960                :::*                    LISTEN      -                   
tcp6       0      0 :::31691                :::*                    LISTEN      -                   
tcp6       0      0 :::31046                :::*                    LISTEN      -                   
tcp6       0      0 :::2231                 :::*                    LISTEN      -                   
bandit16@bandit:~$ echo "kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx" | openssl s_client -connect localhost:31790 -quiet
Can't use SSL_get_servername
depth=0 CN = SnakeOil
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = SnakeOil
verify return:1
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

bandit16@bandit:~$
```
**Private Key**: (The RSA private key shown above)

**Writeup**:
1. **Port Discovery**: Use `nmap` to scan ports 31000-32000 and find open ports
2. **SSL Identification**: Test each open port with `openssl s_client` to identify which ones support SSL/TLS
3. **Service Testing**: The correct port (31790) will accept the current password and return an SSH private key
4. **Key Retrieval**: The service returns an RSA private key instead of a password for the next level
5. **Multiple Services**: Other ports may echo back input or behave differently - only one gives the credentials

---

### Bandit Level 17 → Level 18

**Level Goal**: There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new.

**Solution**:
```bash
❯ ssh -i id_rsa bandit17@bandit.labs.overthewire.org -p 2220
....
bandit17@bandit:~$ 
bandit17@bandit:~$ ls
passwords.new  passwords.old
bandit17@bandit:~$ diff passwords.old passwords.new
42c42
< pGozC8kOHLkBMOaL0ICPvLV1IjQ5F1VA
---
> x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
bandit17@bandit:~$ comm -3 <(sort passwords.old) <(sort passwords.new)
pGozC8kOHLkBMOaL0ICPvLV1IjQ5F1VA
	x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
bandit17@bandit:~$ grep -v -f passwords.old passwords.new
x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
bandit17@bandit:~$ awk 'NR==FNR{a[$0];next} !($0 in a)' passwords.old passwords.new
x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
bandit17@bandit:~$ 
```
**Password**: `x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO`

**Writeup**:
- Two files are present: `passwords.old` and `passwords.new`
- Use `diff` to compare the files and identify the changed line
- The output shows line 42 was changed from the old password to the new password
- The changed line in `passwords.new` contains the password for Level 18
- Multiple file comparison tools can be used to find the difference

---

### Bandit Level 18 → Level 19

**Level Goal**: The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.

**Solution**:
```bash
❯ ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
bandit18@bandit.labs.overthewire.org's password: 
cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
❯ ssh bandit18@bandit.labs.overthewire.org -p 2220 "/bin/sh -c 'cat readme'"
bandit18@bandit.labs.overthewire.org's password: 
cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
❯ scp -P 2220 bandit18@bandit.labs.overthewire.org:readme .
❯ cat readme
cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
```
**Password**: `cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8`

**Writeup**:
- The .bashrc file has been modified to log users out immediately upon interactive login
- Bypass the problematic .bashrc by executing commands directly via SSH without starting an interactive shell
- Use SSH command execution: `ssh user@host "command"`
- Read the readme file directly without invoking the interactive bash session
- The password is contained in the readme file in the home directory

---

### Bandit Level 19 → Level 20

**Level Goal**: To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

**Solution**:
```bash
❯ ssh bandit19@bandit.labs.overthewire.org -p 2220
....
bandit19@bandit:~$ ls
bandit20-do
bandit19@bandit:~$ file bandit20-do 
bandit20-do: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=38f1351d0068ccbbace0e437f34859de85e63025, for GNU/Linux 3.2.0, not stripped
bandit19@bandit:~$ ./bandit20-do
Run a command as another user.
  Example: ./bandit20-do whoami
bandit19@bandit:~$ 
bandit19@bandit:~$ ./bandit20-do id
uid=11019(bandit19) gid=11019(bandit19) euid=11020(bandit20) groups=11019(bandit19)
bandit19@bandit:~$ ./bandit20-do whoami
bandit20
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
```
**Password**: `0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO`

**Writeup**:
- A setuid binary called `bandit20-do` is located in the home directory
- Setuid binaries run with the privileges of the file owner (bandit20) rather than the current user
- Execute the binary without arguments to see usage instructions
- Use `./bandit20-do id` to confirm it runs with bandit20's effective user ID (euid)
- Use the binary to run `cat /etc/bandit_pass/bandit20` as bandit20 to read the password
- This demonstrates privilege escalation through setuid binaries
- The binary allows executing any command with bandit20's privileges

---

### Bandit Level 20 → Level 21

**Level Goal**: There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

**Solution**:
```bash
❯ ssh bandit20@bandit.labs.overthewire.org -p 2220
....
bandit20@bandit:~$ ls
suconnect
bandit20@bandit:~$ file suconnect
suconnect: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=a95f034b2749e585fbeed4f260f85a4b150934c2, for GNU/Linux 3.2.0, not stripped
bandit20@bandit:~$ ./suconnect
Usage: ./suconnect <portnumber>
This program will connect to the given port on localhost using TCP. If it receives the correct password from the other side, the next password is transmitted back.

# Terminal 1: Set up netcat listener on port 4449 with current password
bandit20@bandit:~$ nc -lp 4449 < /etc/bandit_pass/bandit20
EeoULMCra2q0dSkYj561DX7s1CpBuOBt
bandit20@bandit:~$

# Terminal 2: Connect to the listener using suconnect
bandit20@bandit:~$ ./suconnect 4449
Read: 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
Password matches, sending next password
bandit20@bandit:~$ 
```
**Password**: `EeoULMCra2q0dSkYj561DX7s1CpBuOBt`

**Writeup**:
- A setuid binary `suconnect` acts as a network client that requires coordination
- The binary connects to a specified port on localhost and reads a line of text
- If the text matches bandit20's password, it sends back bandit21's password
- Set up a netcat listener on an arbitrary port (e.g., 4449) that serves the current password
- Run `./suconnect` with the same port number to connect to the listener
- The binary validates the password over the network connection and returns the next level's password
- This demonstrates client-server communication and process coordination

---

### Bandit Level 21 → Level 22

**Level Goal**: A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

**Solution**:
```bash
❯ ssh bandit21@bandit.labs.overthewire.org -p 2220
....
bandit21@bandit:~$ ls -la /etc/cron.d/
total 60
drwxr-xr-x   2 root root  4096 Oct 14 09:29 .
drwxr-xr-x 128 root root 12288 Oct 20 16:35 ..
-r--r-----   1 root root    47 Oct 14 09:26 behemoth4_cleanup
-rw-r--r--   1 root root   123 Oct 14 09:19 clean_tmp
-rw-r--r--   1 root root   120 Oct 14 09:26 cronjob_bandit22
-rw-r--r--   1 root root   122 Oct 14 09:26 cronjob_bandit23
-rw-r--r--   1 root root   120 Oct 14 09:26 cronjob_bandit24
-rw-r--r--   1 root root   201 Apr  8  2024 e2scrub_all
-r--r-----   1 root root    48 Oct 14 09:27 leviathan5_cleanup
-rw-------   1 root root   138 Oct 14 09:28 manpage3_resetpw_job
-rwx------   1 root root    52 Oct 14 09:29 otw-tmp-dir
-rw-r--r--   1 root root   102 Mar 31  2024 .placeholder
-rw-r--r--   1 root root   396 Jan  9  2024 sysstat
bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q
bandit21@bandit:~$ 
```
**Password**: `tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q`

**Writeup**:
- Check the `/etc/cron.d/` directory for cron job configurations
- Find `cronjob_bandit22` which runs a script as user bandit22 every minute and at reboot
- Examine the script `/usr/bin/cronjob_bandit22.sh` to understand what it does
- The script changes permissions on a temporary file to make it world-readable
- It then writes bandit22's password to this temporary file
- Read the temporary file `/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv` to get the password for level 22
- This introduces cron job analysis and privilege escalation through scheduled tasks

---

### Bandit Level 22 → Level 23

**Level Goal**: A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

**Solution**:
```bash
❯ ssh bandit22@bandit.labs.overthewire.org -p 2220
....
bandit22@bandit:~$ ls -la /etc/cron.d/
total 60
drwxr-xr-x   2 root root  4096 Oct 14 09:29 .
drwxr-xr-x 128 root root 12288 Oct 20 16:35 ..
-r--r-----   1 root root    47 Oct 14 09:26 behemoth4_cleanup
-rw-r--r--   1 root root   123 Oct 14 09:19 clean_tmp
-rw-r--r--   1 root root   120 Oct 14 09:26 cronjob_bandit22
-rw-r--r--   1 root root   122 Oct 14 09:26 cronjob_bandit23
-rw-r--r--   1 root root   120 Oct 14 09:26 cronjob_bandit24
-rw-r--r--   1 root root   201 Apr  8  2024 e2scrub_all
-r--r-----   1 root root    48 Oct 14 09:27 leviathan5_cleanup
-rw-------   1 root root   138 Oct 14 09:28 manpage3_resetpw_job
-rwx------   1 root root    52 Oct 14 09:29 otw-tmp-dir
-rw-r--r--   1 root root   102 Mar 31  2024 .placeholder
-rw-r--r--   1 root root   396 Jan  9  2024 sysstat
bandit22@bandit:~$ cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
bandit22@bandit:~$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
0Zf11ioIjMVN551jX3CmStKLYqjk54Ga
bandit22@bandit:~$ 
```
**Password**: `0Zf11ioIjMVN551jX3CmStKLYqjk54Ga`

**Writeup**:
- Check the `/etc/cron.d/` directory and find `cronjob_bandit23`
- The cron job runs `/usr/bin/cronjob_bandit23.sh` as user bandit23 every minute
- Examine the script to understand its logic:
  - It gets the current username with `whoami` (which will be "bandit23" when run by cron)
  - It creates an MD5 hash of the string "I am user bandit23"
  - It copies bandit23's password to a file in `/tmp/` with the MD5 hash as the filename
- Calculate what the filename would be when the script runs as bandit23
- The MD5 hash of "I am user bandit23" is `8ca319486bfbbc3663ea0fbe81326349`
- Read the file `/tmp/8ca319486bfbbc3663ea0fbe81326349` to get bandit23's password

---

### Bandit Level 23 → Level 24

**Level Goal**: A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

**Solution**:
```bash
❯ ssh bandit23@bandit.labs.overthewire.org -p 2220
....
bandit23@bandit:~$ ls -la /etc/cron.d/
total 60
drwxr-xr-x   2 root root  4096 Oct 14 09:29 .
drwxr-xr-x 128 root root 12288 Oct 20 16:35 ..
-r--r-----   1 root root    47 Oct 14 09:26 behemoth4_cleanup
-rw-r--r--   1 root root   123 Oct 14 09:19 clean_tmp
-rw-r--r--   1 root root   120 Oct 14 09:26 cronjob_bandit22
-rw-r--r--   1 root root   122 Oct 14 09:26 cronjob_bandit23
-rw-r--r--   1 root root   120 Oct 14 09:26 cronjob_bandit24
-rw-r--r--   1 root root   201 Apr  8  2024 e2scrub_all
-r--r-----   1 root root    48 Oct 14 09:27 leviathan5_cleanup
-rw-------   1 root root   138 Oct 14 09:28 manpage3_resetpw_job
-rwx------   1 root root    52 Oct 14 09:29 otw-tmp-dir
-rw-r--r--   1 root root   102 Mar 31  2024 .placeholder
-rw-r--r--   1 root root   396 Jan  9  2024 sysstat
bandit23@bandit:~$ cat /etc/cron.d/cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
bandit23@bandit:~$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done

bandit23@bandit:~$ openssl rand -hex 6
d3149fac0d3b
bandit23@bandit:~$ mkdir /tmp/d3149fac0d3b
bandit23@bandit:~$ cd /tmp/d3149fac0d3b
bandit23@bandit:/tmp/d3149fac0d3b$ cat << 'EOF' > getpass.sh
#!/bin/bash
cat /etc/bandit_pass/bandit24 >> /tmp/d3149fac0d3b/bandit24pass
EOF
bandit23@bandit:/tmp/d3149fac0d3b$ chmod 777 getpass.sh
bandit23@bandit:/tmp/d3149fac0d3b$ cp getpass.sh /var/spool/bandit24/foo/
bandit23@bandit:/tmp/d3149fac0d3b$ chmod 777 /tmp/d3149fac0d3b
bandit23@bandit:/tmp/d3149fac0d3b$ sleep 60
bandit23@bandit:/tmp/d3149fac0d3b$ ls
bandit24pass  getpass.sh
bandit23@bandit:/tmp/d3149fac0d3b$ cat bandit24pass 
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8
bandit23@bandit:/tmp/d3149fac0d3b$ 
```
**Password**: `gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8`

**Writeup**:
- Check `/etc/cron.d/cronjob_bandit24` to find it runs a script every minute as bandit24
- The script `/usr/bin/cronjob_bandit24.sh` executes all scripts in `/var/spool/bandit24/foo/` that are owned by bandit23
- Create a script that reads bandit24's password and writes it to an accessible location
- Copy the script to `/var/spool/bandit24/foo/` and make it executable
- Wait for the cron job to execute the script (runs every minute)
- The script runs with bandit24's privileges and copies the password
- Read the password from the output file

---

### Bandit Level 24 → Level 25

**Level Goal**: A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

**Solution**:
```bash
❯ ssh bandit24@bandit.labs.overthewire.org -p 2220
....
bandit24@bandit:~$ cat /etc/bandit_pass/bandit24
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8
bandit24@bandit:~$ echo "gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 1234" | nc localhost 30002
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Wrong! Please enter the correct current password and pincode. Try again.
^C
bandit24@bandit:~$ openssl rand -hex 6
3a767bb9ffbc
bandit24@bandit:~$ mkdir /tmp/3a767bb9ffbc
bandit24@bandit:~$ cd /tmp/3a767bb9ffbc
bandit24@bandit:/tmp/3a767bb9ffbc$ cat << 'EOF' > brute.sh
#!/bin/bash

pass24="gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8"

for pin in {0000..9999}; do
    echo "$pass24 $pin"
done | nc localhost 30002 | grep -v "Wrong"
EOF
bandit24@bandit:/tmp/3a767bb9ffbc$ chmod +x brute.sh 
bandit24@bandit:/tmp/3a767bb9ffbc$ ./brute.sh 
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Correct!
The password of user bandit25 is iCi86ttT4KSNe1armKiwbQNmB3YJP3q4

bandit24@bandit:/tmp/3a767bb9ffbc$ 
bandit24@bandit:/tmp/3a767bb9ffbc$ for i in {0000..9999}; do echo "gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i"; done | nc localhost 30002 | grep -v "Wrong"
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Correct!
The password of user bandit25 is iCi86ttT4KSNe1armKiwbQNmB3YJP3q4

bandit24@bandit:/tmp/3a767bb9ffbc$ 
```
**Password**: `iCi86ttT4KSNe1armKiwbQNmB3YJP3q4`

**Writeup**:
- Retrieve the current level's password from `/etc/bandit_pass/bandit24`
- The service on port 30002 requires both bandit24's password and a secret 4-digit pincode
- Create a brute force script that generates all 10,000 possible pincodes (0000-9999)
- Pipe all combinations through a single `nc` connection to the service
- Use `grep -v "Wrong"` to filter out failed attempts and display only the successful response
- The service returns bandit25's password when the correct pincode is found
- This demonstrates a basic brute force attack against weak authentication

---

### Bandit Level 25 → Level 26

**Level Goal**: Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.

**Solution**:
```bash
❯ ssh bandit25@bandit.labs.overthewire.org -p 2220
....
bandit25@bandit:~$ ls
bandit26.sshkey
bandit25@bandit:~$ cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit25@bandit:~$ ls -la /usr/bin/showtext
-rwxr-xr-x 1 root root 58 Oct 14 09:26 /usr/bin/showtext
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

exec more ~/text.txt
exit 0
bandit25@bandit:~$ 
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost -p 2220
Connection to localhost closed.

# The trick: resize your terminal window to be very small
# Then SSH will trigger the 'more' command which allows escape
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost -p 2220
  _                     _ _ _   ___   __  
 | |                   | (_) | |__ \ / /  
 | |__   __ _ _ __   __| |_| |_   ) / /_  
 | '_ \ / _` | '_ \ / _` | | __| / / '_ \ 
 | |_) | (_| | | | | (_| | | |_ / /| (_) |
 |_.__/ \__,_|_| |_|\__,_|_|\__|____\___/ 
Connection to localhost closed.

# Make terminal very small (less than 5 lines), then SSH again
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost -p 2220

# Now you're in 'more' - press 'v' to enter vi editor
# In vi, type:
:set shell=/bin/bash
:shell
bandit26@bandit:~$ whoami
bandit26
bandit26@bandit:~$ cat /etc/bandit_pass/bandit26
s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ
```
**Password**: `s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ`

**Writeup**:
- First, check what shell bandit26 uses in `/etc/passwd`
- Discover bandit26 uses `/usr/bin/showtext` as shell instead of `/bin/bash`
- Examine `/usr/bin/showtext` - it uses `more` to display a text file then exits
- The trick: when terminal is small, `more` doesn't exit immediately and shows pagination
- Resize your terminal window to be very small (less than 5 lines height)
- SSH into bandit26 - now `more` will pause and show the pagination prompt
- Press 'v' to enter vi editor from within `more`
- In vi, set shell to bash and spawn a shell, or use vi commands to read the password file
- This gives you a proper shell as bandit26 to read the password

---

### Bandit Level 26 → Level 27

**Level Goal**: Good job getting a shell! Now hurry and grab the password for bandit27!

**Solution**:
```bash
bandit26@bandit:~$ ls -la
total 36
drwxr-xr-x  3 root     root     4096 Oct 14 09:26 .
drwxr-xr-x 41 root     root     4096 Oct 14 09:29 ..
-rwsr-x---  1 bandit27 bandit26 7296 Oct 14 09:26 bandit27-do
-rw-r--r--  1 root     root      220 Mar 31  2024 .bash_logout
-rw-r--r--  1 root     root     3526 Oct 14 09:19 .bashrc
-rw-r--r--  1 root     root      675 Mar 31  2024 .profile
drwxr-xr-x  2 root     root     4096 Oct 14 09:26 .ssh
-rw-r-----  1 bandit26 bandit26  258 Oct 14 09:26 text.txt

bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB
```
**Password**: `upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB`

**Writeup**:
- After escaping the restricted shell in the previous level, you now have access as bandit26
- There's a setuid binary called `bandit27-do` in the home directory
- Setuid binaries run with the privileges of the file owner (bandit27)
- Use the binary to execute commands as bandit27, specifically to read `/etc/bandit_pass/bandit27`
- The binary allows any command to be run with bandit27's privileges
- This demonstrates privilege escalation through setuid binaries

---

### Bandit Level 27 → Level 28

**Level Goal**: There is a git repository at `ssh://bandit27-git@bandit.labs.overthewire.org/home/bandit27-git/repo` via port 2220. The password for user bandit27-git is the same as for user bandit27. Clone the repository and find the password for the next level.

**Solution**:
```bash
❯ ssh bandit27@bandit.labs.overthewire.org -p 2220
....
bandit27@bandit:~$ mkdir /tmp/7aa04696d2aa
bandit27@bandit:~$ cd /tmp/7aa04696d2aa
bandit27@bandit:/tmp/7aa04696d2aa$ git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo
Cloning into 'repo'...
The authenticity of host '[bandit.labs.overthewire.org]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit27/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit27/.ssh/known_hosts).
bandit27-git@bandit.labs.overthewire.org's password: 
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (3/3), done.
bandit27@bandit:/tmp/7aa04696d2aa$ cd repo
bandit27@bandit:/tmp/7aa04696d2aarepo$ ls
README
bandit27@bandit:/tmp/7aa04696d2aa/repo$ cat README
The password to the next level is: Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN
bandit27@bandit:/tmp/7aa04696d2aa/repo$ 
```
**Password**: `Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN`

**Writeup**:
- First, create a temporary directory in `/tmp` to work in since the home directory may have restrictions
- Use `git clone` to clone the repository from the given SSH URL
- When prompted for password, use the same password as bandit27: `upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB`
- Navigate into the cloned repository directory
- List the contents to find a README file
- Read the README file which contains the password for the next level
- The password is revealed as plain text in the repository
- This introduces basic Git usage and shows how sensitive information can be exposed in version control systems

---

### Bandit Level 28 → Level 29

**Level Goal**: There is a git repository at `ssh://bandit28-git@bandit.labs.overthewire.org/home/bandit28-git/repo` via port 2220. The password for user bandit28-git is the same as for user bandit28. Clone the repository and find the password for the next level.

**Solution**:
```bash
❯ ssh bandit28@bandit.labs.overthewire.org -p 2220
....
bandit28@bandit:~$ mkdir /tmp/2a78d3ea2a11
bandit28@bandit:~$ cd /tmp/2a78d3ea2a11
bandit28@bandit:/tmp/2a78d3ea2a11$ git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo
Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit28/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit28/.ssh/known_hosts).
bandit28-git@localhost's password: 
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (2/2), done.
bandit28@bandit:/tmp/2a78d3ea2a11$ cd repo
bandit28@bandit:/tmp/2a78d3ea2a11/repo$ ls
README.md
bandit28@bandit:/tmp/2a78d3ea2a11/repo$ cat README.md
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx

bandit28@bandit:/tmp/2a78d3ea2a11/repo$ git log
commit 817e303aa6c2b207ea043c7bba1bb7575dc4ea73 (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    fix info leak

commit 3621de89d8eac9d3b64302bfb2dc67e9a566decd
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    add missing data

commit 0622b73250502618babac3d174724bb303c32182
Author: Ben Dover <noone@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    initial commit of README.md

bandit28@bandit:/tmp/2a78d3ea2a11/repo$ git show 3621de89d8eac9d3b64302bfb2dc67e9a566decd
commit 3621de89d8eac9d3b64302bfb2dc67e9a566decd
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    add missing data

diff --git a/README.md b/README.md
index d4e3b74..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials
 
 - username: bandit29
-- password: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7
+- password: xxxxxxxxxx

bandit28@bandit:/tmp/2a78d3ea2a11/repo$ git checkout 3621de89d8eac9d3b64302bfb2dc67e9a566decd
Note: switching to '3621de89d8eac9d3b64302bfb2dc67e9a566decd'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

HEAD is now at 3621de8 add missing data
bandit28@bandit:/tmp/2a78d3ea2a11/repo$ cat README.md
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7

bandit28@bandit:/tmp/2a78d3ea2a11/repo$ 
```

**Password**: `4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7`

**Writeup**:
- Clone the Git repository using the same method as previous levels
- The current README.md file shows the password as "xxxxxxxxxx" (redacted)
- Use `git log` to view the commit history and identify previous commits
- Notice there are three commits: "initial commit", "add missing data", and "fix info leak"
- The "add missing data" commit likely contains the actual password before it was removed
- Use `git show` on commit `3621de89d8eac9d3b64302bfb2dc67e9a566decd` to examine the changes
- The diff reveals that the password `4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7` was removed in the "fix info leak" commit
- Checkout the commit with the password or simply read it from the git show output
- The password is revealed in the commit diff showing what was changed
- This demonstrates how sensitive information can be exposed in Git history even if removed in later commits

---

### Bandit Level 29 → Level 30

**Level Goal**: There is a git repository at `ssh://bandit29-git@bandit.labs.overthewire.org/home/bandit29-git/repo` via port 2220. The password for user bandit29-git is the same as for user bandit29. Clone the repository and find the password for the next level.

**Solution**:
```bash
❯ ssh bandit29@bandit.labs.overthewire.org -p 2220
....
bandit29@bandit:~$ mkdir /tmp/2858b72456ec
bandit29@bandit:~$ cd /tmp/2858b72456ec
bandit29@bandit:/tmp/2858b72456ec$ git clone ssh://bandit29-git@localhost:2220/home/bandit29-git/repo
Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit29/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit29/.ssh/known_hosts).
bandit29-git@localhost's password: 
remote: Enumerating objects: 16, done.
remote: Counting objects: 100% (16/16), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 16 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (16/16), done.
Resolving deltas: 100% (2/2), done.
bandit29@bandit:/tmp/2858b72456ec$ cd repo
bandit29@bandit:/tmp/2858b72456ec/repo$ ls
README.md
bandit29@bandit:/tmp/2858b72456ec/repo$ cat README.md
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>

bandit29@bandit:/tmp/2858b72456ec/repo$ git branch -a
* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev
bandit29@bandit:/tmp/2858b72456ec/repo$ git checkout dev
Branch 'dev' set up to track remote branch 'dev' from 'origin'.
Switched to a new branch 'dev'
bandit29@bandit:/tmp/2858b72456ec/repo$ cat README.md
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: qp30ex3VLz5MDG1n91YowTv4Q8l7CDZ

bandit29@bandit:/tmp/2858b72456ec/repo$ git log --oneline
5c4d6d0 (HEAD -> dev, origin/dev) add data needed for development
f08c0e5 (origin/master, origin/HEAD, master) fix username
d56bcd0 initial commit of README.md
bandit29@bandit:/tmp/2858b72456ec/repo$ 
```
**Password**: `qp30ex3VLz5MDG1n91YowTv4Q8l7CDZ`

**Writeup**:
- Clone the Git repository using the standard method
- The README.md file in the master branch shows "no passwords in production!" indicating the password might be in a different branch
- Use `git branch -a` to list all available branches (local and remote)
- Notice there's a `dev` branch in addition to the master branch
- Switch to the `dev` branch using `git checkout dev`
- Read the README.md file in the dev branch, which contains the actual password for the next level
- The password `qp30ex3VLz5MDG1n91YowTv4Q8l7CDZ` is revealed in the development branch
- This demonstrates how sensitive information might be stored in different branches rather than in the commit history
- Development branches often contain credentials that shouldn't be in production code

---

### Bandit Level 30 → Level 31

**Level Goal**: There is a git repository at `ssh://bandit30-git@bandit.labs.overthewire.org/home/bandit30-git/repo` via port 2220. The password for user bandit30-git is the same as for user bandit30. Clone the repository and find the password for the next level.

**Solution**:
```bash
❯ ssh bandit30@bandit.labs.overthewire.org -p 2220
....
bandit30@bandit:~$ mkdir /tmp/971449d49d56
bandit30@bandit:~$ cd /tmp/971449d49d56
bandit30@bandit:/tmp/971449d49d56$ git clone ssh://bandit30-git@localhost:2220/home/bandit30-git/repo
Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit30/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit30/.ssh/known_hosts).
bandit30-git@localhost's password: 
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 18 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (18/18), done.
Resolving deltas: 100% (2/2), done.
bandit30@bandit:/tmp/971449d49d56$ cd repo
bandit30@bandit:/tmp/971449d49d56/repo$ ls
README.md
bandit30@bandit:/tmp/971449d49d56/repo$ cat README.md
just an epmty file... muahaha
bandit30@bandit:/tmp/971449d49d56/repo$ git log
commit acfc3c67816fc778c4aeb5893299451ca6d65a78 (HEAD -> master, origin/master, origin/HEAD)
Author: Ben Dover <noone@overthewire.org>
Date:   Thu Sep 19 07:08:44 2024 +0000

    initial commit of README.md
bandit30@bandit:/tmp/971449d49d56/repo$ git branch -a
* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/master
bandit30@bandit:/tmp/971449d49d56/repo$ git tag
secret
bandit30@bandit:/tmp/971449d49d56/repo$ git show secret
fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy
bandit30@bandit:/tmp/971449d49d56/repo$ 
```
**Password**: `fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy`

**Writeup**:
- Clone the Git repository using the standard method
- The README.md file contains "just an epmty file... muahaha" indicating the password is hidden elsewhere
- Check the commit history with `git log` - only one commit exists
- List all branches with `git branch -a` - only the master branch exists
- Check for Git tags using `git tag` - reveals a tag named "secret"
- Use `git show secret` to display the contents of the tag
- The tag directly contains the password `fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy` without any file context
- This demonstrates how sensitive information can be stored in Git tags, which are often overlooked during security audits
- Tags are typically used for version markers but can contain arbitrary data

---

### Bandit Level 31 → Level 32

**Level Goal**: There is a git repository at `ssh://bandit31-git@bandit.labs.overthewire.org/home/bandit31-git/repo` via port 2220. The password for user bandit31-git is the same as for user bandit31. Clone the repository and find the password for the next level.

**Solution**:
```bash
❯ ssh bandit31@bandit.labs.overthewire.org -p 2220
....
bandit31@bandit:~$ mkdir /tmp/3c353615ddb0
bandit31@bandit:~$ cd /tmp/3c353615ddb0
bandit31@bandit:/tmp/3c353615ddb0$ git clone ssh://bandit31-git@localhost:2220/home/bandit31-git/repo
Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit31/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
bandit31-git@localhost's password: 
remote: Enumerating objects: 4, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 4 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (4/4), done.
bandit31@bandit:/tmp/3c353615ddb0$ cd repo
bandit31@bandit:/tmp/3c353615ddb0/repo$ ls
README.md
bandit31@bandit:/tmp/3c353615ddb0/repo$ cat README.md
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master

bandit31@bandit:/tmp/3c353615ddb0/repo$ ls -la
total 20
drwxr-sr-x 3 bandit31 root 4096 Nov 21 12:34 .
drwxr-sr-x 3 bandit31 root 4096 Nov 21 12:34 ..
drwxr-sr-x 8 bandit31 root 4096 Nov 21 12:34 .git
-rw-r--r-- 1 bandit31 root  147 Nov 21 12:34 README.md
bandit31@bandit:/tmp/3c353615ddb0/repo$ cat .gitignore
*.txt
bandit31@bandit:/tmp/3c353615ddb0/repo$ echo 'May I come in?' > key.txt
bandit31@bandit:/tmp/3c353615ddb0/repo$ git add key.txt -f
bandit31@bandit:/tmp/3c353615ddb0/repo$ git commit -m "Add key.txt"
[master 6a5d9f0] Add key.txt
 1 file changed, 1 insertion(+)
 create mode 100644 key.txt
bandit31@bandit:/tmp/3c353615ddb0/repo$ git push
Could not create directory '/home/bandit31/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
bandit31-git@localhost's password: 
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 2 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 315 bytes | 315.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0)
remote: ### Attempting to validate files... ####
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: Well done! Here is the password for the next level:
remote: 3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
To localhost:2220:/home/bandit31-git/repo
   3c32276..6a5d9f0  master -> master
bandit31@bandit:/tmp/3c353615ddb0/repo$ 
```
**Password**: `3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K`

**Writeup**:
- Clone the Git repository using the standard method
- Read the README.md file which provides specific instructions: create a file named `key.txt` with content 'May I come in?' and push it to the master branch
- Check for a `.gitignore` file which shows `*.txt` - meaning all .txt files are ignored by Git by default
- Create the `key.txt` file with the required content using `echo 'May I come in?' > key.txt`
- Use `git add key.txt -f` (the `-f` or `--force` flag is required to add files that are ignored by .gitignore)
- Commit the file with a descriptive message
- Push the commit to the remote repository using `git push`
- The remote repository validates the pushed file and returns the password for the next level in the push response
- This demonstrates how to work with Git's ignore functionality and how to force-add files that would normally be excluded

---

### Bandit Level 32 → Level 33

**Level Goal**: After all this git stuff, it's time for another escape. Good luck!

**Solution**:
```bash
❯ ssh bandit32@bandit.labs.overthewire.org -p 2220
....
WELCOME TO THE UPPERCASE SHELL
>> whoami
sh: 1: WHOAMI: Permission denied
>> ls
sh: 1: LS: Permission denied
>> id
sh: 1: ID: Permission denied
>> $0
$ whoami
bandit33
$ id
uid=11033(bandit33) gid=11032(bandit32) groups=11032(bandit32)
$ cat /etc/bandit_pass/bandit33
tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0
$
```
**Password**: `tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0`

**Writeup**:
- Upon logging into bandit32, you're immediately placed into an "UPPERCASE SHELL" that converts all commands to uppercase
- Regular commands like `whoami`, `ls`, `id` fail because they become `WHOAMI`, `LS`, `ID` which either don't exist or you lack permission to execute
- The trick is to use `$0` which expands to the name of the current shell or script
- When `$0` is executed, it spawns a new shell without the uppercase conversion
- In the new shell, commands work normally in lowercase
- Use `whoami` and `id` to confirm you're now bandit33
- Read the password from `/etc/bandit_pass/bandit33`
- This demonstrates shell escaping techniques and environment variable manipulation
- The `$0` variable refers to the current shell's name, and executing it spawns a new instance that bypasses the uppercase restriction

---

### Bandit Level 33 → Level 34

**Level Goal**: At this moment, level 34 does not exist yet.

**Solution**:
```bash
❯ ssh bandit33@bandit.labs.overthewire.org -p 2220
....
bandit33@bandit:~$ ls
README.txt
bandit33@bandit:~$ cat README.txt
Congratulations on solving the last level of this game!

At this moment, there are no more levels to play in this game. However, we are constantly working
on new levels and will most likely expand this game with more levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.

If you have an idea for an awesome new level, please let us know!
```

**Writeup**:
- Log into bandit33 using the password obtained from the previous level
- There is only a README.txt file in the home directory
- Reading the README.txt reveals that this is currently the final level of the Bandit wargame
- The message congratulates you on completing all available levels
- It mentions that new levels may be added in the future
- Players are encouraged to try other OverTheWire wargames or suggest new level ideas

**Congratulations!** You have completed the Bandit wargame! 🎉

*The console falls silent, but the hunt continues. Your next target awaits at [HackTheBox](https://referral.hackthebox.com/mzBAiBw)...*
