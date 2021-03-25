# Simple AES File Encryption in Go

This program is used to encrypt and decrypt files with a key using AES symmetric encryption. To use this program download the correct build for your operating system from the Github page.

# Important Notes

- All files paths are relative to the program file.

- Encrypting or decrypting a directory of files will not create new files, instead it will override the previous file.

* Encrypting or decrypting a directory of files will only encrypt files in the directory that you specify, this will not encrypt any files in subdirectories.

# Examples

## Encrypt a single file.

Encrypt a singular file with a key. Replace "myfile.jpeg" with the path to the file that you wish to encrypt and replace "myKey" with your encryption key.

```
build.exe -e -i myfile.jpeg -key myKey
```

## Decrypt a single file

Decrypt a singular file with a key. Replace "myfile.jpeg" with the path to the file that you wish to encrypt and replace "myKey" with your encryption key.

```
build.exe -d -i myfile.jpeg -key myKey
```

## Encrypt a directory of files

Encrypt all files in a given directory. Replace "mydir/" with the directory that your want to encrypt and replace "myKey" with your encryption key.

```
build.exe -e -dir -i mydir/ -key myKey
```

## Decrypt a directory of files

Decrypt all files in a given directory. Replace "mydir/" with the directory that your want to decrypt and replace "myKey" with your encryption key.

```
build.exe -d -dir -i mydir/ -key myKey
```
