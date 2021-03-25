package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"encoding/hex"
	"flag"
	"path/filepath"
	"strings"
)


type EncryptOptions struct {
	Filename string // file to encrypt 
	Key []byte // encryption key
	SameFile bool // encryption to same file?
	NewFilename string // filename for new file if creating new file
}

type DecryptOptions struct {
	Filename string /* file to decrypt */
	Key []byte /* decryption key */
	SameFile bool /* decrypt to same file ?*/
	NewFilename string // filename for new file if creating new file
}
// encrypt []byte with a key
func encryptBytes(text []byte, key []byte) ([]byte, error) {
	
	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		return []byte(""), err
	}



	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte(""), err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte(""), err
	}

	encrypted := gcm.Seal(nonce, nonce, text, nil)

	return []byte(encrypted), nil
}
// decrypt []byte with a key
func decryptBytes(encryptedText []byte, key []byte) ([]byte, error) {
	// key
	c, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte(""), err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedText) < nonceSize {
		return []byte(""), err
	}

	nonce, encryptedText := encryptedText[:nonceSize], encryptedText[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedText, nil)
	if err != nil {
		return []byte(""), err
	} 
	return []byte(plaintext), nil
}


// encrypt any given file with a key
func encryptFile(params EncryptOptions) error {
	filename := params.Filename
	key := params.Key

	text, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	encryptedData, err := encryptBytes(text, key)
	if err != nil {
		return err
	}

	
	if params.SameFile == true {
		err = ioutil.WriteFile(filename, encryptedData, 0644)
		return err
	} else {
		err = ioutil.WriteFile(params.NewFilename, encryptedData, 0644)
		return err
	}
}

// decrypt file with a key
func decryptFile(params DecryptOptions) error {
	filename := params.Filename
	key := params.Key

	// get encrypted bytes
	encrypted, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	decrypted, err := decryptBytes(encrypted, key)
	if err != nil {
		return err
	}
	// write decryptedData
	if params.SameFile == true {
		err = ioutil.WriteFile(filename, decrypted, 0644)
		return err
	} else {
		err = ioutil.WriteFile(params.NewFilename, decrypted, 0644)
		return err
	}
}

type DirOptions struct {
	Directory string
	Key []byte
}

func deDirectory(params DirOptions, encrypt1 bool) error {
	dirToEncrypt := params.Directory
	key := params.Key

	// iterate files calling encryptFile function
	files, err := ioutil.ReadDir(dirToEncrypt)
	if err != nil {
		return err
	}
	for i, file := range files {
		fmt.Println("File:", i, "/", len(files))
		filepath := strings.Replace(filepath.Join(dirToEncrypt, file.Name()), "\\", "/", 900)
		if encrypt1 == false {
			err = decryptFile(DecryptOptions{
				Filename: filepath,
				Key: key,
				SameFile: true,
			})
		} else {
			err = encryptFile(EncryptOptions{
				Filename: filepath,
				Key: key,
				SameFile: true,
			})
		}
	}

	return nil
}

func encryptDirectory(params DirOptions) error {
	e := deDirectory(params, true) // true for encryption
	return e
}

func decryptDirectory(params DirOptions) error {
	e := deDirectory(params, false) // false for decryption
	return e
}



// returns md5 hash in bytes
// using an md5 hash allows users to use passwords which aren't 32 bytes
func hashMd5(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return []byte(hex.EncodeToString(hash.Sum(nil)))
}

func main() {
	var key []byte
	var err error
	// handle flags
	encrypt := flag.Bool("e", false, "")
	decrypt := flag.Bool("d", false, "")
	aesKey := flag.String("key", "", "aes key")
	input := flag.String("i", "", "input file")
	outputFile := flag.String("o", "", "outputfile")
	// directory options
	cryptDir := flag.Bool("dir", false, "")


	flag.Parse()
	// if user specifies no flags then the program will print some basic documentation
	if *encrypt == false && *decrypt == false && *aesKey == "" && *input == "" && *outputFile == "" {
		fmt.Println("-e", "encrypt")
		fmt.Println("-d", "decrypt")
		fmt.Println("-dir", "tells to encrypt or decrypt a directory instead of a file")
		fmt.Println("-i", "input file or directory")
		fmt.Println("-o", "output file")
		fmt.Println("-key", "aes encryption key\n")
		fmt.Println("Example encrypt 123.png: \n")
		fmt.Println("program.exe -e -i 123.png -key mykey")
		//testing
		err := decryptDirectory(DirOptions{
			Key: hashMd5([]byte("myKey")),
			Directory: "./test/",
		})
		fmt.Println("result:", err)
	}

	var sameFile bool
	if *outputFile == "" {
		sameFile = true
	} else {
		sameFile = false
	}
	key = hashMd5([]byte(*aesKey))

	if *encrypt == true && *cryptDir == false {
		//encrypt

		// run encrypt
		err = encryptFile(EncryptOptions{
			Filename: *input,
			Key: key,
			SameFile: sameFile,
			NewFilename: *outputFile,
		})
		// check for errors
		if err != nil {
			panic(err)
		}
		fmt.Println("\ndone encryption")
	} else if *decrypt == true && *cryptDir == false {
		// decrypt file

		// run decrypt
		err = decryptFile(DecryptOptions {
			Filename: *input,
			Key: key,
			SameFile: sameFile,
			NewFilename: *outputFile,
		})
		// check for errors
		if err != nil {
			panic(err)
		}
		fmt.Println("\ndone decryption")
	} else if *encrypt == true && *cryptDir == true {
		// encrypt directory
		err = encryptDirectory(DirOptions{
			Key: key,
			Directory: *input,
		})
		if err != nil {
			panic(err)
		}
		fmt.Println("\ndone encryption")
	} else if *decrypt == true && *cryptDir == true {
		// decrypt directory
		err = decryptDirectory(DirOptions{
			Key: key,
			Directory: *input,
		})
		if err != nil {
			panic(err)
		}
		fmt.Println("\ndone decryption")
	}

	
}