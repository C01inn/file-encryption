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
	inputFile := flag.String("i", "", "input file")
	outputFile := flag.String("o", "", "outputfile")
	flag.Parse()
	// if user specifies no flags then the program will print some basic documentation
	if *encrypt == false && *decrypt == false && *aesKey == "" && *inputFile == "" && *outputFile == "" {
		fmt.Println("-e", "encrypt")
		fmt.Println("-d", "decrypt")
		fmt.Println("-i", "input file")
		fmt.Println("-o", "output file")
		fmt.Println("-key", "aes encryption key\n")
		fmt.Println("Example encrypt 123.jpg: \n")
		fmt.Println("program.exe -e -i 123.jpg -key mykey")
	}

	var sameFile bool
	if *outputFile == "" {
		sameFile = true
	} else {
		sameFile = false
	}

	if *encrypt == true {
		//encrypt
		// key
		key = hashMd5([]byte(*aesKey))
		// run encrypt
		err = encryptFile(EncryptOptions{
			Filename: *inputFile,
			Key: key,
			SameFile: sameFile,
			NewFilename: *outputFile,
		})
		// check for errors
		if err != nil {
			panic(err)
		}
		fmt.Println("done encryption")
	} else if *decrypt == true{
		// decrypt file
		// hash key 
		key = hashMd5([]byte(*aesKey))

		// run decrypt
		err = decryptFile(DecryptOptions {
			Filename: *inputFile,
			Key: key,
			SameFile: sameFile,
			NewFilename: *outputFile,
		})
		// check for errors
		if err != nil {
			panic(err)
		}
		fmt.Println("done decryption")
	}

	
}