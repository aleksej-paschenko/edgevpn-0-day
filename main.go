package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"runtime"
	"sync"
	"time"
)

// MD5 is just syntax sugar around crypto/md5
func MD5(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}
func Unseal(message []byte, key string) (decoded string, err error) {
	enckey := [32]byte{}
	copy(enckey[:], key)
	return AESDecrypt(message, enckey)
}

func AESDecrypt(ciphertext []byte, key [32]byte) (plaintext string, err error) {
	//ciphertext, _ := hex.DecodeString(text)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("malformed ciphertext")
	}

	decodedtext, err := gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
	if err != nil {
		return "", err
	}

	return string(decodedtext), err
}

func deCompress(b []byte) (*bytes.Buffer, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	result, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(result), nil
}

// Update the blockchain from a message
func Update(msg string) error {
	b, err := deCompress([]byte(msg))
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", b.String())
	return nil
}

func main() {

	// assuming key length is 32

	nums := runtime.NumCPU() * 2
	fmt.Printf("goroutines = %v\n", nums)
	ch := make(chan string, nums)
	msg := "b7ff0bdc5fad3694be5620d13dc9a4dd5853cca683c7c0b28ddad857c368f88dde84ae3ce1f26149d97a907354d51142f2fe9eb2f81363e64eec6567a66d4d88685972a8694e04eec3b4ffb2a38159eea83dbb5068b240340d7720e1fa8be13af5efc2958a00ac99782d6dd7a853d95eb05eabebbd48c1beaf4c388dada82257d88b1e9f666c79e7abb36526920bf351d5dca113d0db9695249438df3aab6ca8cb7e18929f331698b390085fac91b8a02f6060dd437472d2246ad986c3d2b98f2e5f63965c762b861f5a3ef2445df83b6ca93a23ce3408f68291796eb9eb06edfb117a5de092522e95f983cc66acc7f873e0660eb8553b43fd2cc3465e1a4772e647846be7d8cb2e3c08a3385909c32200ea55000ae465723bd0144a740cc5e772f368e17070cc0543689335bddacaf6eaa5"
	ciphertext, err := hex.DecodeString(msg)
	if err != nil {
		panic(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)

	for i := 0; i < nums; i++ {
		go func() {
			for {
				x := <-ch
				text, err := Unseal(ciphertext, x)
				if err != nil {
					continue
				}
				fmt.Printf("key= %v\n", x)
				Update(text)
				wg.Done()
			}
		}()
	}

	started := time.Now()
	c := math.MaxInt32 / 100
	go func() {
		for i := 0; i <= math.MaxInt32; i++ {
			otp := fmt.Sprintf("%032d", i)
			x := MD5(otp)
			ch <- x
			if i%c == 0 {
				fmt.Printf("scanned %0.2f%%\n", float64(i)/math.MaxInt32*100)
			}
		}
		wg.Done()
	}()
	wg.Wait()

	fmt.Printf("it takes %v\n", time.Since(started))
}
