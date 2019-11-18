package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var alg = flag.String("a", "sha256", "algorithm to use")
var chk = flag.Bool("c", false, "read checksums from the file(s) and check them")

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s [OPTION]... [FILE]...\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nAlgorithms supported: crc32 md5 sha1 sha224 sha256 sha384 sha512 sha512224 sha512256\n")
	os.Exit(2)
}

func parseLine(line string) (string, string, error) {
	fs := strings.Index(line, "  ")
	if fs < 0 {
		return "","", errors.New("bad input line")
	}
	return line[:fs], line[fs+2:], nil
}

func hashFile(hasher hash.Hash, filepath string) (string, error) {
	hashHex := ""
	inFile, err := os.Open(filepath)
	if err != nil {
		return hashHex, fmt.Errorf("can't hash %s: %v", filepath, err)
	}
	var ret error
	defer func () {
		err = inFile.Close()
		if err != nil {
			ret = fmt.Errorf("error closing %s: %v", filepath, err)
		}
	}()
	hasher.Reset()
	_, err = io.Copy(hasher, inFile)
	if err != nil {
		return hashHex, fmt.Errorf("can't hash %s: %v", filepath, err)
	}
	sum := hasher.Sum(nil)
	hashHex = fmt.Sprintf("%x", sum)
	return hashHex, ret
}

func makeAllHashes(hasher hash.Hash, fileList []string) int {
	failCount := 0
	hashFunc := func (filename string) {
		hexHash, err := hashFile(hasher, filename)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failCount++
		} else {
			fmt.Printf("%s  %s\n", hexHash, filename)
		}
	}
	for _, file := range fileList {
		info, err := os.Stat(file)
		if err != nil {
			failCount++
			continue
		}
		if info.IsDir() {
			err := filepath.Walk(file, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					failCount++
					return nil
				}
				if !info.IsDir() {
					hashFunc(path)
				}
				return nil
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				failCount++
			}
		continue
		}
		hashFunc(file)
	}
	return failCount
}

func checkAllHashes(hasher hash.Hash, fileList []string) int {
	failCount := 0
	for _, file := range fileList {
		failures, err := checkHashes(hasher, file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		failCount += failures
	}
	if failCount != 0 {
		s := ""
		if failCount > 1 {
			s = "s"
		}
	  fmt.Fprintf(os.Stderr, "WARNING: %d computer checksum%s did NOT match", failCount, s)
	}
	return failCount
}

func checkHashes(hasher hash.Hash, filename string) (int, error) {
	failCount := 0
	inFile, err := os.Open(filename)
	if err != nil {
		failCount++
		return failCount, fmt.Errorf("can't check %s: %v", filename, err)
	}
	var ret error
	defer func () {
		err = inFile.Close()
		if err != nil {
			ret = fmt.Errorf("error closing %s: %v", filename, err)
		}
	}()
	line := 0
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		line++
		expectedHash, fileToHash, err := parseLine(scanner.Text())
		if err != nil {
			failCount++
			return failCount, fmt.Errorf("bad input line %d of %s", line, filename)
		}
		fileHash, err := hashFile(hasher, fileToHash)
		if err != nil {
			failCount++
			return failCount, fmt.Errorf("can't check line %d of %s: %v", line, filename, err)
		}
		if fileHash == expectedHash {
			fmt.Printf("%s: OK\n", fileToHash)
		} else {
			fmt.Printf("%s: FAILED\n", fileToHash)
			failCount++
		}
	}
	return failCount, ret
}

// NewHasher returns a hash.Hash object for the algorithm specified by the string argument.
func NewHasher(algo string) hash.Hash {
	switch algo {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha224":
		return sha256.New224()
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	case "sha512224":
		return sha512.New512_224()
	case "sha512256":
		return sha512.New512_256()
	case "crc32":
		return crc32.New(crc32.MakeTable(crc32.IEEE))
	default:
		return nil
	}
}

func main () {
	flag.Usage = usage
	flag.Parse()

	hasher := NewHasher(*alg)
	if hasher == nil {
		fmt.Fprintf(os.Stderr,"unsupported hash algorithm %s\n", *alg)
		os.Exit(3)
	}

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "no input files specified\n")
		os.Exit(1)
	}

	failCount := 0
	if *chk {
		failCount = checkAllHashes(hasher, args)
	} else {
		failCount = makeAllHashes(hasher, args)
	}

	if failCount != 0 {
		os.Exit(4)
	}

}

