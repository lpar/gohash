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

func parseline(line string) (string, string, error) {
	fs := strings.Index(line, "  ")
	if fs < 0 {
		return "","", errors.New("bad input line")
	}
	return line[:fs], line[fs+2:], nil
}

func hashfile(hasher hash.Hash, filepath string) (string, error) {
	hashhex := ""
	file, err := os.Open(filepath)
	if err != nil {
		return hashhex, fmt.Errorf("can't hash %s: %v", filepath, err)
	}
	var ret error = nil
	defer func () {
		err = file.Close()
		if err != nil {
			ret = fmt.Errorf("error closing %s: %v", filepath, err)
		}
	}()
	hasher.Reset()
	_, err = io.Copy(hasher, file)
	if err != nil {
		return hashhex, fmt.Errorf("can't hash %s: %v", filepath, err)
	}
	sum := hasher.Sum(nil)
	hashhex = fmt.Sprintf("%x", sum)
	return hashhex, ret
}

func makeallhashes(hasher hash.Hash, filelist []string) int {
	failcount := 0
	for _, file := range filelist {
		hexhash, err := hashfile(hasher, file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failcount++
		} else {
			fmt.Printf("%s  %s\n", hexhash, file)
		}
	}
	return failcount
}

func checkallhashes(hasher hash.Hash, filelist []string) int {
	failcount := 0
	for _, file := range filelist {
		failures, err := checkhashes(hasher, file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		failcount += failures
	}
	if failcount != 0 {
		s := ""
		if failcount > 1 {
			s = "s"
		}
	  fmt.Fprintf(os.Stderr, "WARNING: %d computer checksum%s did NOT match", failcount, s)
	}
	return failcount
}

func checkhashes(hasher hash.Hash, filename string) (int, error) {
	failcount := 0
	file, err := os.Open(filename)
	if err != nil {
		failcount++
		return failcount, fmt.Errorf("can't check %s: %v", filename, err)
	}
	var ret error = nil
	defer func () {
		err = file.Close()
		if err != nil {
			ret = fmt.Errorf("error closing %s: %v", filename, err)
		}
	}()
	line := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line++
		expectedhash, filetohash, err := parseline(scanner.Text())
		if err != nil {
			failcount++
			return failcount, fmt.Errorf("bad input line %d of %s", line, filename)
		}
		filehash, err := hashfile(hasher, filetohash)
		if err != nil {
			failcount++
			return failcount, fmt.Errorf("can't check line %d of %s: %v", line, filename, err)
		}
		if filehash == expectedhash {
			fmt.Printf("%s: OK\n", filetohash)
		} else {
			fmt.Printf("%s: FAILED\n", filetohash)
			failcount++
		}
	}
	return failcount, ret
}

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

	failcount := 0
	if *chk {
		failcount = checkallhashes(hasher, args)
	} else {
		failcount = makeallhashes(hasher, args)
	}

	if failcount != 0 {
		os.Exit(4)
	}

}

