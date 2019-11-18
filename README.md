
# gohash

A command line checksum generator and checker written in Go.

## Description

This is a simple command line checksum program. It will hash the files or directories given as arguments, including recursively descending any directories so you don't need to use `find`.

It supports the following algorithms:

 * crc32 (IEEE CRC-32)
 * md5 (RFC 1321)
 * sha1 (SHA-1)
 * sha224 (SHA-2-224)
 * sha256 (SHA-2-256)
 * sha384 (SHA-2-384)
 * sha512 (SHA-2-512)
 * sha512224 (SHA-2-512/224)
 * sha512256 (SHA-2-512/256)

Its checksum files should be compatible with the `shasum`, `sha1sum`, `sha224sum`, `sha256sum` and `sha512sum` Linux commands,
and the `shasum` program supplied with macOS. 

The CRC32 function is compatible with that of 7-zip and the Linux `crc32` program, but the output format is different. The GNU `cksum` program uses a different algorithm.

The code uses only Go standard library functions and can easily be compiled for Windows, or any other OS and architecture supported by Go, including:

 * Android
 * macOS
 * *BSD
 * Linux (PowerPC, ARM or MIPS)
 * Windows (386 or AMD64)

For example, to build a Windows binary using a Mac or Linux machine:

     env GOOS=windows GOARCH=amd64 go build -v

To build for the system you're using, a simple `go build` should suffice.

## Limitations

The "universal line endings" mode of `shasum` is not supported (*). This utility always compares file contents in binary mode. However, checksum files can have Unix or MS-DOS line endings.

(*) Yet. Patches welcome!
