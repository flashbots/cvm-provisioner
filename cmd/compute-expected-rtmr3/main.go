// Command compute-expected-rtmr3 is the verifier-side helper: given a compose
// file on stdin (or as argv[1]), it prints the SHA384 of the manifest and the
// expected RTMR3 value (SHA384(zero(48) || SHA384(compose))).
//
// The operator pins this expected value alongside MRTD + RTMR0..2 from the
// image build. The remote verifier fetches a TDX quote and checks RTMR3 == pinned.
package main

import (
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [compose.yaml]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Reads from stdin if no file given.\n")
	}
	flag.Parse()

	var data []byte
	var err error
	switch flag.NArg() {
	case 0:
		data, err = io.ReadAll(os.Stdin)
	case 1:
		data, err = os.ReadFile(flag.Arg(0))
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	composeDigest := sha512.Sum384(data)

	// RTMR3 starts at zero on TD launch. The provisioner extends it exactly once:
	//   RTMR3_new = SHA384(RTMR3_old || extend_input)
	//             = SHA384(zero(48)  || SHA384(compose))
	var zero [48]byte
	concat := append(zero[:], composeDigest[:]...)
	rtmr3 := sha512.Sum384(concat)

	fmt.Printf("compose_sha384:    %s\n", hex.EncodeToString(composeDigest[:]))
	fmt.Printf("expected_rtmr3:    %s\n", hex.EncodeToString(rtmr3[:]))
}
