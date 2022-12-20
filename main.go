package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/operdies/go-pewriter/pkg/embed"
)

var quietFlag = false

func main() {
	var help = flag.Bool("help", false, "Show help")
	var writeFlag = false
	var readFlag = false
	var inFile = ""
	var outFile = ""
	var payloadFlag = ""
	var payloadKey = ""
	var getKeys = false
	var dump = false

	flag.BoolVar(&writeFlag, "write", false, "Write a payload to a file")
	flag.BoolVar(&readFlag, "read", false, "Read a payload from a file")
	flag.BoolVar(&quietFlag, "quiet", false, "Squelch informational logging")
	flag.StringVar(&inFile, "file", "", "The file to read or write")
	flag.StringVar(&outFile, "out", "", "The file to write the result to")
	flag.StringVar(&payloadFlag, "payload", "", "The file containing the payload to embed.")
	flag.StringVar(&payloadKey, "key", "", "The name of the payload to embed")
	flag.BoolVar(&getKeys, "keys", false, "List the keys embedded in the file")
	flag.BoolVar(&dump, "dump", false, "Dump the entire embedded json object")

	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	if quietFlag {
		log.SetOutput(ioutil.Discard)
	}

	// Disable timestamp logging
	log.SetFlags(0)

	var data []byte
	stat, err := os.Stat(inFile)
	if err != nil {
		log.Fatalf("File %v does not exist.\n", inFile)
	}

	if outFile == "" {
		outFile = inFile + ".out"
	}

	data, _ = os.ReadFile(inFile)

	if writeFlag || readFlag {
		if payloadKey == "" {
			log.Fatalln("No payload key specified.")
		}
	}
	if writeFlag {
		log.Printf("Adding payload to %v\n", inFile)
		payload, _ := os.ReadFile(payloadFlag)
		data = embed.AddPayload(data, payload, payloadKey)
		log.Printf("Saving result to %v\n", outFile)
		os.WriteFile(outFile, data, stat.Mode())
	}
	if readFlag {
		if writeFlag {
			log.Printf("Reading the payload which was written to %v\n", outFile)
		}
		payload, err := embed.ReadPayload(data, payloadKey)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(string(payload))
	}
	if dump {
		dir := embed.ReadPayloadDirectory(data)
		for k := range dir {
			payload, _ := embed.ReadPayload(data, k)
			fmt.Printf("%v: %v\n", k, string(payload))
		}
	}
}
