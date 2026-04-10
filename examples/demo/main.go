// Demo runner that loads the example policies and evaluates them against
// examples/demo/input.json. Useful for sanity-checking a fresh checkout.
//
//	cd /Users/duppster/crowdcontrol
//	go run ./examples/demo
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/mikemackintosh/crowdcontrol"
	"github.com/mikemackintosh/crowdcontrol/evaluator"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("demo: ")

	eng, err := crowdcontrol.New([]string{"examples/policies"})
	if err != nil {
		log.Fatalf("loading policies: %v", err)
	}

	data, err := os.ReadFile("examples/demo/input.json")
	if err != nil {
		log.Fatalf("reading input: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		log.Fatalf("parsing input: %v", err)
	}

	results := eng.Evaluate(doc)
	output, allPassed := evaluator.FormatResults(results)
	fmt.Print(output)

	if !allPassed {
		fmt.Fprintln(os.Stderr, "demo: at least one rule denied this input")
		os.Exit(1)
	}
}
