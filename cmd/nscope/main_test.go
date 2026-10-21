package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLIRejectsInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{{"-connect-ports", "no"}, {"-connect-ports", ""}, {"-connect-ports", "443,"}, {"-listen", "0.0.0.0:8081"}, {"-request-timeout", "0s"}, {"-deny", "https://example.com"}, {"unexpected"}, {"-unknown"}, {"-ui-listen", "0.0.0.0:8082"}} {
		var output bytes.Buffer
		if err := run(context.Background(), args, &output); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
func TestHelpDoesNotStartListener(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"-help"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "127.0.0.1:8081") {
		t.Fatal("help missing default listen address")
	}
}
