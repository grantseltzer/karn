package cli

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/GrantSeltzer/karn/tests"
)

func TestGenerateSeccomp(t *testing.T) {

	tempOutputDirectory, err := ioutil.TempDir("/tmp", "declarations")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempOutputDirectory) // clean up

	GenOptions := GenerateOptions{
		declarationDirectory: "../tests/golden_files/input",
		seccomp:              true,
		apparmor:             false,
		outputDirectory:      tempOutputDirectory,
	}

	// Sub tests
	t.Run("clashing_rules", func(t *testing.T) {
		out := tests.MockWriter{}
		arguments := []string{"clashing_rules_a", "clashing_rules_b"}
		err := GenOptions.Run(&out, arguments)
		if err != nil {
			t.Error(err)
		}

		written, err := ioutil.ReadFile("../tests/golden_files/output/clashing_rules_output.json")
		if err != nil {
			t.Error(err)
		}

		if !out.CorrectOutput(written) {
			t.Errorf("wrong output for clashing rules\nExpected:\n%s\nGot:\n%s\n", string(written), string(out.Internal))
		}
	})

}
