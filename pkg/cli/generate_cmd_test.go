package cli

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/grantseltzer/karn/tests"
)

func TestGenerateSeccomp(t *testing.T) {

	tempOutputDirectory, err := ioutil.TempDir("/tmp", "declarations")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempOutputDirectory) // clean up

	GenOptions := GenerateOptions{
		declarationDirectory: "../test_files/input",
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

		written, err := ioutil.ReadFile("../test_files/output/clashing_rules_seccomp_golden.json")
		if err != nil {
			t.Error(err)
		}

		if !out.CorrectOutput(written) {
			t.Errorf("wrong output for clashing rules\nExpected:\n%s\nGot:\n%s\n", string(written), string(out.Internal))
		}
	})

	t.Run("multiple_inputs_same_action", func(t *testing.T) {
		out := tests.MockWriter{}
		arguments := []string{"chown", "dns"}
		err := GenOptions.Run(&out, arguments)
		if err != nil {
			t.Error(err)
		}

		written, err := ioutil.ReadFile("../test_files/output/chown_dns_seccomp_golden.json")
		if err != nil {
			t.Error(err)
		}

		if !out.CorrectOutput(written) {
			t.Errorf("wrong output for multiple declarations with same action\nExpected:\n%s\nGot:\n%s\n", string(written), string(out.Internal))
		}
	})

	t.Run("single_input", func(t *testing.T) {
		out := tests.MockWriter{}
		arguments := []string{"chown"}
		err := GenOptions.Run(&out, arguments)
		if err != nil {
			t.Error(err)
		}

		written, err := ioutil.ReadFile("../test_files/output/chown_seccomp_golden.json")
		if err != nil {
			t.Error(err)
		}

		if !out.CorrectOutput(written) {
			t.Errorf("wrong output for single declaration\nExpected:\n%s\nGot:\n%s\n", string(written), string(out.Internal))
		}
	})
}

func TestGenerateApparmor(t *testing.T) {

	tempOutputDirectory, err := ioutil.TempDir("/tmp", "declarations")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempOutputDirectory) // clean up

	GenOptions := GenerateOptions{
		declarationDirectory: "../test_files/input",
		seccomp:              false,
		apparmor:             true,
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

		written, err := ioutil.ReadFile("../test_files/output/clashing_rules_apparmor_golden")
		if err != nil {
			t.Error(err)
		}

		if !out.CorrectOutput(written) {
			t.Errorf("wrong output for clashing rules\nExpected:\n%s\nGot:\n%s\n", string(written), string(out.Internal))
		}
	})

	t.Run("multiple_inputs_same_action", func(t *testing.T) {
		out := tests.MockWriter{}
		arguments := []string{"chown", "dns"}
		err := GenOptions.Run(&out, arguments)
		if err != nil {
			t.Error(err)
		}

		written, err := ioutil.ReadFile("../test_files/output/chown_dns_apparmor_golden")
		if err != nil {
			t.Error(err)
		}

		if !out.CorrectOutput(written) {
			t.Errorf("wrong output for multiple declarations with same action\nExpected:\n%s\nGot:\n%s\n", string(written), string(out.Internal))
		}
	})

	t.Run("single_input", func(t *testing.T) {
		out := tests.MockWriter{}
		arguments := []string{"chown"}
		err := GenOptions.Run(&out, arguments)
		if err != nil {
			t.Error(err)
		}

		written, err := ioutil.ReadFile("../test_files/output/chown_apparmor_golden")
		if err != nil {
			t.Error(err)
		}

		if !out.CorrectOutput(written) {
			t.Errorf("wrong output for single declaration\nExpected:\n%s\nGot:\n%s\n", string(written), string(out.Internal))
		}
	})
}
