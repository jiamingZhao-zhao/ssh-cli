package version

import "testing"

func TestStringLocalDefault(t *testing.T) {
	if Version != "dev" {
		t.Fatalf("local default version = %q", Version)
	}
	if String() != "ssh-cli dev" {
		t.Fatalf("String() = %q", String())
	}
}

func TestStringWithBuildIdentity(t *testing.T) {
	oldV, oldC, oldD := Version, Commit, Date
	t.Cleanup(func() {
		Version, Commit, Date = oldV, oldC, oldD
	})
	Version, Commit, Date = "1.2.3", "abc", "2026-10-08T00:00:00Z"
	if String() != "ssh-cli 1.2.3 (abc, 2026-10-08T00:00:00Z)" {
		t.Fatalf("String() = %q", String())
	}
	Version, Commit, Date = "1.2.3", "abc", ""
	if String() != "ssh-cli 1.2.3 (abc)" {
		t.Fatalf("String() = %q", String())
	}
}

func TestReleaseVersion(t *testing.T) {
	if ReleaseVersion("v1.2.3") != "1.2.3" || ReleaseVersion("1.2.3") != "1.2.3" {
		t.Fatal(ReleaseVersion("v1.2.3"))
	}
}
