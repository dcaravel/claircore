package rhcc

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestMatcherVulnerable(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	m := &matcher{}

	t.Run("Inverted", func(t *testing.T) {
		record := &claircore.IndexRecord{
			Package:    &claircore.Package{Name: "mta/mta-rhel8-operator", Version: "7.0.3-13"},
			Repository: &GoldRepo,
		}
		vuln := &claircore.Vulnerability{
			Name:   "CVE-2024-24786",
			Invert: true,
			Repo:   &GoldRepo,
		}
		got, err := m.Vulnerable(ctx, record, vuln)
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Error("expected vulnerable=true for inverted vulnerability")
		}
	})

	t.Run("Normal", func(t *testing.T) {
		record := &claircore.IndexRecord{
			Package:    &claircore.Package{Name: "quay/quay-rhel8", Version: "v3.5.5-4"},
			Repository: &GoldRepo,
		}
		vuln := &claircore.Vulnerability{
			Name:           "CVE-2023-12345",
			FixedInVersion: "v3.5.6-1",
			Repo:           &GoldRepo,
		}
		got, err := m.Vulnerable(ctx, record, vuln)
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Error("expected vulnerable=true when version < fixed")
		}
	})

	t.Run("Fixed", func(t *testing.T) {
		record := &claircore.IndexRecord{
			Package:    &claircore.Package{Name: "quay/quay-rhel8", Version: "v3.5.7-1"},
			Repository: &GoldRepo,
		}
		vuln := &claircore.Vulnerability{
			Name:           "CVE-2023-12345",
			FixedInVersion: "v3.5.6-1",
			Repo:           &GoldRepo,
		}
		got, err := m.Vulnerable(ctx, record, vuln)
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Error("expected vulnerable=false when version >= fixed")
		}
	})
}

func TestVulnerable(t *testing.T) {
	t.Parallel()

	type testcase struct {
		name           string
		packageVersion string
		fixedInVersion string
		repoCPE        cpe.WFN
		vulnRepoCPE    cpe.WFN
		want           bool
	}
	table := []testcase{
		{
			name:           "TimestampOlder",
			packageVersion: "1740000000",
			fixedInVersion: "1742843776",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           true,
		},
		{
			name:           "TimestampNewer",
			packageVersion: "1744596866",
			fixedInVersion: "1742843776",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           false,
		},
		{
			name:           "TimestampEqual",
			packageVersion: "1742843776",
			fixedInVersion: "1742843776",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift_gitops:1.16::el8"),
			want:           false,
		},
		{
			name:           "TagOlder",
			packageVersion: "v3.5.5-4",
			fixedInVersion: "v3.5.7-8",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			want:           true,
		},
		{
			name:           "TagNewer",
			packageVersion: "v3.5.9-2",
			fixedInVersion: "v3.5.7-8",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			want:           false,
		},
		{
			name:           "TagCPEMismatch",
			packageVersion: "v3.5.5-4",
			fixedInVersion: "v3.5.7-8",
			repoCPE:        cpe.MustUnbind("cpe:/a:redhat:quay:3::el8"),
			vulnRepoCPE:    cpe.MustUnbind("cpe:/a:redhat:openshift:4::el8"),
			want:           false,
		},
	}

	var m matcher
	ctx := test.Logging(t)
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record := &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: tc.packageVersion,
				},
				Repository: &claircore.Repository{
					Key:  RepositoryKey,
					Name: tc.repoCPE.String(),
					CPE:  tc.repoCPE,
				},
			}
			vuln := &claircore.Vulnerability{
				FixedInVersion: tc.fixedInVersion,
				Repo: &claircore.Repository{
					Key:  RepositoryKey,
					Name: tc.vulnRepoCPE.String(),
					CPE:  tc.vulnRepoCPE,
				},
			}
			got, err := m.Vulnerable(ctx, record, vuln)
			if err != nil {
				t.Error(err)
			}
			if got != tc.want {
				t.Errorf("%q failed: Vulnerable(%q, %q) = %v, want %v",
					tc.name, tc.packageVersion, tc.fixedInVersion, got, tc.want)
			}
		})
	}
}
