// Package certificate implements `flareadm certificate ...`: zone custom
// certificates (upload, inspect, delete).
package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// statusValues are the custom certificate statuses accepted by the API.
var statusValues = []string{"active", "expired", "deleted", "pending", "initializing"}

// bundleMethods are the accepted bundle methods.
var bundleMethods = []string{"ubiquitous", "optimal", "force"}

// deployValues are the accepted deploy environments.
var deployValues = []string{"staging", "production"}

// typeValues are the accepted certificate types.
var typeValues = []string{"legacy_custom", "sni_custom"}

// New builds the certificate command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Zone custom certificates",
		Long:  "Manage custom certificates uploaded to a zone.",
	}
	cmd.AddCommand(newList(rt))
	cmd.AddCommand(newGet(rt))
	cmd.AddCommand(newCreate(rt))
	cmd.AddCommand(newDelete(rt))
	return cmd
}

func certRow(c cloudflare.Certificate) []string {
	return []string{c.ID, c.Status, strings.Join(c.Hosts, ","), dateOnly(c.ExpiresOn), c.Issuer}
}

// dateOnly trims an RFC3339 timestamp to its date part for table output.
func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// valueOrFile resolves a flag value: "@path" reads the file, anything else
// is used verbatim.
func valueOrFile(flag, v string) (string, error) {
	if !strings.HasPrefix(v, "@") {
		return v, nil
	}
	path := v[1:]
	if path == "" {
		return "", errors.Usage("--%s @ requires a file path", flag)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.Wrap(errors.CodeInvalid, fmt.Sprintf("reading %s file %s", flag, path), err)
	}
	return string(data), nil
}

// fileOnlyValue resolves a flag that accepts ONLY the @file form. Used for
// credential material: command-line arguments are observable (ps, shell
// history), so inline secrets are rejected.
func fileOnlyValue(flag, v string) (string, error) {
	if !strings.HasPrefix(v, "@") {
		return "", errors.Usage(
			"--%s accepts only the @file form (for example @key.pem); inline secret values are not allowed because process arguments are observable",
			flag)
	}
	return valueOrFile(flag, v)
}

// certificateHosts extracts the host names of the leaf certificate for the
// dry-run preview. It never inspects or returns key material.
func certificateHosts(pemText string) []string {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	hosts := append([]string(nil), cert.DNSNames...)
	if len(hosts) == 0 && cert.Subject.CommonName != "" {
		hosts = append(hosts, cert.Subject.CommonName)
	}
	sort.Strings(hosts)
	return hosts
}

func newList(rt *app.Runtime) *cobra.Command {
	var statusFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List custom certificates of a zone",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if statusFlag != "" && !contains(statusValues, statusFlag) {
				return errors.Usage("invalid --status %q (supported: %s)", statusFlag, strings.Join(statusValues, ", "))
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			q := cloudflare.CertificateQuery{Status: statusFlag}
			res, err := client.ListCertificates(cmd.Context(), zoneID, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "STATUS", "HOSTS", "EXPIRES", "ISSUER"}, certRow)
		},
	}
	cmd.Flags().StringVar(&statusFlag, "status", "", "only certificates with this status (active, expired, deleted, pending, initializing)")
	return cmd
}

func newGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get CERTIFICATE_ID",
		Short: "Show one custom certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetCertificate(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "STATUS", "HOSTS", "EXPIRES", "ISSUER"}, certRow)
		},
	}
}

func newCreate(rt *app.Runtime) *cobra.Command {
	var certificateFlag, privateKeyFlag, bundleMethod, deploy, certType string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Upload a custom certificate",
		Long: "Upload a custom certificate to a zone.\n\n" +
			"Examples:\n" +
			"  flareadm certificate create --zone example.com --certificate @cert.pem --private-key @key.pem\n" +
			"  flareadm certificate create --zone example.com --certificate @cert.pem --private-key @key.pem \\\n" +
			"    --bundle-method optimal --deploy production\n\n" +
			"--private-key accepts only the @file form: inline secret values are rejected\n" +
			"because process arguments are observable. The key is sent only to the\n" +
			"Cloudflare API and is never printed or logged.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if bundleMethod != "" && !contains(bundleMethods, bundleMethod) {
				return errors.Usage("invalid --bundle-method %q (supported: %s)", bundleMethod, strings.Join(bundleMethods, ", "))
			}
			if deploy != "" && !contains(deployValues, deploy) {
				return errors.Usage("invalid --deploy %q (supported: %s)", deploy, strings.Join(deployValues, ", "))
			}
			if certType != "" && !contains(typeValues, certType) {
				return errors.Usage("invalid --type %q (supported: %s)", certType, strings.Join(typeValues, ", "))
			}
			certificate, err := valueOrFile("certificate", certificateFlag)
			if err != nil {
				return err
			}
			if certificate == "" {
				return errors.Usage("--certificate is required (PEM bundle, inline or @file)")
			}
			privateKey := ""
			if cmd.Flags().Changed("private-key") {
				privateKey, err = fileOnlyValue("private-key", privateKeyFlag)
				if err != nil {
					return err
				}
				if strings.TrimSpace(privateKey) == "" {
					return errors.Usage("--private-key file is empty")
				}
				// Register the key material for scrubbing before any
				// request, error path or diagnostic can run.
				rt.ProtectSecret(privateKey)
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewCreate(rt, zoneID, certificate)
			}
			res, err := client.CreateCertificate(cmd.Context(), zoneID, cloudflare.CertificateCreateParams{
				Certificate:  certificate,
				PrivateKey:   privateKey,
				BundleMethod: bundleMethod,
				Deploy:       deploy,
				Type:         certType,
			})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "STATUS", "HOSTS", "EXPIRES", "ISSUER"}, certRow)
		},
	}
	cmd.Flags().StringVar(&certificateFlag, "certificate", "", "certificate PEM bundle, inline or @file")
	cmd.Flags().StringVar(&privateKeyFlag, "private-key", "", "private key PEM as @file only (inline secret values are rejected)")
	cmd.Flags().StringVar(&bundleMethod, "bundle-method", "", "bundle method (ubiquitous, optimal, force)")
	cmd.Flags().StringVar(&deploy, "deploy", "", "deploy environment (staging, production)")
	cmd.Flags().StringVar(&certType, "type", "", "certificate type (legacy_custom, sni_custom)")
	return cmd
}

func newDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete CERTIFICATE_ID",
		Short: "Delete a custom certificate",
		Long: "Delete a custom certificate from a zone. Destructive: prompts for\n" +
			"confirmation unless --yes is given; --dry-run previews the deletion without\n" +
			"confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetCertificate(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				line := fmt.Sprintf("Would delete certificate %s (%s)", existing.Item.ID, strings.Join(existing.Item.Hosts, ","))
				if rt.Format() == output.Table {
					_, _ = fmt.Fprintln(rt.Out, line)
					return nil
				}
				return rt.Printer().Emit(map[string]string{"preview": line})
			}
			question := fmt.Sprintf("Delete certificate %s?", existing.Item.ID)
			if len(existing.Item.Hosts) > 0 {
				question = fmt.Sprintf("Delete certificate %s (%s)?", existing.Item.ID, strings.Join(existing.Item.Hosts, ","))
			}
			if err := rt.Confirm(question); err != nil {
				return err
			}
			if err := client.DeleteCertificate(cmd.Context(), zoneID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted certificate %s from zone %s", args[0], zoneID)
			return nil
		},
	}
	return cmd
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// previewCreate prints the dry-run preview for certificate create. Only
// public information (zone and certificate host names) is shown; key
// material never reaches the preview.
func previewCreate(rt *app.Runtime, zoneID, certificatePEM string) error {
	line := fmt.Sprintf("Would upload a certificate to zone %s", zoneID)
	if hosts := certificateHosts(certificatePEM); len(hosts) > 0 {
		line += " for hosts: " + strings.Join(hosts, ", ")
	}
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": rt.Redact(line)})
}
