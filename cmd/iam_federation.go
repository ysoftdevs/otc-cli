package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/iam"
)

type iamFederationAPI interface {
	GetOIDCConfig(string) (iam.Record, error)
	CheckOIDCConfig(string) ([]iam.Record, error)
	GetSAMLMetadata(string, string) (iam.Record, error)
	GetSPMetadata() (iam.Record, error)
}

var _ iamFederationAPI = (*iam.Service)(nil)

func addIAMFederationCommands(root *cobra.Command, connect iamFactory) {
	for _, group := range root.Commands() {
		switch group.Name() {
		case "providers":
			oidc := &cobra.Command{Use: "oidc", Short: "Inspect stored OIDC configuration and compare public signing keys"}
			oidc.AddCommand(iamShow(connect, "show PROVIDER_ID", "Show stored OIDC configuration and public signing keys",
				func(api iamAPI, args []string) (iam.Record, error) {
					federation, err := requireIAMFederation(api)
					if err != nil {
						return nil, err
					}
					return federation.GetOIDCConfig(args[0])
				}))
			oidc.AddCommand(iamOIDCCheck(connect))
			group.AddCommand(oidc)
		case "protocols":
			group.AddCommand(iamRead(connect, "metadata PROVIDER_ID PROTOCOL_ID", "Show imported SAML IdP metadata, including XML",
				formats.View[iam.Record]{}, true, func(api iamAPI, args []string) ([]iam.Record, error) {
					federation, err := requireIAMFederation(api)
					if err != nil {
						return nil, err
					}
					return iamSingle(federation.GetSAMLMetadata(args[0], args[1]))
				}, 2))
			group.AddCommand(iamRead(connect, "sp-metadata", "Show regional Keystone service-provider metadata XML",
				formats.View[iam.Record]{}, true, func(api iamAPI, _ []string) ([]iam.Record, error) {
					federation, err := requireIAMFederation(api)
					if err != nil {
						return nil, err
					}
					return iamSingle(federation.GetSPMetadata())
				}, 0))
		}
	}
}

func requireIAMFederation(api iamAPI) (iamFederationAPI, error) {
	federation, ok := api.(iamFederationAPI)
	if !ok {
		return nil, fmt.Errorf("IAM client does not support federation inspection")
	}
	return federation, nil
}

func iamOIDCCheck(connect iamFactory) *cobra.Command {
	command := iamRead(connect, "check PROVIDER_ID", "Compare stored OIDC keys with the issuer's public discovery and JWKS",
		formats.View[iam.Record]{}, false, nil, 1)
	command.Long = `Read the provider's OIDC configuration from OTC, then fetch its public HTTPS
discovery and JWKS documents using a separate client without OTC credentials.
Compare issuer, signing key IDs and public key material. No keys are updated.

Private/local metadata addresses are rejected. Requests have a 10-second timeout
and a 1 MiB response limit. This is a configuration comparison, not a login test:
token audience, claims mapping and effective permissions are not verified.

Results are printed before returning a nonzero exit status for differences or
unavailable evidence. A stored-only key is informational (rotation overlap).`
	command.RunE = func(_ *cobra.Command, args []string) error {
		api, err := connect()
		if err != nil {
			return err
		}
		federation, err := requireIAMFederation(api)
		if err != nil {
			return err
		}
		rows, err := federation.CheckOIDCConfig(args[0])
		if err != nil {
			return err
		}
		view := formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
			iamColumn("Check", "check"), iamColumn("Status", "status"), iamColumn("Key ID", "kid"), iamColumn("Detail", "detail"),
		}}
		if err := printIAMRecords(rows, view, false); err != nil {
			return err
		}
		if len(rows) == 0 {
			return fmt.Errorf("OIDC comparison returned no evidence")
		}
		for _, row := range rows {
			if row["status"] == "different" || row["status"] == "unavailable" {
				return fmt.Errorf("OIDC comparison found differences or unavailable evidence; see results above")
			}
		}
		return nil
	}
	return command
}
