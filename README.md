# T Cloud ELB Certificate Sync Controller

This Kubernetes controller watches TLS Secrets annotated with `t-cloud.telekom.com/listener-id: "<listener-uuid>"`. When the certificate changes, it uploads the new certificate to T Cloud ELB v3 and binds it to that listener. It remembers successful syncs in a Secret annotation.

The previous certificate is deleted after a successful bind unless its name matches `KEEP_CERT_REGEX`. If the certificate name cannot be checked, cleanup is skipped. By default the controller needs cluster-wide access to Secrets; deploy it only in a trusted cluster, or set `WATCH_NAMESPACE` to limit it to one namespace.

### Listener slots

A listener serves one default certificate and SNI certificates. The annotation `t-cloud.telekom.com/listener-slot` selects where a Secret goes:

| Value | Effect |
| --- | --- |
| `default` or unset | Replaces the listener's `default_tls_container_ref`. Only one Secret per listener may use it. |
| `sni` | Replaces only this Secret's entry in `sni_container_refs` and keeps all other SNI certificates. Several Secrets can share one listener this way. |

```yaml
metadata:
  annotations:
    t-cloud.telekom.com/listener-id: "<listener-uuid>"
    t-cloud.telekom.com/listener-slot: "sni"
```

ELB requires domain names on SNI certificates. The controller takes them from the DNS subject alternative names of the leaf certificate in `tls.crt` and skips Secrets without any. According to the ELB v3 API, the domain names of all SNI certificates on a listener must be unique and may not exceed 30 in total.

After a successful bind the controller records the ELB certificate ID in `t-cloud.telekom.com/certificate-id`. An SNI rotation replaces exactly that entry; if the annotation is missing or stale, it falls back to the entry named `k8s-<secret-name>-<timestamp>`. Any other SNI certificate sharing a domain name with the new certificate, for example one uploaded by hand, is removed from the listener in the same update but not deleted. Two Secrets with a shared domain name on one listener therefore keep displacing each other. If the listener or one of its SNI certificates cannot be read, the SNI sync is skipped rather than risking other entries. The controller reads and then replaces the listener's SNI list; concurrent changes from the console or another controller between those operations may be overwritten. Avoid managing the SNI list concurrently. Every listener needs a default certificate before SNI certificates can be added.

For SNI clients, ELB serves a matching SNI certificate instead of the default certificate. Before binding a default certificate, the controller logs a warning for each SNI certificate on the listener that shares a domain name with it; it does not change the SNI list. This typically happens when the previous default certificate was also added as an SNI certificate. Its cleanup then fails with `ELB.8921` (certificate in use by a listener) until it is removed from the SNI list.

## Install

Use a Kubernetes cluster with cert-manager or another source of TLS Secrets, a T Cloud project, and a published container image. Create a Kubernetes Secret in the controller's namespace containing `OS_ACCESS_KEY` and `OS_SECRET_KEY`. The IAM user only needs the ELB actions `elb:certificates:create`, `elb:certificates:get`, `elb:certificates:delete`, `elb:listeners:get` and `elb:listeners:put`. The [Helm chart](.helm/README.md) documents installation from the GitHub Pages Helm repository with an existing Secret.

## Development

Go 1.23.12 or newer is required. The controller itself uses in-cluster Kubernetes credentials.

```bash
go test -mod=readonly ./...
docker build -t t-cloud-cert-sync:dev .
```

## Configuration

| Variable | Description |
|---|---|
| `OS_AUTH_URL` | Identity endpoint, e.g. `https://iam.eu-de.otc.t-systems.com/v3` |
| `OS_REGION_NAME` | T Cloud region, e.g. `eu-de` |
| `OS_PROJECT_ID` | T Cloud project ID |
| `OS_ACCESS_KEY` | T Cloud access key (from a Kubernetes Secret) |
| `OS_SECRET_KEY` | T Cloud secret key (from a Kubernetes Secret) |
| `KEEP_CERT_REGEX` | Regex matched against old certificate names before cleanup; default `dummy`. An invalid regex stops startup. |
| `WATCH_NAMESPACE` | Only watch Secrets in this namespace; empty watches all namespaces (needs cluster-wide Secret access). |

## Releases

GitHub Actions runs tests, lints the chart, and builds the image on pull requests and pushes. A `v*` tag publishes the image to GHCR, attaches the Helm chart to a GitHub release, and updates the GitHub Pages Helm repository. Enable Pages with GitHub Actions as its source before the first chart repository deployment. Set the GHCR package visibility to public before using the chart without registry credentials; the repository owner must authorize publication of the code and images.

Licensed under [GPL-3.0](LICENSE).
