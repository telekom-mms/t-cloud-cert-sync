# Helm Chart: T Cloud ELB Certificate Sync

By default the controller watches TLS Secrets in all namespaces and patches their sync annotations, with cluster-wide Secret permissions. Set `config.watchNamespace` to watch a single namespace instead; the chart then grants a Role in that namespace only.

Create a Kubernetes Secret named `t-cloud-credentials` in the release namespace with keys `OS_ACCESS_KEY` and `OS_SECRET_KEY`. Do not commit actual credentials to Helm values or Git.

Add the GitHub Pages Helm repository and install the latest stable chart:

```bash
helm repo add t-cloud-cert-sync https://sfhl.github.io/t-cloud-cert-sync/charts
helm repo update
helm upgrade --install cert-sync cert-sync/t-cloud-cert-sync \
  --namespace t-cloud-cert-sync --create-namespace \
  --set config.tCloudProjectId=YOUR_PROJECT_ID \
  --set credentials.existingSecret.name=t-cloud-credentials
```

Enable GitHub Pages in the GitHub repository settings with **GitHub Actions** as the build and deployment source. The chart repository becomes available after the next non-prerelease `v*` release. Run `helm repo update` before upgrades to discover newer charts; omit `--version` to select the latest stable chart. The chart defaults to `ghcr.io/telekom-mms/t-cloud-cert-sync:latest`. For a fixed deployment, set `--version` on the Helm command and `image.tag` to the matching `v` tag. Replace the project ID and override `image.repository` if using a fork or another registry. Set `config.tCloudRegion` if the project is not in `eu-de`. `config.keepCertRegex` defaults to `dummy`: certificates whose names match this regex will not be removed during cleanup. If your image is private, supply `imagePullSecrets`.
