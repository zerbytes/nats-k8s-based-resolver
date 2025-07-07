---
title: nats-k8s-based-resolver Helm Chart
---
{{ template "generatedDocsWarning" . }}

Installs [nats-k8s-based-resolver](https://github.com/zerbytes/nats-k8s-based-resolver).

## Prerequisites

* Kubernetes 1.19+
* Helm 3.x

See the [Helm support matrix](https://helm.sh/docs/topics/version_skew/) for more details.

## Installing

```console
helm repo add nats-k8s-based-resolver https://zerbytes.github.io/nats-k8s-based-resolver
helm install nats-k8s-based-resolver/nats-k8s-based-resolver -f values.yaml

# Or upgrade
helm upgrade --install nats-resolver nats-k8s-based-resolver/nats-k8s-based-resolver -f values.yaml
```

For example settings, see the next section or [values.yaml](/dist/chart/values.yaml).

### Must Change Values

The following values must be changed before installing the chart:

- `controllerManager.container.args`: Make sure to update the `--nats-url` flag to point to your NATS server/cluster that you want to manage with nats-k8s-based-resolver.

## Configuration

The following table lists the configurable parameters of the nats-k8s-based-resolver chart and their default values.

{{ template "chart.valuesTable" . }}

## Uninstalling the Chart

To see the currently installed nats-k8s-based-resolver chart:

```console
helm ls
```

To uninstall/delete the `nats-k8s-based-resolver` deployment:

```console
helm delete nats-k8s-based-resolver
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## License

Apache 2.0 License, see [LICENSE](/LICENSE).
