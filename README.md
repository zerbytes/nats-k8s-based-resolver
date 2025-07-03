# nats-based-resolver - NATS Account Resolver

NATS based account resolver Kubernetes-native operator.

This operator provides a Kubernetes-native way to manage NATS accounts and users, allowing you to create and manage NATS accounts and users using Kubernetes Custom Resource Definitions (CRDs).

[![Go Report Card](https://goreportcard.com/badge/github.com/zerbytes/nats-based-resolver)](https://goreportcard.com/report/github.com/zerbytes/nats-based-resolver)
[![License](https://img.shields.io/github/license/zerbytes/nats-based-resolver)](LICENSE)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/zerbytes/nats-based-resolver/CI)](https://github.com/zerbytes/nats-based-resolver/actions)

## Usage

> **Note**: This project is in early development stages, expect breaking changes and limited features.
> The API is not stable yet.

1. **Deploy the operator** - provides CRDs, generates Operator JWT and `$SYS` account automatically.
2. **Patch / deploy your NATS cluster** - mount and configure the following secrets:
   * `nats-operator-jwt` secret (operator.jwt)
   * `nats-sys-account-jwt` secret (sys.jwt)
   and enable `resolver: FULL` in `nats.conf`.
3. **Deploy the resolver service** (included YAML) - point it at NATS via env `NATS_URL` + mount the `$SYS` resolver creds.
4. **Create an account & user**:

```yaml
apiVersion: zerbytes.net/v1alpha1
kind: NatsAccount
metadata:
  name: payments
spec:
  jetStreamEnabled: true
---
apiVersion: zerbytes.net/v1alpha1
kind: NatsUser
metadata:
  name: payments-api
spec:
  accountRef:
    name: payments
    namespace: default
```

5. Mount `nats-user-payments-api-jwt` secret into your app pod and connect to NATS with the creds.

### Configure NATS To Use The Generated Secrets

To configure your NATS server to use the generated secrets, you need to modify your `nats.conf` file to include the following:

```conf
# This is the resolver configuration for NATS based account resolver
resolver: {
    type: full
    # Directory in which account jwt will be stored (in Kubernetes this can be a volume mount or emptyDir)
    dir: './jwt'
    # In order to support jwt deletion, set to true.
    # If you set it to true, be aware that there is currently no mechanism that would delete deleted jwts.
    allow_delete: false
    # Interval at which a nats-server with a nats based account resolver will compare
    # it's state with one random nats based account resolver in the cluster and if needed,
    # exchange jwt and converge on the same set of jwt.
    interval: "2m"
    # limit on the number of jwt stored, will reject new jwt once limit is hit.
    limit: 1000
}
```

(Taken from [NATS docs - Account lookup using Resolver - NATS Based Resolver](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt/resolver#full))

#### Using With NATS Helm Chart

If you are using the [NATS Helm Chart](https://github.com/nats-io/k8s), you can enable the resolver by adding the following to your `values.yaml`:

```yaml
# values.yaml
nats:
  resolver:
    type: full
    dir: './jwt'
    allow_delete: false
    interval: "2m"
    limit: 1000
```

(Currently these instructions are not tested and incomplete (additional volumes and volume mounts for secrets are missing), please open an issue if you have problems.)

## Contributing

Contributions are welcome! A contributing guide will be added soon.

## Development

```bash
# clone repo & init
make generate      # kubebuilder & controller-gen output
make manifests     # CRDs
make docker-build  # build operator & resolver images
make docker-push   # push to your repo
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
