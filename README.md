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
2. **Patch / deploy your NATS cluster** - mount
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
