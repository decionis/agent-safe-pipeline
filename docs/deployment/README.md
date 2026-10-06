# Deployment documentation

Choose the execution boundary, then configure its network, authority and operating controls.

| Guide                                                             | Use it for                                                                                                                                      |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| [Gateway deployment strategies](./gateway-strategies.md)          | Compare on-premises, private cloud and managed cloud; configure Docker/TLS, Kubernetes, Istio, AWS or Azure isolation and verify bypass denial. |
| [Agent integration and setup](../gateway/deployment.md)           | Put tool calls through the gateway, install it on premises and connect to a hosted authority or managed gateway.                                |
| [Trusted executor kit](../../deploy/README.md)                    | Separate authenticated proposers from the process holding privileged API credentials.                                                           |
| [Transparent interceptor](../gateway/transparent-interception.md) | Intercept supported traffic when tool base URLs cannot change.                                                                                  |
| [Production](./production.md)                                     | Pin the image, configure enforcement and failure behavior, and operate the deployment.                                                          |
| [High availability](./high-availability.md)                       | Plan replica routing, held requests, evidence and capacity.                                                                                     |
| [Security](./security.md)                                         | Understand what the image/runtime establish and what the platform must enforce.                                                                 |

The [public deployment overview](https://decionis.ai/deployments) introduces these options.
The runnable examples and configuration contracts live in this repository.
