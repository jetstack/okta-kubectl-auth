# Okta auth plugin for kubectl

## Setup

### Okta

For instructions on how to set up an Okta application that uses the OIDC flow to expose user groups as JWT claims, refer to [okta-setup](./docs/okta-setup.md).

### okta-kubectl-auth

Once you have compiled and installed `okta-kubectl-auth` and created your Okta application we can use it to authenticate.

- In the Okta console, browse to your application and on the General tab, copy your application's ClientID and Client secret
- Browse to Security, API and copy the Issuer URI from your authorisation server

We can now run `okta-kubectl-auth` as follows:

```
okta-kubectl-auth --client-id=<client-id> --client-secret=<client-secret> --base-domain=<issuer-uri>
```

Follow the instructions printed by `okta-kubectl-auth` to complete the setup process.

### `kubectl`

`okta-kubectl-auth` will output the required `kubectl` configuration after authentication.

### `apiserver`

`okta-kubectl-auth` will output the required apiserver configuration flags after authentication. For further details, refer to the Kubernetes documentation [here](https://kubernetes.io/docs/admin/authentication/#openid-connect-tokens).

### Add RBAC rules

For details on using RBAC resources in Kubernetes, refer to the Kubernetes documentation [here](https://kubernetes.io/docs/reference/access-authn-authz/rbac/). Note that if you configure the apiserver with the flags outputted by `okta-kubectl-auth`, the username and group attributes associated with request will be prepended with `okta:`.

## Other resources

- flow is based on [example-app from dex](https://github.com/coreos/dex/tree/master/cmd/example-app)
- Okta docs on getting [groups claim](https://developer.okta.com/docs/how-to/creating-token-with-groups-claim)
