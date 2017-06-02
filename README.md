# pam_auth

### How it works

It provides a user a token after authenticating them with PAM (i.e *nix authentication), the user supplies the token to k8s and k8s passes the token back to pam_auth with validates that the user has been authenticated and includes user groups in the response that can be used for authorization as described [here](https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication)

### Building:

Install the pam libraries and development files:

```
apt-get install libpam0g:amd64
apt-get install libpam0g-dev:amd64
```

```
go build
```

### Todo:
- [] Add SSL support
- [] Make bindaddress, port, signingKey, audience, tokenExpiry, and issuer configurable
- [] Add tests
