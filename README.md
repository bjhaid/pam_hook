[![Build Status](https://api.travis-ci.org/bjhaid/pam_hook.svg?branch=master)](https://travis-ci.org/bjhaid/pam_hook)

# pam_hook
`pam_hook` provides a pam webhook endpoint that can be used with kubernetes

### Who should use this?

- You currently use unix users (for authentication) and groups (for authorization) and want a seamless migration of your existing authentication and authorization mechanisms
- You use LDAP, have some caching set up (sssd, nsscache etc., if you don't have one set up you should seriously consider one) and will like to take advantage of the cache (pam_hook relies on PAM hence gets the existing cache for free).
- You want some tooling that you can fully automate from the command line
- You are shopping for a kubernetes authentication mechanism

### Usage instructions

- Run pam_hook as below:

`./pam_hook -cert-file pamhook_cert.crt -key-file pamhook_key.crt -signing-key foo -bind-port 6443`
for more options run: `./pam_hook -help`

- Create a kubeconfig file as below:
```
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /Users/bjhaid/ca.pem
    server: https://pamhook:6443/authenticate
  name: pamhook
users:
  - name: pamhook
    user:
      client-certificate: /Users/bjhaid/pamhook.pem
      client-key: /Users/bjhaid/pamhook.key
current-context: pamhook
contexts:
- context:
    cluster: pamhook
    user: pamhook
  name: pamhook
```

- Pass the path to the kubeconfig file to the kube-apiserver via the
--authentication-token-webhook-config-file flag see the
[kubernetes documentation](https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication)
for more information
Get a token curl -u bjhaid --cacert pamhook_cert.crt https://pamhook:6443/token 

### How it works

- The user hits the `/token` endpoint of `pamhook` and gets a token in exchange for their
OS username and password, example request:
```bash
curl --cacert pamhook_cert.crt https://localhost:6443/token -u bjhaid
Enter host password for user 'bjhaid':
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIiLCJleHAiOjE0OTY2MTQwMzcsImlhdCI6MTQ5NjYxMjIzNywiaXNzIjoiIiwidXNlcm5hbWUiOiJiamhhaWQifQ.8GVZJJPa_GYxcsHy-WBMYlel_JSyoSLXnwnt4Bp_Nk0
```
- `pam_hook` authenticates the user against pam, if the username and password combination
is valid and the user's account or password has not expired `pam_hook` returns with an
HMAC signed JWT token which contains the user's username, issuer, issued_at, expiry and
token audience. Otherwise it returns with `Authentication failure`, example success response:
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIiLCJleHAiOjE0OTY2MTQwMzcsImlhdCI6MTQ5NjYxMjIzNywiaXNzIjoiIiwidXNlcm5hbWUiOiJiamhhaWQifQ.8GVZJJPa_GYxcsHy-WBMYlel_JSyoSLXnwnt4Bp_Nk0`
example failure response:
`Authentication failure`
- The user makes kubernetes API calls with the received token used, kube-api-server hits
the configured `pam_hook` endpoint, if the token is valid and not expired `pam_hook`
responds with:
```json
{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "status": {
    "authenticated": true,
    "user": {
      "username": "bjhaid",
      "uid": "1000",
      "groups": [
        "bjhaid",
        "sudo"
      ]
    }
  }
}
```
However if the token is invalid or has expired `pam_hook` responds with:
```
{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "status": {
    "authenticated": false
  }
}
```
- Kubernetes proceeds based on the value of `"authenticated"`

### Building:

`docker build -t pam_hook .`

`docker run -v $PWD:/usr/local/go/src/github.com/bjhaid/pam_hook --rm pam_hook /bin/bash -c "cd /usr/local/go/src/github.com/bjhaid/pam_hook && go build"`

### Testing:

`docker run -v $PWD:/usr/local/go/src/github.com/bjhaid/pam_hook --rm pam_hook /bin/bash -c "cd /usr/local/go/src/github.com/bjhaid/pam_hook && go test"`

### Todo:
- [] Add Logging

### License

[MIT](LICENSE)
