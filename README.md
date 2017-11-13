[![Build Status](https://api.travis-ci.org/bjhaid/pam_hook.svg?branch=master)](https://travis-ci.org/bjhaid/pam_hook)

# pam_hook
A [PAM](http://www.linux-pam.org/) webhook endpoint that can be used with [Kubernetes](https://github.com/kubernetes/kubernetes).

### You should consider using this if:

- You currently use Unix users (for authentication) and groups (for authorization) and want a seamless migration of your existing authentication and authorization mechanisms.
- You use LDAP with caching set up (such as [SSSD](https://linux.die.net/man/8/sssd) or [nsscache](https://github.com/google/nsscache)), and would like to take advantage of it (`pam_hook`'s reliance on PAM gives you the existing cache for free).
- You want some tooling that you can fully automate from the command line.
- You are shopping for a Kubernetes authentication mechanism.

### Usage instructions

- Run `pam_hook` as below:

```
$> ./pam_hook -cert-file pamhook_cert.crt -key-file pamhook_key.crt -signing-key foo -bind-port 6443
```

Most of the flags can be configured also via environment variables, run for more options:

```
$> ./pam_hook -help
Usage of ./pam_hook:
  -alsologtostderr
        log to standard error as well as files
  -audience string
        Server that consumes the pam_hook endpoint, configurable via PAMHOOK_AUDIENCE environment variable
  -bind-address string
        Address to bind pam_hook to
  -bind-port string
         (default "8080")
  -cert-file string
        Absolute path to TLS CA certificate, configurable via PAMHOOK_TLS_CERT_FILE environment variable
  -key-file string
        Absolute path to TLS private key file, configurable via PAMHOOK_TLS_KEY_FILE environment variable
  -log_backtrace_at value
        when logging hits line file:N, emit a stack trace
  -log_dir string
        If non-empty, write log files in this directory
  -logtostderr
        log to standard error instead of files
  -server-name string
        The domain name for pam-hook, configurable via PAMHOOK_SERVERNAME environment variable
  -signing-key string
        Key for signing the token (required), configurable via PAMHOOK_SIGNING_KEY environment variable
  -stderrthreshold value
        logs at or above this threshold go to stderr
  -token-expires-in int
        Specifies how long the token is valid for in minutes, configurable via PAMHOOK_TOKEN_EXPIRES_IN environment variable (default 10)
  -v value
        log level for V logs
  -vmodule value
        comma-separated list of pattern=N settings for file-filtered logging
```

Command line flags override options configured via environment variables.

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

- Pass the path to the kubeconfig file to the `kube-apiserver` via the
`--authentication-token-webhook-config-file` flag (see the
[kubernetes documentation](https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication)
for more information).
- Get a token: `curl -u bjhaid --cacert pamhook_cert.crt https://pamhook:6443/token` 

### How it works

- The user hits the `/token` endpoint of `pamhook` and gets a token in exchange for their
OS username and password.  Here's an example request:

```bash
curl --cacert pamhook_cert.crt https://localhost:6443/token -u bjhaid
Enter host password for user 'bjhaid':
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIiLCJleHAiOjE0OTY2MTQwMzcsImlhdCI6MTQ5NjYxMjIzNywiaXNzIjoiIiwidXNlcm5hbWUiOiJiamhhaWQifQ.8GVZJJPa_GYxcsHy-WBMYlel_JSyoSLXnwnt4Bp_Nk0
```

- `pam_hook` authenticates the user against PAM.  If the username and password combination
is valid and the user's account or password has not expired, `pam_hook` returns with an
HMAC signed JWT token which contains the user's `username`, `issuer`, `issued_at`, `expiry` and
token audience.  Otherwise it returns with `Authentication failure`.

A successful response will look something like:
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIiLCJleHAiOjE0OTY2MTQwMzcsImlhdCI6MTQ5NjYxMjIzNywiaXNzIjoiIiwidXNlcm5hbWUiOiJiamhhaWQifQ.8GVZJJPa_GYxcsHy-WBMYlel_JSyoSLXnwnt4Bp_Nk0`

while a failure will simply be the string `"Authentication failure"`.

- The user makes Kubernetes API calls using the received token, and `kube-api-server` hits
the configured `pam_hook` endpoint.  If the token is valid and not expired `pam_hook`
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
- Kubernetes proceeds based on the value of `"authenticated"`.

### Healthcheck:

Health check route is `/heartbeat`


### Building:

```
$> docker build -t pam_hook .
$> docker run -v $PWD:/usr/local/go/src/github.com/bjhaid/pam_hook --rm pam_hook /bin/bash -c "cd /usr/local/go/src/github.com/bjhaid/pam_hook && go build"
```

### Testing:

```
$> docker run -v $PWD:/usr/local/go/src/github.com/bjhaid/pam_hook --rm pam_hook /bin/bash -c "cd /usr/local/go/src/github.com/bjhaid/pam_hook && go test"
```

### Running in Docker (Host Auth)

```
  docker run -it --rm  -e "PAMHOOK_SIGNING_KEY=foo" \
  -v /etc/nsswitch.conf:/etc/nsswitch.conf \
  -v /etc/group:/etc/group -v /etc/shadow:/etc/shadow \
  -v /etc/passwd:/etc/passwd -v /etc/pam.conf:/etc/pam.conf \
  -v /etc/pam.d/:/etc/pam.d -p 6443:6443 \
  -v $PWD/pamhook_cert.crt:/etc/ssl/certs/pamhook_cert.crt \
  -v $PWD/pamhook_key.crt:/etc/ssl/private/pamhook_key.crt \
  --cap-add IPC_LOCK \
  bjhaid/pam_hook:0.1.0 /usr/bin/pam_hook \
  -cert-file /etc/ssl/certs/pamhook_cert.crt \
  -key-file /etc/ssl/private/pamhook_key.crt \
  -bind-port 6443 -v 2

```

Make sure you change the certs to match your actual certificate path. On OSX,
you'll need to prepend the etc directories with `/private`, OSX also does not
have `/etc/nsswitch` and `/etc/pam.conf`

### License

[MIT](LICENSE)
