package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/golang/glog"
	"github.com/msteinert/pam"
	"golang.org/x/sys/unix"
)

type Config struct {
	TokenExpiresIn int
	SigningKey     *string
	Audience       *string
	ServerName     *string
	BindAddress    *string
	BindPort       *string
	TlsKeyFile     *string
	TlsCertFile    *string
	DisableMlock   *bool
	PAMServiceName *string
}

type User struct {
	Username string   `json:"username"`
	Uid      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

type Status struct {
	Authenticated bool  `json:"authenticated"`
	User          *User `json:"user,omitempty"`
}

type Response struct {
	ApiVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Status     *Status `json:"status"`
}

type Spec struct {
	Token string `json:"token"`
}

type AuthRequest struct {
	ApiVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       *Spec  `json:"spec"`
}

func newConfig() *Config {
	c := &Config{}
	empty := ""
	port := "8080" //default port
	c.BindAddress = &empty
	c.BindPort = &port
	tokenExpiry, err := strconv.Atoi(os.Getenv("PAMHOOK_TOKEN_EXPIRES_IN"))
	if err != nil {
		tokenExpiry = 10 //default token expiry
	}
	c.TokenExpiresIn = tokenExpiry
	signingKey := os.Getenv("PAMHOOK_SIGNING_KEY")
	c.SigningKey = &signingKey
	audience := os.Getenv("PAMHOOK_AUDIENCE")
	c.Audience = &audience
	serverName := os.Getenv("PAMHOOK_SERVERNAME")
	c.ServerName = &serverName
	tlsKeyFile := os.Getenv("PAMHOOK_TLS_KEY_FILE")
	c.TlsKeyFile = &tlsKeyFile
	tlsCertFile := os.Getenv("PAMHOOK_TLS_CERT_FILE")
	c.TlsCertFile = &tlsCertFile
	pamServiceName := os.Getenv("PAMHOOK_PAM_SERVICE_NAME")
	c.PAMServiceName = &pamServiceName
	// Have to take a pointer so we need a new var.
	disableMlock := false
	c.DisableMlock = &disableMlock
	return c
}

func lookupGroups(username string) ([]string, error) {
	userS, err := user.Lookup(username)
	if err != nil {
		return []string{}, err
	}
	groups, err := userS.GroupIds()
	if err != nil {
		return []string{}, err
	}
	for i, group := range groups {
		group, err := user.LookupGroupId(group)
		if err == nil {
			groups[i] = group.Name
		}
	}
	return groups, nil
}

func NewUser(username string) (*User, error) {
	userStruct := User{}
	userS, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	groups, err := lookupGroups(username)
	if err != nil {
		return nil, err
	}
	userStruct.Username = userS.Username
	userStruct.Uid = userS.Uid
	userStruct.Groups = groups
	return &userStruct, nil
}

func NewStatus(userS *User, authenticated bool) *Status {
	status := Status{}
	status.Authenticated = authenticated
	status.User = userS
	return &status
}

func NewResponse(status *Status) *Response {
	response := Response{}
	response.ApiVersion = "authentication.k8s.io/v1beta1"
	response.Kind = "TokenReview"
	response.Status = status
	return &response
}

func userNameFromToken(token string, signingKey string) (string, error) {
	w, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return "", err
	}
	username := w.Claims().Get("username")
	if err := w.Validate([]byte(signingKey), crypto.SigningMethodHS256); err != nil {
		return "", err
	}
	return username.(string), nil
}

func authenticateUser(pamServiceName *string, username string, password string) error {
	glog.V(3).Infof("Received request from user: %s", username)
	tx, err := pam.StartFunc(*pamServiceName, username, func(s pam.Style, msg string) (string, error) {
		return password, nil
	})
	if err != nil {
		return err
	}
	err = tx.Authenticate(0)
	if err != nil {
		return err
	}
	err = tx.AcctMgmt(pam.Silent)
	if err != nil {
		return err
	}
	runtime.GC()
	return nil
}

func createToken(username string, c *Config, tokenExpiresIn int) (string,
	error) {
	claims := jws.Claims{
		"username": username,
	}
	now := time.Now().UTC()
	claims.SetAudience(*c.Audience)
	claims.SetIssuedAt(now)
	claims.SetIssuer(*c.ServerName)
	claims.SetExpiration(now.Add(time.Minute *
		time.Duration(tokenExpiresIn)))

	j := jws.NewJWT(claims, crypto.SigningMethodHS256)
	b, err := j.Serialize([]byte(*c.SigningKey))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func createResponseFromToken(token string, signingKey string) []byte {
	username, err := userNameFromToken(token, signingKey)
	valid := true
	if err != nil {
		valid = false
		glog.Errorf("Token supplied is invalid due to: %s", err)
	}
	uS, err := NewUser(username)
	if err != nil {
		valid = false
		glog.Errorf("The user: %s details cannot be retrieved due to: %s", username, err)
	}
	status := NewStatus(uS, valid)
	response := NewResponse(status)
	json, err := json.Marshal(response)
	if err == nil {
		return json
	} else {
		return []byte("")
	}
}

func heartbeatHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		glog.V(2).Infof("%s %s: %s, %d", r.Method, r.URL.Path, r.UserAgent(), status)
		fmt.Fprintf(w, "ok\n")
	}
}

func authenticateHandler(c *Config) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		status := http.StatusOK
		glog.V(2).Infof("%s %s: %s, %d", r.Method, r.URL.Path, r.UserAgent(), status)
		var a AuthRequest
		if err != nil {
			fmt.Fprintln(w, "invalid request")
			return
		}
		err = json.Unmarshal(body, &a)
		if err != nil {
			fmt.Fprintln(w, "invalid request")
			return
		}
		resp := createResponseFromToken(a.Spec.Token, *c.SigningKey)
		fmt.Fprintf(w, "%s\n", resp)
	}
}

func tokenHandler(c *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		tokenExpiresIn := c.TokenExpiresIn
		if v := r.URL.Query().Get("token-expires-in"); v != "" {
			if t, err := strconv.Atoi(v); err != nil {
				glog.Errorf("Got a non int token expiry: %s", v)
				http.Error(w, fmt.Sprintf("'%s' is not a valid integer", v),
					http.StatusBadRequest)
				return
			} else {
				if t > tokenExpiresIn {
					glog.V(2).Infof("Ignoring token expiry %d, which is greater than"+
						"configured token expiry: ", tokenExpiresIn)
					http.Error(w, fmt.Sprintf("%d is greater than the configured"+
						" token-expiry", t), http.StatusBadRequest)
					return
				} else {
					tokenExpiresIn = t
					glog.V(3).Infof("Overriding configured token with: %d", tokenExpiresIn)
				}
			}
		}
		status := http.StatusOK
		if !ok {
			status = http.StatusNotFound
			glog.V(2).Infof("%s %s: %s, %d", r.Method, r.URL.Path, r.UserAgent(), status)
			http.Error(w, "Supply username and password", http.StatusNotFound)
			return
		}
		if err := authenticateUser(c.PAMServiceName, username, password); err != nil {
			status = http.StatusForbidden
			glog.V(2).Infof("%s %s: %s, %s, %d", r.Method, r.URL.Path, r.UserAgent(),
				r.URL.Query(), status)
			glog.Errorf("Authenticating user failed with: %s", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		b, err := createToken(username, c, tokenExpiresIn)
		if err != nil {
			status = http.StatusInternalServerError
			glog.V(2).Infof("%s %s: %s, %v, %d", r.Method, r.URL.Path, r.UserAgent(),
				r.URL.Query(), status)
			glog.Errorf("%s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		glog.V(2).Infof("%s %s: %s, %v, %d", r.Method, r.URL.Path, r.UserAgent(),
			r.URL.Query(), status)
		w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", b))
		fmt.Fprintf(w, "%s\n", b)
	}
}

func main() {
	u, _ := user.Current()
	config := newConfig()
	flag.IntVar(&config.TokenExpiresIn, "token-expires-in", config.TokenExpiresIn, "Specifies how long the token is valid for in minutes, configurable via PAMHOOK_TOKEN_EXPIRES_IN environment variable")
	flag.StringVar(config.SigningKey, "signing-key", *config.SigningKey, "Key for signing the token (required), configurable via PAMHOOK_SIGNING_KEY environment variable")
	flag.StringVar(config.Audience, "audience", *config.Audience, "Server that consumes the pam_hook endpoint, configurable via PAMHOOK_AUDIENCE environment variable")
	flag.StringVar(config.ServerName, "server-name", *config.ServerName, "The domain name for pam-hook, configurable via PAMHOOK_SERVERNAME environment variable")
	flag.StringVar(config.BindAddress, "bind-address", *config.BindAddress, "Address to bind pam_hook to")
	flag.StringVar(config.BindPort, "bind-port", *config.BindPort, "")
	flag.StringVar(config.TlsKeyFile, "key-file", *config.TlsKeyFile, "Absolute path to TLS private key file, configurable via PAMHOOK_TLS_KEY_FILE environment variable")
	flag.StringVar(config.TlsCertFile, "cert-file", *config.TlsCertFile, "Absolute path to TLS CA certificate, configurable via PAMHOOK_TLS_CERT_FILE environment variable")
	flag.StringVar(config.PAMServiceName, "pam-service-name", *config.PAMServiceName, "PAM service name against which to perform user authentication during token creation, configurable via PAMHOOK_PAM_SERVICE_NAME environment variable")
	flag.BoolVar(config.DisableMlock, "disable-mlock", *config.DisableMlock, "Disable calling sys mlock")
	flag.Set("logtostderr", "true")
	flag.Set("v", "2")
	flag.Parse()

	defer glog.Flush()
	if u.Uid != "0" {
		fmt.Fprintln(os.Stderr, "run pam_hook as root")
		os.Exit(1)
	}
	if *config.TlsKeyFile == "" {
		fmt.Fprintln(os.Stderr, "Please provide a path to a tls private key file")
		os.Exit(1)
	}
	if *config.TlsCertFile == "" {
		fmt.Fprintln(os.Stderr, "Please provide a path to a tls CA certificate")
		os.Exit(1)
	}
	if *(config.SigningKey) == "" {
		fmt.Fprintln(os.Stderr, "Please provide a signing key")
		os.Exit(1)
	}
	if config.TokenExpiresIn == 0 {
		fmt.Fprintln(os.Stderr, "Please provide a token expiry")
		os.Exit(1)
	}
	if !*config.DisableMlock {
		if err := unix.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to lock memory: %v", err)
			os.Exit(1)
		}
	}
	http.HandleFunc("/heartbeat", heartbeatHandler())
	http.HandleFunc("/token", tokenHandler(config))
	http.HandleFunc("/authenticate", authenticateHandler(config))
	bind := *config.BindAddress + ":" + *config.BindPort
	glog.Infof("Starting pam_hook on %s", bind)
	err := http.ListenAndServeTLS(bind, *config.TlsCertFile, *config.TlsKeyFile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start pamhook due to: %s", err)
		os.Exit(1)
	}
}
