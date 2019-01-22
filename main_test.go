package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/SermoDigital/jose/jws"
)

var (
	expiry     = 10
	signingKey = "foo"
	audience   = "k8s.io"
	servername = "pamhook.com"
	pamServiceName = "passwd"
	config     = &Config{
		SigningKey:     &signingKey,
		TokenExpiresIn: expiry,
		Audience:       &audience,
		ServerName:     &servername,
		PAMServiceName: &pamServiceName,
	}
	userS = &User{
		Username: "foo",
		Uid:      "1000",
		Groups:   []string{"foo", "deployer", "admin"}}
	failureStatus   = &Status{Authenticated: false}
	status          = &Status{User: userS, Authenticated: true}
	successResponse = &Response{
		ApiVersion: "authentication.k8s.io/v1beta1",
		Kind:       "TokenReview",
		Status:     status}
	failureResponse = &Response{
		ApiVersion: "authentication.k8s.io/v1beta1",
		Kind:       "TokenReview",
		Status:     failureStatus}
	authRequest = AuthRequest{
		ApiVersion: "authentication.k8s.io/v1beta1",
		Kind:       "TokenReview"}
)

func init() {
	cmd := exec.Command("groupadd", "deployer")
	var out bytes.Buffer
	err := cmd.Run()
	cmd = exec.Command("groupadd", "admin")
	err = cmd.Run()
	cmd = exec.Command("useradd", "-p", "salrRVtmwT6Wg", "-G", "deployer,admin", "foo")
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	if err != nil {
		fmt.Println(out.String())
		fmt.Println(err)
	}
}

func TestNewConfig(t *testing.T) {
	os.Setenv("PAMHOOK_TOKEN_EXPIRES_IN", "5")
	os.Setenv("PAMHOOK_SIGNING_KEY", "foo")
	os.Setenv("PAMHOOK_AUDIENCE", "k8s.io")
	os.Setenv("PAMHOOK_SERVERNAME", "pamhook.io")
	os.Setenv("PAMHOOK_TLS_KEY_FILE", "/etc/ssl/private/pamhook.key")
	os.Setenv("PAMHOOK_TLS_CERT_FILE", "/etc/ssl/certs/pamhook.cert")
	os.Setenv("PAMHOOK_PAM_SERVICE_NAME", "passwd")

	nConfig := *newConfig()

	if nConfig.TokenExpiresIn != 5 {
		t.Errorf("Expected returned TokenExpiresIn to be 5 got %v", nConfig.TokenExpiresIn)
	}

	if *(nConfig.SigningKey) != "foo" {
		t.Errorf("Expected returned SigningKey to be 'foo' got %v", *(nConfig.SigningKey))
	}

	if *(nConfig.Audience) != "k8s.io" {
		t.Errorf("Expected returned Audience to be 5 got %v", *(nConfig.Audience))
	}

	if *(nConfig.ServerName) != "pamhook.io" {
		t.Errorf("Expected returned ServerName to be 'pamhook.io' got %v", *(nConfig.ServerName))
	}

	if *(nConfig.TlsKeyFile) != "/etc/ssl/private/pamhook.key" {
		t.Errorf("Expected returned TlsKeyFile to be '/etc/ssl/private/pamhook.key' got %v", *(nConfig.TlsKeyFile))
	}

	if *(nConfig.TlsCertFile) != "/etc/ssl/certs/pamhook.cert" {
		t.Errorf("Expected returned TlsCertFile to be '/etc/ssl/certs/pamhook.cert' got %v", *(nConfig.TlsCertFile))
	}

	if *(nConfig.PAMServiceName) != "passwd" {
		t.Errorf("Expected returned PAMServiceName to be 'passwd' got %v", *(nConfig.PAMServiceName))
	}
}

func TestLookupGroups(t *testing.T) {
	expected := []string{"foo", "deployer", "admin"}
	actual, err := lookupGroups("foo")
	if err != nil {
		t.Fatal(err)
	}

	if len(actual) != 3 {
		t.Errorf("Expected returned groups to be 3 got %v", len(actual))
	}

	for i := range actual {
		if actual[i] != expected[i] {
			t.Errorf("lookupGroups returned wrong groups: got %v want %v",
				actual, expected)
		}
	}
}

func TestLookupGroupsNonExistingUser(t *testing.T) {
	actual, err := lookupGroups("bar")
	if err == nil {
		t.Errorf("Expected to get an 'unknown user error'")
	}

	if len(actual) != 0 {
		t.Errorf("Expected returned groups to be 0 got %v", len(actual))
	}
}

func TestTokenHandlerHappyPath(t *testing.T) {
	req, err := http.NewRequest("GET", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(tokenHandler(config))
	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	// Check that the authorization header is set
	authHeader := rr.Result().Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		t.Errorf(
			"Authorization header is wrong: got '%s' want something like 'Bearer <token here>'",
			authHeader)
	}
}

func TestTokenHandlerOverrideExpiry(t *testing.T) {
	expectedExpiry := 3
	req, err := http.NewRequest("GET", fmt.Sprintf("/token?token-expires-in=%d",
		expectedExpiry), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(tokenHandler(config))
	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	buf, err := ioutil.ReadAll(rr.Body)

	if err != nil {
		t.Errorf("Failed reading response, due to: %s", err)
	}

	w, err := jws.ParseJWT(buf)

	if err != nil {
		t.Errorf("Failed parsing jwt, due to: %s", err)
	}

	configuredExpiry := int(w.Claims().Get("exp").(float64)) -
		int(w.Claims().Get("iat").(float64))
	if configuredExpiry != expectedExpiry*60 {
		t.Errorf("Expected token expiry to be: %d got: %d", expectedExpiry*60,
			configuredExpiry)
	}
}

func TestTokenOverrideBadExpiry(t *testing.T) {
	req, err := http.NewRequest("GET", "/token?token-expires-in=d", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(tokenHandler(config))
	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	buf, err := ioutil.ReadAll(rr.Body)
	buf = buf[:len(buf)-1] // remove newline

	if err != nil {
		t.Errorf("Failed reading response, due to: %s", err)
	}

	expected := "'d' is not a valid integer"
	if strings.Compare(string(buf), expected) != 0 {
		t.Errorf("'%s' != '%s'", string(buf), expected)
	}
}

func TestTokenOverrideCannotBeGreaterThanConfigured(t *testing.T) {
	expectedExpiry := 1000
	req, err := http.NewRequest("GET", fmt.Sprintf("/token?token-expires-in=%d",
		expectedExpiry), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(tokenHandler(config))
	handler.ServeHTTP(rr, req)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	buf, err := ioutil.ReadAll(rr.Body)
	buf = buf[:len(buf)-1] // remove newline

	if err != nil {
		t.Errorf("Failed reading response, due to: %s", err)
	}

	expected := "1000 is greater than the configured token-expiry"
	if strings.Compare(string(buf), expected) != 0 {
		t.Errorf("'%s' != '%s'", string(buf), expected)
	}
}

func TestTokenHandlerNoCredentials(t *testing.T) {
	req, err := http.NewRequest("GET", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(tokenHandler(config))
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusNotFound)
	}
	expected := "Supply username and password"
	actual := strings.TrimSpace(rr.Body.String())
	if actual != expected {
		t.Errorf("handler returned unexpected body: got {%v} want {%v}",
			rr.Body.String(), expected)
	}
}

func TestTokenHandlerWrongCredentials(t *testing.T) {
	req, err := http.NewRequest("GET", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic Zm9vOmJh")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(tokenHandler(config))
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}
	expected := "Authentication Failure"
	if strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got {%v} want {%v}",
			rr.Body.String(), expected)
	}
}

func TestHeartbeatHandler(t *testing.T) {
	req, _ := http.NewRequest("GET", "/heartbeat", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(heartbeatHandler())
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestAuthenticateHandler(t *testing.T) {
	token, err := createToken("foo", config, config.TokenExpiresIn)
	if err != nil {
		t.Fatal(err)
	}
	authRequest.Spec = &Spec{Token: token}
	reqBody, err := json.Marshal(authRequest)
	req, err := http.NewRequest("POST", "/authenticate", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(authenticateHandler(config))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	actual := &Response{}
	err = json.Unmarshal([]byte(rr.Body.String()), actual)
	if err != nil {
		t.Fatal(err)
	}

	if !(reflect.DeepEqual(*actual, *successResponse)) {
		t.Errorf("handler returned wrong response: got %v want %v",
			actual, successResponse)
	}
	authRequest.Spec = nil
}

func TestAuthenticateHandlerExpiredToken(t *testing.T) {
	expiry := -1
	token, err := createToken("foo", config, expiry)
	if err != nil {
		t.Fatal(err)
	}
	authRequest.Spec = &Spec{Token: token}
	reqBody, err := json.Marshal(authRequest)
	req, err := http.NewRequest("POST", "/authenticate", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(authenticateHandler(config))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	actual := &Response{}
	err = json.Unmarshal([]byte(rr.Body.String()), actual)
	if err != nil {
		t.Fatal(err)
	}

	if !(reflect.DeepEqual(*actual, *failureResponse)) {
		t.Errorf("handler returned wrong response: got %v want %v",
			actual, successResponse)
	}
	authRequest.Spec = nil
}

func TestAuthenticateHandlerInvalidUser(t *testing.T) {
	config.TokenExpiresIn = expiry
	token, err := createToken("bar", config, config.TokenExpiresIn)
	if err != nil {
		t.Fatal(err)
	}
	authRequest.Spec = &Spec{Token: token}
	reqBody, err := json.Marshal(authRequest)
	req, err := http.NewRequest("POST", "/authenticate", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(authenticateHandler(config))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	actual := &Response{}
	err = json.Unmarshal([]byte(rr.Body.String()), actual)
	if err != nil {
		t.Fatal(err)
	}

	if !(reflect.DeepEqual(*actual, *failureResponse)) {
		t.Errorf("handler returned wrong response: got %v want %v",
			actual, successResponse)
	}
	authRequest.Spec = nil
}
