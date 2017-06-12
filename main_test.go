package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

var (
	expiry     = 1
	signingKey = "foo"
	audience   = "k8s.io"
	servername = "pamhook.com"
	config     = &Config{
		SigningKey:     &signingKey,
		TokenExpiresIn: &expiry,
		Audience:       &audience,
		ServerName:     &servername}
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

func TestAuthenticateHandler(t *testing.T) {
	token, err := createToken("foo", config)
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
	oldExpiry := config.TokenExpiresIn
	config.TokenExpiresIn = &expiry
	token, err := createToken("foo", config)
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
	config.TokenExpiresIn = oldExpiry
}

func TestAuthenticateHandlerInvalidUser(t *testing.T) {
	config.TokenExpiresIn = &expiry
	token, err := createToken("bar", config)
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
