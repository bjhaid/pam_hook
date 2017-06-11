package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

var expiry = 1
var signingKey = "foo"
var audience = "k8s.io"
var servername = "pamhook.com"
var config = &Config{
	SigningKey:     &signingKey,
	TokenExpiresIn: &expiry,
	Audience:       &audience,
	ServerName:     &servername,
}

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
