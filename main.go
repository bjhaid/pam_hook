package main

import (
	"encoding/json"
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/msteinert/pam"
	"io/ioutil"
	"net/http"
	"os/user"
	"runtime"
	"time"
)

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

func authenticateUser(username string, password string) error {
	tx, err := pam.StartFunc("", username, func(s pam.Style, msg string) (string, error) {
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

func createToken(username string, signingKey string) (string, error) {
	tokenExpiry := 10
	claims := jws.Claims{
		"username": username,
	}
	claims.SetAudience("https://foo.com")
	claims.SetIssuedAt(time.Now())
	claims.SetIssuer("https://pam-auth.com")
	claims.SetExpiration(time.Now().Add(time.Minute * time.Duration(tokenExpiry)))

	j := jws.NewJWT(claims, crypto.SigningMethodHS256)
	b, err := j.Serialize([]byte(signingKey))
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
		fmt.Println(err) // log this line
	}
	uS, err := NewUser(username)
	if err != nil {
		valid = false
		fmt.Println(err) // log this line
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

func authenticateHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	var a AuthRequest
	if err != nil {
		fmt.Fprintf(w, "invalid request")
		return
	}
	err = json.Unmarshal(body, &a)
	if err != nil {
		fmt.Fprintf(w, "invalid request")
		return
	}
	resp := createResponseFromToken(a.Spec.Token, "foo")
	fmt.Fprintf(w, "%s\n", resp)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	signingKey := "foo"
	if !ok {
		http.Error(w, "Supply username and password", http.StatusNotFound)
		return
	}
	if err := authenticateUser(username, password); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	b, err := createToken(username, signingKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s\n", b)
}

func main() {
	u, _ := user.Current()
	if u.Uid != "0" {
		panic("run pam_auth as root")
	}
	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/authenticate", authenticateHandler)
	http.ListenAndServe(":8080", nil)
}
