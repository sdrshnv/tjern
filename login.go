package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/timer"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/pbkdf2"
)

var (
	focusedLoginButton    = focusedStyle.Copy().Render("[ Login ]")
	blurredLoginButton    = blurredStyle.Copy().Render("[ Login ]")
	focusedRegisterButton = focusedStyle.Copy().Render("[ Register ]")
	blurredRegisterButton = blurredStyle.Copy().Render("[ Register ]")
)

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginPageModel struct {
	errTimer       timer.Model
	focusIdx       int
	loginInputs    []textinput.Model
	errMessage     string
	spinner        spinner.Model
	authenticating bool
}

type LoginMsg struct {
	Err       string
	IsSuccess bool
	Jwt       string
	HexSalt   string
	Username  string
	Password  string
}

type RegisterMsg struct {
	Err       string
	IsSuccess bool
	Jwt       string
	HexSalt   string
	Username  string
	Password  string
}

type SaveCredentialMsg struct {
	Err error
}

type AutoLoginMsg struct {
	Error error
}

func deriveKey(password string, salt string) []byte {
	return pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha512.New)
}

func readCredential() (Credential, error) {
	appDir, err := appDirPath()
	if err != nil {
		return Credential{}, err
	}
	jsonBytes, err := os.ReadFile(appDir + "/cred.json")
	if err != nil {
		return Credential{}, err
	}
	var cred Credential
	err = json.Unmarshal(jsonBytes, &cred)
	if err != nil {
		return Credential{}, err
	}
	if cred.Username == "" {
		return Credential{}, err
	}
	if cred.Password == "" {
		return Credential{}, err
	}
	return cred, nil
}

func autoLogin() tea.Msg {
	cred, err := readCredential()
	if err != nil {
		return AutoLoginMsg{Error: err}
	}
	return Login(cred.Username, cred.Password)
}

func saveCredential(c Credential) tea.Msg {
	appDir, err := appDirPath()
	if err != nil {
		return SaveCredentialMsg{Err: err}
	}
	credBytes, err := json.MarshalIndent(&c, "", "    ")
	if err != nil {
		return SaveCredentialMsg{Err: err}
	}
	err = os.WriteFile(appDir+"/cred.json", credBytes, os.ModePerm)
	if err != nil {
		return SaveCredentialMsg{Err: err}
	}
	return nil
}

func Login(username string, password string) tea.Msg {
	if len(username) == 0 {
		return LoginMsg{Err: "username cannot be empty"}
	}
	if len(password) == 0 {
		return LoginMsg{Err: "password cannot be empty"}
	}
	data := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return LoginMsg{Err: "Failed to marshal login data", IsSuccess: false}
	}
	loginUrl := baseUrl + "/api/login"
	resp, err := client.Post(loginUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return LoginMsg{Err: "Login failed", IsSuccess: false}
	}
	if resp.StatusCode != http.StatusOK {
		return LoginMsg{Err: "Login failed", IsSuccess: false}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return LoginMsg{Err: "Error reading login response body", IsSuccess: false}
	}
	type loginResp struct {
		Jwt     string `json:"jwt"`
		HexSalt string `json:"salt"`
	}
	var loginResponse loginResp
	err = json.Unmarshal(body, &loginResponse)
	if err != nil {
		return LoginMsg{Err: "Cannot unmarshal login response", IsSuccess: false}
	}
	return LoginMsg{Err: "", IsSuccess: true, Jwt: loginResponse.Jwt, HexSalt: loginResponse.HexSalt, Username: username, Password: password}
}

func Register(username string, password string) tea.Msg {
	if len(username) == 0 {
		return RegisterMsg{Err: "username cannot be empty"}
	}
	if len(password) == 0 {
		return RegisterMsg{Err: "password cannot be empty"}
	}
	data := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return RegisterMsg{Err: "Failed to marshal registration data, " + err.Error(), IsSuccess: false}
	}
	registerUrl := baseUrl + "/api/register"
	resp, err := client.Post(registerUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return RegisterMsg{Err: fmt.Sprintf("Registration failed: %s", err.Error()), IsSuccess: false}
	}
	if resp.StatusCode != http.StatusOK {
		return RegisterMsg{Err: "Registration failed", IsSuccess: false}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return RegisterMsg{Err: "Error reading from response body", IsSuccess: false}
	}
	type registerResp struct {
		Jwt     string `json:"jwt"`
		HexSalt string `json:"salt"`
	}
	var registerResponse registerResp
	err = json.Unmarshal(body, &registerResponse)
	if err != nil {
		return RegisterMsg{Err: "Cannot unmarshal registration response", IsSuccess: false}
	}
	return RegisterMsg{Err: "", IsSuccess: true, Jwt: registerResponse.Jwt, HexSalt: registerResponse.HexSalt, Username: username, Password: password}
}
