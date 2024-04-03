package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	// "github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	focusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle  = focusedStyle.Copy()
	noStyle      = lipgloss.NewStyle()
	// helpStyle     = blurredStyle.Copy()
	focusedLoginButton    = focusedStyle.Copy().Render("[ Login ]")
	blurredLoginButton    = blurredStyle.Copy().Render("[ Login ]")
	focusedRegisterButton = focusedStyle.Copy().Render("[ Register ]")
	blurredRegisterButton = blurredStyle.Copy().Render("[ Register ]")
	focusedNewEntryButton = focusedStyle.Copy().Render("[ New Entry ]")
	blurredNewEntryButton = blurredStyle.Copy().Render("[ New Entry ]")
	baseUrl               = "http://localhost:8787"
	client                = &http.Client{
		Timeout: 10 * time.Second,
	}
)

type model struct {
	focusIdx      int
	loginInputs   []textinput.Model
	loginErr      string
	onLoginScreen bool
	jwt           string
	onHomePage    bool
	// cursorMode cursor.Mode
}

func initialModel() model {
	m := model{
		loginInputs:   make([]textinput.Model, 2),
		onLoginScreen: true,
		onHomePage:    false,
	}

	var t textinput.Model

	for i := range m.loginInputs {
		t = textinput.New()
		t.Cursor.Style = cursorStyle
		t.CharLimit = 128
		switch i {
		case 0:
			t.Placeholder = "username"
			t.Focus()
			t.PromptStyle = focusedStyle
			t.TextStyle = focusedStyle
		case 1:
			t.Placeholder = "password"
			t.CharLimit = 128
			t.EchoMode = textinput.EchoPassword
			t.EchoCharacter = '•'
		}
		m.loginInputs[i] = t
	}
	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.onLoginScreen {

		switch msg := msg.(type) {
		case LoginMsg:
			if msg.IsSuccess {
				m.onLoginScreen = false
				m.onHomePage = true
				m.jwt = msg.Jwt
			} else {
				m.loginErr = msg.Err
			}
			return m, nil
		case tea.KeyMsg:
			switch msg.String() {
			case tea.KeyCtrlC.String(), tea.KeyEsc.String():
				return m, tea.Quit
			case tea.KeyTab.String(), tea.KeyShiftTab.String(), tea.KeyEnter.String(), tea.KeyUp.String(), tea.KeyDown.String():
				s := msg.String()
				if s == tea.KeyEnter.String() && m.focusIdx == len(m.loginInputs) {
					return m, func() tea.Msg { return Login(m.loginInputs[0].Value(), m.loginInputs[1].Value()) }
				}
				if s == tea.KeyEnter.String() && m.focusIdx == len(m.loginInputs)+1 {
					// TODO: registration
					return m, nil
				}
				if s == tea.KeyUp.String() || s == tea.KeyShiftTab.String() {
					m.focusIdx--
				} else {
					m.focusIdx++
				}
				if m.focusIdx > len(m.loginInputs)+1 {
					m.focusIdx = 0
				} else if m.focusIdx < 0 {
					m.focusIdx = len(m.loginInputs) - 1
				}

				cmds := make([]tea.Cmd, len(m.loginInputs))
				for i := 0; i < len(m.loginInputs); i++ {
					if i == m.focusIdx {
						cmds[i] = m.loginInputs[i].Focus()
						m.loginInputs[i].PromptStyle = focusedStyle
						m.loginInputs[i].TextStyle = focusedStyle
						continue
					}
					m.loginInputs[i].Blur()
					m.loginInputs[i].PromptStyle = noStyle
					m.loginInputs[i].TextStyle = noStyle
				}

				return m, tea.Batch(cmds...)
			}
		}

		cmd := m.updateLoginScreenInputs(msg)
		return m, cmd
	} else if m.onHomePage {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case tea.KeyCtrlC.String(), tea.KeyEsc.String():
				return m, tea.Quit
			default:
				return m, nil
			}
		default:
			return m, nil
		}
	} else {
		return m, nil
	}
}

func (m *model) updateLoginScreenInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.loginInputs))

	for i := range m.loginInputs {
		m.loginInputs[i], cmds[i] = m.loginInputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (m model) View() string {

	if m.onLoginScreen {

		var b strings.Builder
		for i := range m.loginInputs {
			b.WriteString(m.loginInputs[i].View())
			if i < len(m.loginInputs)-1 {
				b.WriteRune('\n')
			}
		}

		loginButton := &blurredLoginButton
		if m.focusIdx == len(m.loginInputs) {
			loginButton = &focusedLoginButton
		}
		registerButton := &blurredRegisterButton
		if m.focusIdx == len(m.loginInputs)+1 {
			registerButton = &focusedRegisterButton
		}
		fmt.Fprintf(&b, "\n\n%s\n", *loginButton)
		fmt.Fprintf(&b, "%s\n\n", *registerButton)

		return b.String()
	}
	if m.onHomePage {
		return "Logged in!"
	}
	return ""
}

func main() {
	if _, err := tea.NewProgram(initialModel()).Run(); err != nil {
		fmt.Printf("could not start program: %s\n", err)
		os.Exit(1)
	}
}

type LoginMsg struct {
	Err       string
	IsSuccess bool
	Jwt       string
}

// type RegisterMs struct {
// 	Err       string
// 	IsSuccess bool
// }

// func Register(username string, password string) tea.Msg {
// 	c := &http.Client{
// 		Timeout: 10 * time.Second,
// 	}
// 	data := map[string]string{
// 		"username": username,
// 		"password": password,
// 	}
// }

func Login(username string, password string) tea.Msg {
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
		Jwt string `json:"jwt"`
	}
	var loginResponse loginResp
	err = json.Unmarshal(body, &loginResponse)
	if err != nil {
		return LoginMsg{Err: "Cannot unmarshal login response", IsSuccess: false}
	}
	return LoginMsg{Err: "", IsSuccess: true, Jwt: loginResponse.Jwt}
}
