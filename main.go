package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	baseUrl               = "http://localhost:8787"
)

type model struct {
	focusIdx      int
	inputs        []textinput.Model
	loginErr      string
	onLoginScreen bool
	// cursorMode cursor.Mode
}

func initialModel() model {
	m := model{
		inputs: make([]textinput.Model, 2),
	}

	var t textinput.Model

	for i := range m.inputs {
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
		m.inputs[i] = t
	}
	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case LoginMsg:
		if msg.IsSuccess {
			m.onLoginScreen = false
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
			if s == tea.KeyEnter.String() && m.focusIdx == len(m.inputs) {
				// TODO: send a request to BE to authenticate user or create new account if username doesn't already exist, on BE side, make sure to limit creations per ip

				return m, func() tea.Msg { return Login(m.inputs[0].Value(), m.inputs[1].Value()) }
			}
			if s == tea.KeyEnter.String() && m.focusIdx == len(m.inputs)+1 {
				// TODO: registration
				return m, nil
			}
			if s == tea.KeyUp.String() || s == tea.KeyShiftTab.String() {
				m.focusIdx--
			} else {
				m.focusIdx++
			}
			if m.focusIdx > len(m.inputs)+1 {
				m.focusIdx = 0
			} else if m.focusIdx < 0 {
				m.focusIdx = len(m.inputs) - 1
			}

			cmds := make([]tea.Cmd, len(m.inputs))
			for i := 0; i < len(m.inputs); i++ {
				if i == m.focusIdx {
					cmds[i] = m.inputs[i].Focus()
					m.inputs[i].PromptStyle = focusedStyle
					m.inputs[i].TextStyle = focusedStyle
					continue
				}
				m.inputs[i].Blur()
				m.inputs[i].PromptStyle = noStyle
				m.inputs[i].TextStyle = noStyle
			}

			return m, tea.Batch(cmds...)
		}
	}

	cmd := m.updateInputs(msg)
	return m, cmd
}

func (m *model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))

	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (m model) View() string {
	var b strings.Builder

	for i := range m.inputs {
		b.WriteString(m.inputs[i].View())
		if i < len(m.inputs)-1 {
			b.WriteRune('\n')
		}
	}

	loginButton := &blurredLoginButton
	if m.focusIdx == len(m.inputs) {
		loginButton = &focusedLoginButton
	}
	registerButton := &blurredRegisterButton
	if m.focusIdx == len(m.inputs)+1 {
		registerButton = &focusedRegisterButton
	}
	fmt.Fprintf(&b, "\n\n%s\n", *loginButton)
	fmt.Fprintf(&b, "%s\n\n", *registerButton)

	return b.String()
}

func main() {
	if _, err := tea.NewProgram(initialModel()).Run(); err != nil {
		fmt.Printf("could not start program: %s\n", err)
		os.Exit(1)
	}
}

const loginUrl = "fake.server"

type LoginMsg struct {
	Err       string
	IsSuccess bool
}

func Login(username string, password string) tea.Msg {
	c := &http.Client{
		Timeout: 10 * time.Second,
	}
	data := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return LoginMsg{Err: "Failed to marshal login data", IsSuccess: false}
	}
	resp, err := c.Post(loginUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return LoginMsg{Err: "Login failed", IsSuccess: false}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return LoginMsg{Err: "Login failed", IsSuccess: false}
	}
	// return successful login msg that sends us to screen
	return LoginMsg{Err: "", IsSuccess: true}
}
