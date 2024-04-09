package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	// "github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	docStyle     = lipgloss.NewStyle().Margin(1, 2)
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

type EntryItem struct {
	encryptedContent string
	createdTs        time.Time
}

func (i EntryItem) Title() string       { return i.createdTs.String() }
func (i EntryItem) Description() string { return i.encryptedContent }
func (i EntryItem) FilterValue() string { return i.createdTs.String() }

type homePageModel struct {
	focusIdx int
	list     list.Model
	listItems []list.Item
}

type model struct {
	focusIdx      int
	loginInputs   []textinput.Model
	loginErr      string
	registerErr   string
	onLoginScreen bool
	jwt           string
	hexSalt       string
	onHomePage    bool
	onEntryPage   bool
	username      string
	homePage      homePageModel
	// cursorMode cursor.Mode
}

func initialModel() model {
	m := model{
		loginInputs:   make([]textinput.Model, 2),
		onLoginScreen: true,
		onHomePage:    false,
		onEntryPage:   false,
		homePage: homePageModel{
			listItems:  make([]list.Item, 0),
			focusIdx: -1,
		},
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
		case RegisterMsg:
			if msg.IsSuccess {
				m.onLoginScreen = false
				m.onHomePage = true
				m.jwt = msg.Jwt
				m.hexSalt = msg.HexSalt
				m.username = msg.Username
				return m, func() tea.Msg { return entries(m.jwt) }
			} else {
				m.registerErr = msg.Err
			}
		case LoginMsg:
			if msg.IsSuccess {
				m.onLoginScreen = false
				m.onHomePage = true
				m.jwt = msg.Jwt
				m.hexSalt = msg.HexSalt
				m.username = msg.Username
				return m, func() tea.Msg { return entries(m.jwt) }
			} else {
				m.loginErr = msg.Err
			}
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
					return m, func() tea.Msg { return Register(m.loginInputs[0].Value(), m.loginInputs[1].Value()) }
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
		case EntriesMsg:
			if msg.IsSuccess {
				for _, e := range msg.Entries {
					m.homePage.listItems = append(m.homePage.listItems, e)
				}
				m.homePage.list = list.New(m.homePage.listItems, list.NewDefaultDelegate(), 0, 0)
				m.homePage.list.Title = "Entries"
				return m, nil
			} else {
				log.Println("failed to get entries")
				return m, nil
			}
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
		fmt.Fprintf(&b, "\n\n%s", *loginButton)
		b.WriteString(" " + m.loginErr + "\n")
		fmt.Fprintf(&b, "%s\n\n", *registerButton)
		b.WriteString(" " + m.registerErr + "\n")

		return b.String()
	}
	if m.onHomePage {
		var b strings.Builder
		newEntryButton := &blurredNewEntryButton
		if m.homePage.focusIdx == -1 {
			newEntryButton = &focusedNewEntryButton
		}
		fmt.Fprintf(&b, "\n\n%s\n\n", *newEntryButton)
		b.WriteString(docStyle.Render(m.homePage.list.View()))
		return b.String()
	}
	log.Println("on login screen: ", m.onLoginScreen, " on home page: ", m.onHomePage, " on entry page: ", m.onEntryPage)
	return "Unclear which page we're on!"
}

func main() {
	if len(os.Getenv("DEBUG")) > 0 {
		f, err := tea.LogToFile("debug.log", "debug")
		if err != nil {
			fmt.Println("fatal:", err)
			os.Exit(1)
		}
		defer f.Close()
	}
	if _, err := tea.NewProgram(initialModel()).Run(); err != nil {
		fmt.Printf("could not start program: %s\n", err)
		os.Exit(1)
	}
}

type LoginMsg struct {
	Err       string
	IsSuccess bool
	Jwt       string
	HexSalt   string
	Username  string
}

type RegisterMsg struct {
	Err       string
	IsSuccess bool
	Jwt       string
	HexSalt   string
	Username  string
}

type EntriesMsg struct {
	Err       string
	IsSuccess bool
	Entries   []EntryItem
}

func entries(jwt string) tea.Msg {
	req, err := http.NewRequest(http.MethodGet, baseUrl+"/api/entries", nil)
	if err != nil {
		log.Println("error creating list entries request ", err)
		return EntriesMsg{Err: err.Error(), IsSuccess: false}
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := client.Do(req)
	if err != nil {
		log.Println("error with get entries request", err)
		return EntriesMsg{Err: err.Error(), IsSuccess: false}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("get entries response error ", err)
		return EntriesMsg{Err: err.Error(), IsSuccess: false}
	}
	type entry struct {
		content   string `json:"content"`
		createdTs string `json:"createdTs"`
	}
	type listEntriesResp struct {
		Entries []entry `json:"entries"`
	}
	var listEntriesResponse listEntriesResp
	err = json.Unmarshal(body, &listEntriesResponse)
	if err != nil {
		log.Println("cannot unmarshal list entries response ", err)
		return EntriesMsg{Err: err.Error(), IsSuccess: false}
	}
	entries := make([]EntryItem, 0)
	for _, e := range listEntriesResponse.Entries {
		t, err := time.Parse(time.DateTime, e.createdTs)
		if err != nil {
			log.Println("error parsing datetime", err)
			continue
		}
		eItem := EntryItem{encryptedContent: e.content, createdTs: t}
		entries = append(entries, eItem)
	}
	return EntriesMsg{Err: "", IsSuccess: true, Entries: entries}
}

func Register(username string, password string) tea.Msg {
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
	return RegisterMsg{Err: "", IsSuccess: true, Jwt: registerResponse.Jwt, HexSalt: registerResponse.HexSalt, Username: username}
}

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
		Jwt     string `json:"jwt"`
		HexSalt string `json:"salt"`
	}
	var loginResponse loginResp
	err = json.Unmarshal(body, &loginResponse)
	if err != nil {
		return LoginMsg{Err: "Cannot unmarshal login response", IsSuccess: false}
	}
	return LoginMsg{Err: "", IsSuccess: true, Jwt: loginResponse.Jwt, HexSalt: loginResponse.HexSalt, Username: username}
}
