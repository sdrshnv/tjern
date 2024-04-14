package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/timer"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/pbkdf2"
)

var (
	docStyle              = lipgloss.NewStyle().Margin(1, 2)
	focusedStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle           = focusedStyle.Copy()
	noStyle               = lipgloss.NewStyle()
	focusedLoginButton    = focusedStyle.Copy().Render("[ Login ]")
	blurredLoginButton    = blurredStyle.Copy().Render("[ Login ]")
	focusedRegisterButton = focusedStyle.Copy().Render("[ Register ]")
	blurredRegisterButton = blurredStyle.Copy().Render("[ Register ]")
	baseUrl               = "https://tjern-worker.tjern.workers.dev"
	client                = &http.Client{
		Timeout: 10 * time.Second,
	}
	timeFormat = time.RFC822
)

const errTimeout = time.Second * 2

type Config struct {
	BaseUrl string `json:"baseUrl"`
}

type EntryItem struct {
	encryptedContent string
	createdTs        time.Time
}

func (i EntryItem) Title() string       { return i.createdTs.Format(timeFormat) }
func (i EntryItem) Description() string { return i.encryptedContent }
func (i EntryItem) FilterValue() string { return i.createdTs.Format(timeFormat) }

type homePageModel struct {
	list list.Model
}

type loginPageModel struct {
	errTimer    timer.Model
	focusIdx    int
	loginInputs []textinput.Model
	errMessage  string
}

type entryPageKeyMap struct {
	Up    key.Binding
	Down  key.Binding
	Left  key.Binding
	Right key.Binding
	Help  key.Binding
	Back  key.Binding
}

func (k entryPageKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Back}
}

func (k entryPageKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right}, // first column
		{k.Help, k.Back},                // second column
	}
}

type entryPageModel struct {
	textarea textarea.Model
	keys     entryPageKeyMap
	help     help.Model

	err error
}

type model struct {
	windowHeight     int
	windowWidth      int
	onLoginScreen    bool
	jwt              string
	hexSalt          string
	onHomePage       bool
	onEntryPage      bool
	onReadEntryPage  bool
	readEntryContent string
	username         string
	loginPage        loginPageModel
	homePage         homePageModel
	entryPage        entryPageModel
	derivedKey       []byte
}

func initialModel() model {
	ta := textarea.New()
	ta.Focus()
	var keys = entryPageKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "move up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "move down"),
		),
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("←/h", "move left"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("→/l", "move right"),
		),
		Help: key.NewBinding(
			key.WithKeys("ctrl+h"),
			key.WithHelp("ctrl+h", "toggle help"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "save entry and go back"),
		),
	}
	m := model{
		onLoginScreen:    true,
		onHomePage:       false,
		onEntryPage:      false,
		onReadEntryPage:  false,
		readEntryContent: "",
		loginPage: loginPageModel{
			loginInputs: make([]textinput.Model, 2),
			errTimer:    timer.New(errTimeout),
		},
		homePage: homePageModel{
			list: list.New(make([]list.Item, 0), list.NewDefaultDelegate(), 0, 0),
		},
		entryPage: entryPageModel{
			textarea: ta,
			keys:     keys,
			help:     help.New(),
			err:      nil,
		},
	}

	additionalListBindings := []key.Binding{
		key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
		key.NewBinding(key.WithKeys("ctrl-n"), key.WithHelp("ctrl-n", "new")),
	}

	m.homePage.list.AdditionalShortHelpKeys = func() []key.Binding {
		return additionalListBindings
	}

	m.homePage.list.AdditionalFullHelpKeys = func() []key.Binding {
		return additionalListBindings
	}

	m.homePage.list.Title = "Entries"

	var t textinput.Model

	for i := range m.loginPage.loginInputs {
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
		m.loginPage.loginInputs[i] = t
	}
	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) setListSize() tea.Msg {
	return tea.WindowSizeMsg{Height: m.windowHeight, Width: m.windowWidth}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case timer.TickMsg:
		var cmd tea.Cmd
		m.loginPage.errTimer, cmd = m.loginPage.errTimer.Update(msg)
		return m, cmd
	case timer.TimeoutMsg:
		m.loginPage.errTimer = timer.New(errTimeout)
		m.loginPage.errMessage = ""
		return m, nil
	case tea.WindowSizeMsg:
		m.windowHeight = msg.Height
		m.windowWidth = msg.Width
		h, v := docStyle.GetFrameSize()
		m.entryPage.textarea.SetHeight(msg.Height - strings.Count(m.entryPage.help.View(m.entryPage.keys), "\n") - 1)
		m.entryPage.textarea.SetWidth(msg.Width)
		m.entryPage.help.Width = msg.Width
		m.homePage.list.SetSize(msg.Width-h, msg.Height-v)
	case RegisterMsg:
		if msg.IsSuccess {
			m.onLoginScreen = false
			m.onHomePage = true
			m.jwt = msg.Jwt
			m.hexSalt = msg.HexSalt
			m.username = msg.Username
			dk := pbkdf2.Key([]byte(msg.Password), []byte(msg.HexSalt), 4096, 32, sha512.New)
			m.derivedKey = dk
			entriesCmd := func() tea.Msg { return entries(m.jwt) }
			return m, tea.Sequence(entriesCmd, m.setListSize)
		} else {
			m.loginPage.errMessage = msg.Err
			return m, m.loginPage.errTimer.Init()
		}
	case LoginMsg:
		if msg.IsSuccess {
			m.onLoginScreen = false
			m.onHomePage = true
			m.jwt = msg.Jwt
			m.hexSalt = msg.HexSalt
			m.username = msg.Username
			dk := pbkdf2.Key([]byte(msg.Password), []byte(msg.HexSalt), 4096, 32, sha512.New)
			m.derivedKey = dk
			entriesCmd := func() tea.Msg { return entries(m.jwt) }
			return m, tea.Sequence(entriesCmd, m.setListSize)
		} else {
			m.loginPage.errMessage = msg.Err
			return m, m.loginPage.errTimer.Init()
		}
	case EntriesMsg:
		if msg.IsSuccess {
			items := make([]list.Item, len(msg.Entries))
			for i, e := range msg.Entries {
				items[i] = e
			}
			return m, tea.Batch(m.homePage.list.SetItems(items), m.setListSize)
		} else {
			return m, nil
		}
	}
	if m.onLoginScreen {

		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case tea.KeyCtrlC.String(), tea.KeyEsc.String():
				return m, tea.Quit
			case tea.KeyTab.String(), tea.KeyShiftTab.String(), tea.KeyEnter.String(), tea.KeyUp.String(), tea.KeyDown.String():
				s := msg.String()
				if s == tea.KeyEnter.String() && m.loginPage.focusIdx == len(m.loginPage.loginInputs) {
					return m, func() tea.Msg { return Login(m.loginPage.loginInputs[0].Value(), m.loginPage.loginInputs[1].Value()) }
				}
				if s == tea.KeyEnter.String() && m.loginPage.focusIdx == len(m.loginPage.loginInputs)+1 {
					return m, func() tea.Msg {
						return Register(m.loginPage.loginInputs[0].Value(), m.loginPage.loginInputs[1].Value())
					}
				}
				if s == tea.KeyUp.String() || s == tea.KeyShiftTab.String() {
					m.loginPage.focusIdx--
				} else {
					m.loginPage.focusIdx++
				}
				if m.loginPage.focusIdx > len(m.loginPage.loginInputs)+1 {
					m.loginPage.focusIdx = 0
				} else if m.loginPage.focusIdx < 0 {
					m.loginPage.focusIdx = len(m.loginPage.loginInputs) - 1
				}

				cmds := make([]tea.Cmd, len(m.loginPage.loginInputs))
				for i := 0; i < len(m.loginPage.loginInputs); i++ {
					if i == m.loginPage.focusIdx {
						cmds[i] = m.loginPage.loginInputs[i].Focus()
						m.loginPage.loginInputs[i].PromptStyle = focusedStyle
						m.loginPage.loginInputs[i].TextStyle = focusedStyle
						continue
					}
					m.loginPage.loginInputs[i].Blur()
					m.loginPage.loginInputs[i].PromptStyle = noStyle
					m.loginPage.loginInputs[i].TextStyle = noStyle
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
			case tea.KeyEnter.String():
				m.onHomePage = false
				m.onEntryPage = false
				m.onLoginScreen = false
				m.onReadEntryPage = true
				item := m.homePage.list.SelectedItem()
				entryItem, ok := item.(EntryItem)
				if !ok {
					return m, nil
				}
				plainContent, err := decrypt(entryItem.encryptedContent, m.derivedKey)
				if err != nil {
					return m, nil
				}
				m.readEntryContent = plainContent
				return m, nil
			case tea.KeyCtrlN.String():
				m.onHomePage = false
				m.onEntryPage = true
				m.onLoginScreen = false
				return m, nil
			case tea.KeyCtrlC.String():
				return m, tea.Quit
			}
		}
		var cmd tea.Cmd
		m.homePage.list, cmd = m.homePage.list.Update(msg)
		return m, cmd
	} else if m.onEntryPage {
		var cmds []tea.Cmd
		var cmd tea.Cmd
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch {
			case key.Matches(msg, m.entryPage.keys.Help):
				m.entryPage.help.ShowAll = !m.entryPage.help.ShowAll
				return m, nil
			case key.Matches(msg, m.entryPage.keys.Back):
				plainContent := m.entryPage.textarea.Value()
				m.onEntryPage = false
				m.onHomePage = true
				m.onLoginScreen = false
				m.entryPage.textarea.Reset()
				if len(strings.TrimSpace(plainContent)) == 0 {
					return m, nil
				}
				cipherContent, err := encrypt(plainContent, m.derivedKey)
				if err != nil {
					return m, func() tea.Msg { return SaveEntryMsg{Err: err} }
				}
				createdTs := time.Now()
				saveEntryCmd := func() tea.Msg { return saveEntry(cipherContent, m.jwt, createdTs.Format(timeFormat)) }
				updateListCmd := m.homePage.list.InsertItem(0, EntryItem{encryptedContent: cipherContent, createdTs: createdTs})
				return m, tea.Batch(saveEntryCmd, updateListCmd, m.setListSize)
			}

			switch msg.Type {
			case tea.KeyCtrlC:
				return m, tea.Quit
			default:
				if !m.entryPage.textarea.Focused() {
					cmd = m.entryPage.textarea.Focus()
					cmds = append(cmds, cmd)
				}
			}

		// We handle errors just like any other message
		default:
			return m, nil
		}

		m.entryPage.textarea, cmd = m.entryPage.textarea.Update(msg)
		cmds = append(cmds, cmd)
		return m, tea.Batch(cmds...)
	} else if m.onReadEntryPage {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.Type {
			case tea.KeyEsc:
				m.onHomePage = true
				m.onLoginScreen = false
				m.onEntryPage = false
				m.onReadEntryPage = false
				m.readEntryContent = ""
				return m, m.setListSize
			}
		}
		return m, nil
	} else {
		return m, nil
	}
}

func (m *model) updateLoginScreenInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.loginPage.loginInputs))

	for i := range m.loginPage.loginInputs {
		m.loginPage.loginInputs[i], cmds[i] = m.loginPage.loginInputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (m model) View() string {

	if m.onLoginScreen {

		var b strings.Builder
		for i := range m.loginPage.loginInputs {
			b.WriteString(m.loginPage.loginInputs[i].View())
			if i < len(m.loginPage.loginInputs)-1 {
				b.WriteRune('\n')
			}
		}

		loginButton := &blurredLoginButton
		if m.loginPage.focusIdx == len(m.loginPage.loginInputs) {
			loginButton = &focusedLoginButton
		}
		registerButton := &blurredRegisterButton
		if m.loginPage.focusIdx == len(m.loginPage.loginInputs)+1 {
			registerButton = &focusedRegisterButton
		}
		fmt.Fprintf(&b, "\n\n%s", *loginButton)
		fmt.Fprintf(&b, "\n\n%s\n\n", *registerButton)
		b.WriteString(m.loginPage.errMessage)

		return b.String()
	}
	if m.onHomePage {
		return docStyle.Render(m.homePage.list.View())
	}
	if m.onEntryPage {
		var b strings.Builder
		b.WriteString(m.entryPage.textarea.View())
		fmt.Fprintf(&b, "\n%s", m.entryPage.help.View(m.entryPage.keys))
		return b.String()
	}
	if m.onReadEntryPage {
		return m.readEntryContent
	}
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

	if _, err := tea.NewProgram(initialModel(), tea.WithAltScreen()).Run(); err != nil {
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

type EntriesMsg struct {
	Err       string
	IsSuccess bool
	Entries   []EntryItem
}

type SaveEntryMsg struct {
	Err error
}

func decrypt(cipherContent string, key []byte) (string, error) {
	cipherText, err := base64.RawStdEncoding.DecodeString(cipherContent)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}
	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return string(cipherText), nil
}

func encrypt(plainContent string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	cipherContent := make([]byte, aes.BlockSize+len(plainContent))
	iv := cipherContent[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherContent[aes.BlockSize:], []byte(plainContent))
	return base64.RawStdEncoding.EncodeToString(cipherContent), nil
}

func saveEntry(content string, jwt string, createdTs string) tea.Msg {
	data := map[string]string{
		"content":   content,
		"createdTs": createdTs,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return SaveEntryMsg{Err: err}
	}
	newEntryUrl := baseUrl + "/api/entries"
	req, err := http.NewRequest(http.MethodPost, newEntryUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return SaveEntryMsg{Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := client.Do(req)
	if err != nil {
		return SaveEntryMsg{Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SaveEntryMsg{Err: err}
	}
	if resp.StatusCode != http.StatusCreated {
		return SaveEntryMsg{Err: fmt.Errorf("error saving entry: %s", string(body[:]))}
	}
	return SaveEntryMsg{Err: nil}
}

func entries(jwt string) tea.Msg {
	req, err := http.NewRequest(http.MethodGet, baseUrl+"/api/entries", nil)
	if err != nil {
		return EntriesMsg{Err: err.Error(), IsSuccess: false}
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := client.Do(req)
	if err != nil {
		return EntriesMsg{Err: err.Error(), IsSuccess: false}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return EntriesMsg{Err: err.Error(), IsSuccess: false}
	}
	if resp.StatusCode != http.StatusOK {
		return EntriesMsg{Err: fmt.Sprintf("get entries error: %s", string(body[:])), IsSuccess: false}
	}
	type entry struct {
		Content   string `json:"content"`
		CreatedTs string `json:"createdTs"`
	}
	type listEntriesResp struct {
		Entries []entry `json:"entries"`
	}
	var listEntriesResponse listEntriesResp
	err = json.Unmarshal(body, &listEntriesResponse)
	if err != nil {
		return EntriesMsg{Err: err.Error(), IsSuccess: false}
	}
	entries := make([]EntryItem, len(listEntriesResponse.Entries))
	for i, e := range listEntriesResponse.Entries {
		t, err := time.Parse(timeFormat, e.CreatedTs)
		if err != nil {
			continue
		}
		eItem := EntryItem{encryptedContent: e.Content, createdTs: t}
		entries[i] = eItem
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
	return RegisterMsg{Err: "", IsSuccess: true, Jwt: registerResponse.Jwt, HexSalt: registerResponse.HexSalt, Username: username, Password: password}
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
	return LoginMsg{Err: "", IsSuccess: true, Jwt: loginResponse.Jwt, HexSalt: loginResponse.HexSalt, Username: username, Password: password}
}
