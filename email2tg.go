package main

import (
    "bytes"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/smtp"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/Azure/go-ntlmssp"
    "github.com/emersion/go-imap"
    "github.com/emersion/go-imap/client"
    "github.com/emersion/go-message"
    "github.com/emersion/go-message/mail"
    tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
    "github.com/jordan-wright/email"
    "github.com/k3a/html2text"
    "golang.org/x/net/html/charset"
)

type Config struct {
    TgToken         string `json:"tg_token"`
    MyTelegramID    int64  `json:"my_telegram_id"`
    EmailLogin      string `json:"email_login"`
    EmailUser       string `json:"email_user"`
    EmailPass       string `json:"email_pass"`
    ImapServer      string `json:"imap_server"`
    SmtpHost        string `json:"smtp_host"`
    SmtpPort        string `json:"smtp_port"`
    AuthType        string `json:"auth_type"`
    PollIntervalSec int    `json:"poll_interval_sec"`
    RetryDelaySec   int    `json:"retry_delay_sec"`
}

var (
    cfg               Config
    commonSentFolders = []string{"Sent Items", "SentMessages", "Отправленные", "Sent"}
    mediaBuffer       = make(map[string]*mediaGroup)
    bufferMutex       sync.Mutex
)

type mediaGroup struct {
    Messages []*tgbotapi.Message
    Timer    *time.Timer
}

func safeLog(level, format string, v ...interface{}) {
    msg := fmt.Sprintf(format, v...)
    if cfg.TgToken != "" {
	msg = strings.ReplaceAll(msg, cfg.TgToken, "[HIDDEN_TOKEN]")
    }
    log.Printf("[%s] %s", level, msg)
}

func loadConfig(path string) error {
    file, err := os.Open(path)
    if err != nil { return err }
    defer file.Close()
    return json.NewDecoder(file).Decode(&cfg)
}

// --- AUTH ---
type ntlmBase struct {
    user, password, domain string
    step                  int
}
func (n *ntlmBase) begin() (string, []byte, error) {
    n.step = 1
    msg, err := ntlmssp.NewNegotiateMessage(n.domain, "")
    return "NTLM", msg, err
}
type smtpNTLM struct{ ntlmBase }
func (a *smtpNTLM) Start(server *smtp.ServerInfo) (string, []byte, error) { return a.begin() }
func (a *smtpNTLM) Next(fromServer []byte, more bool) ([]byte, error) {
    if a.step == 1 {
	a.step = 2
	return ntlmssp.ProcessChallenge(fromServer, a.user, a.password, true)
    }
    return nil, nil
}
type imapNTLM struct{ ntlmBase }
func (a *imapNTLM) Start() (string, []byte, error) { return a.begin() }
func (a *imapNTLM) Next(challenge []byte) ([]byte, error) {
    if a.step == 1 {
	a.step = 2
	return ntlmssp.ProcessChallenge(challenge, a.user, a.password, true)
    }
    return nil, nil
}

func imapAuth(c *client.Client) error {
    if strings.ToLower(cfg.AuthType) == "ntlm" {
	p := strings.Split(cfg.EmailLogin, "\\")
	d, u := "", cfg.EmailLogin
	if len(p) > 1 { d, u = strings.ToUpper(p[0]), p[1] }
	return c.Authenticate(&imapNTLM{ntlmBase{user: u, password: cfg.EmailPass, domain: d}})
    }
    return c.Login(cfg.EmailUser, cfg.EmailPass)
}

func smtpSend(e *email.Email) error {
    addr := net.JoinHostPort(cfg.SmtpHost, cfg.SmtpPort)
    if strings.ToLower(cfg.AuthType) == "ntlm" {
	p := strings.Split(cfg.EmailLogin, "\\")
	d, u := "", cfg.EmailLogin
	if len(p) > 1 { d, u = strings.ToUpper(p[0]), p[1] }
	auth := &smtpNTLM{ntlmBase{user: u, password: cfg.EmailPass, domain: d}}
	return e.SendWithTLS(addr, auth, &tls.Config{ServerName: cfg.SmtpHost})
    }
    auth := smtp.PlainAuth("", cfg.EmailUser, cfg.EmailPass, cfg.SmtpHost)
    if cfg.SmtpPort == "465" {
	return e.SendWithTLS(addr, auth, &tls.Config{ServerName: cfg.SmtpHost})
    }
    return e.Send(addr, auth)
}

func main() {
    configPath := flag.String("config", "config.json", "Path to config")
    flag.Parse()
    if err := loadConfig(*configPath); err != nil {
	log.Fatalf("[FATAL] Config error: %v", err)
    }
    bot, err := tgbotapi.NewBotAPI(cfg.TgToken)
    if err != nil {
	cleanErr := strings.ReplaceAll(err.Error(), cfg.TgToken, "[HIDDEN_TOKEN]")
	log.Fatalf("[FATAL] Telegram Error: %s", cleanErr)
    }
    safeLog("SYSTEM", "Email2Tg запущен: %s (Метод: %s)", bot.Self.UserName, cfg.AuthType)
    go emailToTgLoop(bot)
    u := tgbotapi.NewUpdate(0)
    u.Timeout = 60
    updates := bot.GetUpdatesChan(u)
    for update := range updates {
	if update.Message == nil || update.Message.From.ID != cfg.MyTelegramID { continue }
	msg := update.Message
	if msg.IsCommand() {
	    switch msg.Command() {
	    case "start", "help": sendHelp(bot, msg.Chat.ID)
	    case "status": sendStatus(bot, msg.Chat.ID)
	    }
	    continue
	}
	if msg.MediaGroupID != "" {
	    bufferMutex.Lock()
	    group, exists := mediaBuffer[msg.MediaGroupID]
	    if !exists {
		group = &mediaGroup{Messages: []*tgbotapi.Message{msg}}
		group.Timer = time.AfterFunc(2*time.Second, func() { processMediaGroup(bot, msg.MediaGroupID) })
		mediaBuffer[msg.MediaGroupID] = group
	    } else {
		group.Messages = append(group.Messages, msg)
	    }
	    bufferMutex.Unlock()
	} else {
	    handleTgToEmail(bot, []*tgbotapi.Message{msg})
	}
    }
}

func sendHelp(bot *tgbotapi.BotAPI, chatID int64) {
    bot.Send(tgbotapi.NewMessage(chatID, "📧 <b>Email2Tg</b>\n1. Reply: ответ.\n2. email: текст: новое.\n/status: проверка."))
}

func sendStatus(bot *tgbotapi.BotAPI, chatID int64) {
    m, _ := bot.Send(tgbotapi.NewMessage(chatID, "⏳ Проверка..."))
    imapSt, smtpSt := "✅ OK", "✅ OK"
    c, err := client.DialTLS(cfg.ImapServer, &tls.Config{MinVersion: tls.VersionTLS12})
    if err != nil { imapSt = "❌ Сеть" } else {
	if err := imapAuth(c); err != nil { imapSt = "❌ Auth" }
	c.Logout()
    }
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.SmtpHost, cfg.SmtpPort), 5*time.Second)
    if err != nil { smtpSt = "❌ Порт" } else { conn.Close() }
    res := fmt.Sprintf("📊 <b>Статус</b>\n📥 IMAP: %s\n📤 SMTP: %s", imapSt, smtpSt)
    bot.Send(tgbotapi.NewEditMessageText(chatID, m.MessageID, res))
}

func handleTgToEmail(bot *tgbotapi.BotAPI, msgs []*tgbotapi.Message) {
    mainMsg := msgs[0]
    var targetEmail, targetSub, inReplyTo, bodyText string
    var bodyParts []string
    for _, m := range msgs {
	t := m.Text
	if t == "" { t = m.Caption }
	if t != "" { bodyParts = append(bodyParts, t) }
    }
    bodyText = strings.Join(bodyParts, "\n")
    if bodyText == "" && mainMsg.Document == nil && len(mainMsg.Photo) == 0 { return }
    if mainMsg.ReplyToMessage != nil {
	orig := mainMsg.ReplyToMessage.Text
	if orig == "" { orig = mainMsg.ReplyToMessage.Caption }
	targetEmail = parseField(orig, "📧 От:")
	targetSub = parseField(orig, "Тема:")
	for _, e := range mainMsg.ReplyToMessage.Entities {
	    if e.Type == "text_link" && strings.Contains(e.URL, "msgid:") {
		inReplyTo = strings.TrimPrefix(e.URL, "http://msgid:")
		break
	    }
	}
	bodyText = fmt.Sprintf("%s\n\n--- Original ---\n%s", bodyText, orig)
    }
    if targetEmail == "" {
	pts := strings.SplitN(bodyText, ":", 2)
	if len(pts) == 2 && strings.Contains(pts[0], "@") {
	    targetEmail, bodyText, targetSub = strings.TrimSpace(pts[0]), strings.TrimSpace(pts[1]), "New via Email2Tg"
	} else {
	    bot.Send(tgbotapi.NewMessage(mainMsg.Chat.ID, "⚠️ Reply или 'адрес: текст'"))
	    return
	}
    }
    if targetSub != "" && !strings.HasPrefix(strings.ToLower(targetSub), "re:") { targetSub = "Re: " + targetSub }
    e := email.NewEmail()
    e.From, e.To, e.Subject, e.Text = cfg.EmailUser, []string{targetEmail}, targetSub, []byte(bodyText)
    if inReplyTo != "" { e.Headers.Set("In-Reply-To", inReplyTo); e.Headers.Set("References", inReplyTo) }
    for _, m := range msgs {
	var fID, fName string
	if m.Document != nil { fID, fName = m.Document.FileID, m.Document.FileName
	} else if len(m.Photo) > 0 { fID, fName = m.Photo[len(m.Photo)-1].FileID, fmt.Sprintf("img_%d.jpg", time.Now().Unix()) }
	if fID != "" {
	    url, _ := bot.GetFileDirectURL(fID)
	    if resp, err := http.Get(url); err == nil {
		d, _ := io.ReadAll(resp.Body)
		e.Attach(bytes.NewReader(d), fName, "")
		resp.Body.Close()
	    }
	}
    }
    if err := smtpSend(e); err == nil {
	bot.Send(tgbotapi.NewMessage(mainMsg.Chat.ID, "✅ Отправлено"))
	go tryAppendSent(e)
    } else {
	bot.Send(tgbotapi.NewMessage(mainMsg.Chat.ID, "❌ SMTP: "+err.Error()))
    }
}

func tryAppendSent(e *email.Email) {
    c, err := client.DialTLS(cfg.ImapServer, &tls.Config{MinVersion: tls.VersionTLS12})
    if err != nil { return }
    defer c.Logout()
    if err := imapAuth(c); err != nil { return }
    raw, _ := e.Bytes()
    for _, f := range commonSentFolders {
	if err := c.Append(f, []string{imap.SeenFlag}, time.Now(), bytes.NewReader(raw)); err == nil { break }
    }
}

func emailToTgLoop(bot *tgbotapi.BotAPI) {
    for {
	if err := pollEmails(bot); err != nil {
	    safeLog("ERROR", "IMAP: %v. Retry in %d sec...", err, cfg.RetryDelaySec)
	    time.Sleep(time.Duration(cfg.RetryDelaySec) * time.Second)
	    continue
	}
	time.Sleep(time.Duration(cfg.PollIntervalSec) * time.Second)
    }
}

func pollEmails(bot *tgbotapi.BotAPI) error {
    c, err := client.DialTLS(cfg.ImapServer, &tls.Config{MinVersion: tls.VersionTLS12})
    if err != nil { return err }
    defer c.Logout()
    if err := imapAuth(c); err != nil { return err }
    if _, err := c.Select("INBOX", false); err != nil { return err }

    // ИСПРАВЛЕННЫЙ БЛОК ПОИСКА
    criteria := imap.NewSearchCriteria()
    criteria.WithoutFlags = []string{imap.SeenFlag}
    ids, err := c.Search(criteria)
    if err != nil || len(ids) == 0 { return err }

    seq := new(imap.SeqSet)
    seq.AddNum(ids...)
    msgs := make(chan *imap.Message, 10)
    go c.Fetch(seq, []imap.FetchItem{imap.FetchEnvelope, (&imap.BodySectionName{}).FetchItem()}, msgs)
    for m := range msgs { processEmailToTg(m, bot, c, seq) }
    return nil
}

func processEmailToTg(m *imap.Message, bot *tgbotapi.BotAPI, c *client.Client, seq *imap.SeqSet) {
    message.CharsetReader = charset.NewReaderLabel
    r, err := mail.CreateReader(m.GetBody(&imap.BodySectionName{}))
    if err != nil { return }
    var body string
    from := "Unknown"
    if len(m.Envelope.From) > 0 { from = m.Envelope.From[0].Address() }
    for {
	p, err := r.NextPart()
	if err == io.EOF { break }
	ct, disp := p.Header.Get("Content-Type"), p.Header.Get("Content-Disposition")
	b, _ := io.ReadAll(p.Body)
	if strings.Contains(strings.ToLower(disp), "attachment") {
	    bot.Send(tgbotapi.NewDocument(cfg.MyTelegramID, tgbotapi.FileBytes{Name: "file", Bytes: b}))
	} else if strings.HasPrefix(ct, "text/plain") { body = string(b)
	} else if strings.HasPrefix(ct, "text/html") && body == "" { body = html2text.HTML2Text(string(b)) }
    }
    txt := fmt.Sprintf("<a href=\"http://msgid:%s\"> </a>📧 <b>От:</b> %s\n<b>Тема:</b> %s\n\n%s", m.Envelope.MessageId, escapeHTML(from), escapeHTML(m.Envelope.Subject), escapeHTML(body))
    if len(txt) > 4000 { txt = txt[:4000] }
    msg := tgbotapi.NewMessage(cfg.MyTelegramID, txt)
    msg.ParseMode = "HTML"
    bot.Send(msg)
    c.Store(seq, imap.FormatFlagsOp(imap.AddFlags, true), []interface{}{imap.SeenFlag}, nil)
}

func processMediaGroup(bot *tgbotapi.BotAPI, id string) {
    bufferMutex.Lock()
    g, ok := mediaBuffer[id]
    if !ok { bufferMutex.Unlock(); return }
    delete(mediaBuffer, id)
    bufferMutex.Unlock()
    handleTgToEmail(bot, g.Messages)
}

func escapeHTML(s string) string {
    s = strings.ReplaceAll(s, "&", "&amp;"); s = strings.ReplaceAll(s, "<", "&lt;"); s = strings.ReplaceAll(s, ">", "&gt;")
    return s
}

func parseField(t, f string) string {
    for _, l := range strings.Split(t, "\n") {
	cl := strings.ReplaceAll(strings.ReplaceAll(l, "<b>", ""), "</b>", "")
	if strings.Contains(cl, f) {
	    pts := strings.SplitN(cl, f, 2)
	    if len(pts) < 2 { continue }
	    v := strings.TrimSpace(pts[1])
	    if strings.Contains(f, "От:") {
		if i := strings.LastIndex(v, "<"); i != -1 { v = v[i+1:] }
		if i := strings.Index(v, ">"); i != -1 { v = v[:i] }
	    }
	    return strings.TrimSpace(v)
	}
    }
    return ""
}
