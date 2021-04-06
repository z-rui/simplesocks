package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"io"
	"os"

	"github.com/andlabs/ui"
	_ "github.com/andlabs/ui/winmanifest"
	"github.com/z-rui/simplesocks"
	"github.com/z-rui/simplesocks/x25519"
)

const defaultTitle = "ss-client"
const configFilename = "ss-client.conf"

type config struct {
	ListenAddr string
	DialAddr string
	PeerPubkeyBase64 string
}

var (
	mainwin *ui.Window
	connectBtn *ui.Button
	listenEntry *ui.Entry
	remoteEntry *ui.Entry
	pubkeyEntry *ui.Entry
	logArea *logEntry
	connected bool
	listener net.Listener
)

type logEntry ui.MultilineEntry

func (a *logEntry) Write(stuff []byte) (int, error) {
	((*ui.MultilineEntry)(a)).Append(string(stuff))
	return len(stuff), nil
}

func onClosing(*ui.Window) bool {
	ui.Quit()
	return true
}

func onConnectClicked(*ui.Button) {
	if (!connected) {
		connect()
	} else {
		if listener != nil {
			listener.Close()
			listener = nil
		}
	}
}

func setupUI() {
	mainwin = ui.NewWindow(defaultTitle + " (inactive)", 320, 240, false)
	mainwin.OnClosing(onClosing)
	vbox := ui.NewVerticalBox()
	mainwin.SetChild(vbox)
	vbox.SetPadded(true)
	form := ui.NewForm()
	vbox.Append(form, false)
	listenEntry = ui.NewEntry()
	form.Append("Listen Address", listenEntry, false)
	remoteEntry = ui.NewEntry()
	form.Append("Remote Address", remoteEntry, false)
	pubkeyEntry = ui.NewEntry()
	form.Append("Public Key (base64-encoded)", pubkeyEntry, false)
	form.SetPadded(true)
	hbox := ui.NewHorizontalBox()
	vbox.Append(hbox, false)
	hbox.Append(ui.NewLabel(""), true)
	connectBtn = ui.NewButton("Connect")
	hbox.Append(connectBtn, false)
	connectBtn.OnClicked(onConnectClicked)
	logArea = (*logEntry)(ui.NewMultilineEntry())
	vbox.Append(logArea, true)
	log.SetOutput(logArea)
	loadConfig()
	mainwin.Show()
}

func connect() {
	var err error
	privateKey, err := x25519.NewPrivate(rand.Reader)
	if err != nil {
		ui.MsgBoxError(mainwin, "Internal error",
			"Cannot create private key: " + err.Error())
		return
	}
	peerPubkeyBase64 := pubkeyEntry.Text()
	var serverKey []byte
	serverKey, err = base64.StdEncoding.DecodeString(peerPubkeyBase64)
	if err != nil || len(serverKey) != x25519.PublicKeySize {
		ui.MsgBoxError(mainwin, "Error",
			"Bad public key.  Please ask the server administrator for a correct copy of public key (base64-encoded x25519).")
		return
	}
	listenAddr := listenEntry.Text()
	listener, err = net.Listen("tcp", listenAddr)
	if err != nil {
		ui.MsgBoxError(mainwin, "Error",
			"Cannot create TCP listener: " + err.Error())
		return
	}
	saveConfig()
	(*ui.MultilineEntry)(logArea).SetText("")
	log.Println("Listening on", listenAddr)
	dialAddr := remoteEntry.Text()
	go listenerThread(dialAddr, serverKey, privateKey)
	connected = true
	mainwin.SetTitle(defaultTitle + " (active)")
	connectBtn.SetText("Disconnect")
}

func disconnect() {
	connected = false
	mainwin.SetTitle(defaultTitle + " (inactive)")
	connectBtn.SetText("Connect")
}

func saveConfig() {
	cfg := config{
		ListenAddr: listenEntry.Text(),
		DialAddr: remoteEntry.Text(),
		PeerPubkeyBase64: pubkeyEntry.Text(),
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Print(err)
		return
	}
	os.WriteFile(configFilename, b, 0600)
}

func loadConfig() {
	b, err := os.ReadFile(configFilename)
	if err != nil {
		return
	}
	var cfg config
	err = json.Unmarshal(b, &cfg)
	if err != nil {
		log.Print(err)
		return
	}
	listenEntry.SetText(cfg.ListenAddr)
	remoteEntry.SetText(cfg.DialAddr)
	pubkeyEntry.SetText(cfg.PeerPubkeyBase64)
}

func main() {
	ui.Main(setupUI)
}

func listenerThread(dialAddr string, serverKey []byte, privateKey *x25519.PrivateKey) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Disconnected")
			listener = nil
			ui.QueueMain(disconnect)
			return
		}
		conn.(*net.TCPConn).SetNoDelay(false)
		go func(conn net.Conn) {
			defer conn.Close()
			peer, err := net.Dial("tcp", dialAddr)
			if err != nil {
				log.Println(err)
				return
			}
			defer peer.Close()
			peer, err = simplesocks.ClientConn(peer, privateKey, serverKey)
			if err != nil {
				log.Println("Handshake failed:", err)
				return
			}
			go io.Copy(conn, peer)
			io.Copy(peer, conn)
		}(conn)
	}
}
