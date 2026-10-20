package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

// walk visits root and all objects nested in the container types used by
// buildUI.
func walk(root fyne.CanvasObject, fn func(fyne.CanvasObject)) {
	if root == nil {
		return
	}
	fn(root)

	switch c := root.(type) {
	case *fyne.Container:
		for _, child := range c.Objects {
			walk(child, fn)
		}
	case *container.Scroll:
		walk(c.Content, fn)
	case *container.Split:
		walk(c.Leading, fn)
		walk(c.Trailing, fn)
	}
}

func collect(root fyne.CanvasObject) (entries []*widget.Entry, labels []*widget.Label, buttons []*widget.Button, selects []*widget.Select) {
	walk(root, func(o fyne.CanvasObject) {
		switch v := o.(type) {
		case *widget.Entry:
			entries = append(entries, v)
		case *widget.Label:
			labels = append(labels, v)
		case *widget.Button:
			buttons = append(buttons, v)
		case *widget.Select:
			selects = append(selects, v)
		}
	})
	return
}

func findButton(w fyne.Window, text string) *widget.Button {
	_, _, buttons, _ := collect(w.Content())
	for _, b := range buttons {
		if b.Text == text {
			return b
		}
	}
	return nil
}

func findEntryByPlaceHolder(w fyne.Window, placeholder string) *widget.Entry {
	entries, _, _, _ := collect(w.Content())
	for _, e := range entries {
		if e.PlaceHolder == placeholder {
			return e
		}
	}
	return nil
}

func TestURIToOSPath(t *testing.T) {
	cases := map[string]string{
		"file:///home/user/config.enc":     "/home/user/config.enc",
		"file:///home/user/my%20conf.enc":  "/home/user/my conf.enc",
		"file:///C:/Users/user/config.enc": "C:/Users/user/config.enc",
	}

	for raw, want := range cases {
		u, err := storage.ParseURI(raw)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", raw, err)
		}
		if got := uriToOSPath(u); got != want {
			t.Errorf("uriToOSPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestBuildUI ensures the window content can be constructed without panics.
func TestBuildUI(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	w := test.NewWindow(nil)
	defer w.Close()

	buildUI(w)

	if w.Content() == nil {
		t.Fatal("buildUI did not set any window content")
	}
}

// TestNoDatabaseConnectionFields verifies that the connection settings are not
// editable in the UI: only the "Connect & Test DB" button remains.
func TestNoDatabaseConnectionFields(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	w := test.NewWindow(nil)
	defer w.Close()
	buildUI(w)

	entries, labels, _, selects := collect(w.Content())

	forbiddenPlaceholders := []string{"Host", "Port", "User", "Database", "SSL"}
	for _, e := range entries {
		for _, forbidden := range forbiddenPlaceholders {
			if strings.Contains(e.PlaceHolder, forbidden) {
				t.Errorf("unexpected editable field with placeholder %q", e.PlaceHolder)
			}
		}
	}

	forbiddenLabels := []string{"PostgreSQL Connection", "Host/Proxy:", "Port:", "User:", "Password:", "Database:", "SSL Mode:"}
	for _, l := range labels {
		for _, forbidden := range forbiddenLabels {
			if l.Text == forbidden {
				t.Errorf("unexpected label %q in the UI", l.Text)
			}
		}
	}

	if len(selects) != 0 {
		t.Errorf("expected no select widgets, got %d", len(selects))
	}

	if findButton(w, "Connect & Test DB") == nil {
		t.Error(`"Connect & Test DB" button is missing`)
	}
}

// TestBrowseOpensFileDialog ensures that clicking "Browse..." does not crash.
// dialog.FileDialog.Resize dereferences its internal dialog, which only exists
// after Show, so resizing before showing panics.
func TestBrowseOpensFileDialog(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	w := test.NewWindow(nil)
	defer w.Close()
	buildUI(w)

	browseBtn := findButton(w, "Browse...")
	if browseBtn == nil {
		t.Fatal(`"Browse..." button not found in the UI`)
	}

	test.Tap(browseBtn)

	// The file dialog is added as an overlay on the window canvas.
	if len(w.Canvas().Overlays().List()) == 0 {
		t.Fatal("no overlay/dialog appeared after clicking Browse...")
	}
}

// TestConnectWithoutConfigShowsError verifies that the DB connection cannot be
// tested before a config file has been loaded.
func TestConnectWithoutConfigShowsError(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	w := test.NewWindow(nil)
	defer w.Close()
	buildUI(w)

	connectBtn := findButton(w, "Connect & Test DB")
	if connectBtn == nil {
		t.Fatal(`"Connect & Test DB" button not found in the UI`)
	}

	test.Tap(connectBtn)

	if len(w.Canvas().Overlays().List()) == 0 {
		t.Fatal("expected an error dialog telling the user to load a config file")
	}
}

// TestLoadConfigSetsDatabaseTarget drives the UI: select the encrypted fixture,
// enter its password, press "Load Config" and verify that the loaded target is
// reported in the status label.
func TestLoadConfigSetsDatabaseTarget(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	w := test.NewWindow(nil)
	defer w.Close()
	buildUI(w)

	pathEntry := findEntryByPlaceHolder(w, "Path to encrypted config file (*.enc)")
	passwordEntry := findEntryByPlaceHolder(w, "Password of the encrypted config file")
	if pathEntry == nil || passwordEntry == nil {
		t.Fatal("config file widgets not found in the UI")
	}
	loadBtn := findButton(w, "Load Config")
	if loadBtn == nil {
		t.Fatal(`"Load Config" button not found in the UI`)
	}

	pathEntry.SetText(filepath.Join("testdata", "db_config.enc"))
	passwordEntry.SetText(fixturePassword)
	test.Tap(loadBtn)

	// The decryption runs in a goroutine; the test driver executes fyne.Do
	// synchronously, so polling the status label is enough.
	status := waitForStatus(t, w)
	if status == "" {
		t.Fatal("config loading did not finish within 10s")
	}

	want := "Loaded db_config.enc - test_user@192.168.0.31:6543/testdb"
	if status != want {
		t.Fatalf("status = %q, want %q", status, want)
	}
}

// TestLoadConfigWrongPasswordShowsError verifies that a wrong password does not
// silently provide a database connection and reports a failure.
func TestLoadConfigWrongPasswordShowsError(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	w := test.NewWindow(nil)
	defer w.Close()
	buildUI(w)

	pathEntry := findEntryByPlaceHolder(w, "Path to encrypted config file (*.enc)")
	passwordEntry := findEntryByPlaceHolder(w, "Password of the encrypted config file")
	loadBtn := findButton(w, "Load Config")
	if pathEntry == nil || passwordEntry == nil || loadBtn == nil {
		t.Fatal("config widgets not found in the UI")
	}

	pathEntry.SetText(filepath.Join("testdata", "db_config.enc"))
	passwordEntry.SetText("wrong-password")
	test.Tap(loadBtn)

	status := waitForStatus(t, w)
	if status == "" {
		t.Fatal("no status shown for a wrong password within 10s")
	}
	if !strings.Contains(status, "failed") {
		t.Fatalf("status = %q, want a failure message", status)
	}
}

// waitForStatus polls the status label until config loading reports a result.
func waitForStatus(t *testing.T, w fyne.Window) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, labels, _, _ := collect(w.Content())
		for _, l := range labels {
			if strings.HasPrefix(l.Text, "Loaded ") || strings.Contains(l.Text, "failed") {
				return l.Text
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ""
}
