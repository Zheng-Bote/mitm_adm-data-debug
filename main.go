package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"github.com/jackc/pgx/v5"
)

// prefConfigPath remembers the last selected encrypted config file.
const prefConfigPath = "configPath"

// uriToOSPath converts a file URI chosen in the file dialog into a path usable
// with os.Open. Fyne reports local Windows files as "/C:/dir/config.enc", where
// the leading slash is not part of the OS path.
func uriToOSPath(u fyne.URI) string {
	p := u.Path()
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' && isASCIILetter(p[1]) {
		return p[1:]
	}
	return p
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func main() {
	// A unique app ID is required for the Preferences API used to remember the
	// last selected config file.
	a := app.NewWithID("net.hase-zheng.mitm-adm-data-debug")
	w := a.NewWindow("MitM Admin Data Decryptor")
	w.Resize(fyne.NewSize(960, 820))

	label := widget.NewLabel("Verifying Identity...")
	w.SetContent(container.NewCenter(label))

	go func() {
		verified, err := verifyWindowsHello(w)
		if err != nil || !verified {
			fmt.Println("Authentication failed:", err)
			os.Exit(1)
		}

		fyne.Do(func() { buildUI(w) })
	}()

	w.ShowAndRun()
}

func buildUI(w fyne.Window) {
	// The database connection is taken exclusively from the encrypted config
	// file; there are no editable connection fields.
	target := &dbTarget{}

	configPathEntry := widget.NewEntry()
	configPathEntry.SetPlaceHolder("Path to encrypted config file (*.enc)")
	configPasswordEntry := widget.NewPasswordEntry()
	configPasswordEntry.SetPlaceHolder("Password of the encrypted config file")
	configStatus := widget.NewLabel("No config file loaded - load an encrypted config file to enable the DB connection.")
	configStatus.Wrapping = fyne.TextWrapWord

	loadConfig := func() {
		path := strings.TrimSpace(configPathEntry.Text)
		if path == "" {
			dialog.ShowError(errors.New("Please select an encrypted config file first."), w)
			return
		}
		password := configPasswordEntry.Text
		if password == "" {
			dialog.ShowError(errors.New("Please enter the password of the encrypted config file."), w)
			return
		}

		configStatus.SetText("Decrypting " + filepath.Base(path) + " ...")
		go func() {
			cfg, err := LoadEncryptedDBConfig(path, password)
			fyne.Do(func() {
				if err != nil {
					target.clear()
					configStatus.SetText("Loading " + filepath.Base(path) + " failed - no database connection available.")
					dialog.ShowError(err, w)
					return
				}

				target.set(cfg)
				configStatus.SetText(fmt.Sprintf("Loaded %s", filepath.Base(path)))
				fyne.CurrentApp().Preferences().SetString(prefConfigPath, path)
			})
		}()
	}

	browseBtn := widget.NewButton("Browse...", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()
			configPathEntry.SetText(uriToOSPath(reader.URI()))
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".enc"}))
		if dir := filepath.Dir(strings.TrimSpace(configPathEntry.Text)); dir != "." && dir != "" {
			if lister, err := storage.ListerForURI(storage.NewFileURI(dir)); err == nil {
				fd.SetLocation(lister)
			}
		}
		// Do not call fd.Resize here: FileDialog.Resize dereferences the internal
		// dialog, which only exists after Show, and an explicitly enlarged
		// dialog overflows the parent window because the size is not clamped.
		fd.Show()
	})

	loadBtn := widget.NewButton("Load Config", loadConfig)
	loadBtn.Importance = widget.HighImportance
	configPasswordEntry.OnSubmitted = func(string) { loadConfig() }

	if lastPath := fyne.CurrentApp().Preferences().String(prefConfigPath); lastPath != "" {
		configPathEntry.SetText(lastPath)
	}

	// dsn returns the connection string of the loaded config file.
	dsn := func() (string, error) { return target.connString() }

	masterkeyEntry := widget.NewPasswordEntry()

	jsonInput := widget.NewMultiLineEntry()
	jsonInput.SetPlaceHolder(`{"SSNValue": {"nonce": "...", "ciphertext": "..."}}`)

	jsonOutput := widget.NewMultiLineEntry()

	var connectBtn *widget.Button
	connectBtn = widget.NewButton("Connect & Test DB", func() {
		dsn, err := dsn()
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		connectBtn.Disable()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				fyne.Do(func() {
					connectBtn.Enable()
					dialog.ShowError(fmt.Errorf("DB connection failed:\n%v", err), w)
				})
				return
			}
			conn.Close(ctx)

			fyne.Do(func() {
				connectBtn.Enable()
				dialog.ShowInformation("Success", "Successfully connected to PostgreSQL DB!", w)
			})
		}()
	})

	decryptBtn := widget.NewButton("Decrypt", func() {
		mkBase64 := masterkeyEntry.Text

		mk, err := base64.StdEncoding.DecodeString(mkBase64)
		if err != nil || len(mk) == 0 {
			mk = []byte(mkBase64)
		}

		dsn, err := dsn()
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		inputTxt := strings.TrimSpace(jsonInput.Text)
		if inputTxt == "" {
			return
		}

		var parsed interface{}
		if err := json.Unmarshal([]byte(inputTxt), &parsed); err != nil {
			wrapped := "{" + inputTxt + "}"
			if err2 := json.Unmarshal([]byte(wrapped), &parsed); err2 != nil {
				dialog.ShowError(fmt.Errorf("Invalid JSON input:\n%v", err), w)
				return
			}
		}

		jsonOutput.SetText("Decrypting...")

		go func() {
			processed, err := processJSON(parsed, dsn, mk)
			if err != nil {
				fyne.Do(func() { jsonOutput.SetText(fmt.Sprintf("Error: %v", err)) })
				return
			}

			outBytes, _ := json.MarshalIndent(processed, "", "  ")
			fyne.Do(func() { jsonOutput.SetText(string(outBytes)) })
		}()
	})

	form := container.NewVBox(
		widget.NewLabelWithStyle("Encrypted Config File", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, browseBtn, configPathEntry),
		container.NewBorder(nil, nil, nil, loadBtn, configPasswordEntry),
		configStatus,
		connectBtn,
	)

	inputScroll := container.NewScroll(jsonInput)
	inputScroll.SetMinSize(fyne.NewSize(0, 160))

	outputScroll := container.NewScroll(jsonOutput)
	outputScroll.SetMinSize(fyne.NewSize(0, 180))

	inputPane := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Masterkey (Base64 or Raw):"),
			masterkeyEntry,
			widget.NewLabel("Encrypted JSON Snippet:"),
		),
		container.NewPadded(decryptBtn),
		nil,
		nil,
		inputScroll,
	)

	content := container.NewBorder(
		form,
		nil,
		nil,
		nil,
		container.NewVSplit(
			inputPane,
			container.NewBorder(widget.NewLabel("Decrypted JSON Output:"), nil, nil, nil, outputScroll),
		),
	)

	w.SetContent(content)
}

func processJSON(input interface{}, connString string, mk []byte) (interface{}, error) {
	switch v := input.(type) {
	case map[string]interface{}:
		if nonceObj, hasNonce := v["nonce"]; hasNonce {
			if cipherObj, hasCipher := v["ciphertext"]; hasCipher {
				nonceStr, ok1 := nonceObj.(string)
				cipherStr, ok2 := cipherObj.(string)
				if ok1 && ok2 {
					decrypted, err := decryptPayload(context.Background(), connString, mk, nonceStr, cipherStr)
					if err != nil {
						return nil, err
					}
					var innerJSON interface{}
					if err := json.Unmarshal([]byte(decrypted), &innerJSON); err == nil {
						return innerJSON, nil
					}
					return decrypted, nil
				}
			}
		}
		newMap := make(map[string]interface{})
		for k, val := range v {
			processedVal, err := processJSON(val, connString, mk)
			if err != nil {
				return nil, fmt.Errorf("error in key %s: %v", k, err)
			}
			newMap[k] = processedVal
		}
		return newMap, nil

	case []interface{}:
		newSlice := make([]interface{}, len(v))
		for i, val := range v {
			processedVal, err := processJSON(val, connString, mk)
			if err != nil {
				return nil, fmt.Errorf("error in array index %d: %v", i, err)
			}
			newSlice[i] = processedVal
		}
		return newSlice, nil

	default:
		return v, nil
	}
}

func decryptPayload(ctx context.Context, connString string, mk []byte, nonceB64, ciphertextB64 string) (string, error) {
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("invalid nonce base64: %v", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext base64: %v", err)
	}

	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return "", fmt.Errorf("db connection failed: %v", err)
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, "SELECT wrapped_key FROM storage_keys WHERE is_active = true")
	if err != nil {
		return "", fmt.Errorf("failed to query storage_keys: %v", err)
	}
	defer rows.Close()

	var wrappedKeys [][]byte
	for rows.Next() {
		var w []byte
		if err := rows.Scan(&w); err != nil {
			continue
		}
		wrappedKeys = append(wrappedKeys, w)
	}

	rows2, err := conn.Query(ctx, "SELECT wrapped_dek FROM user_roles_encrypted")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var w []byte
			if err := rows2.Scan(&w); err == nil {
				wrappedKeys = append(wrappedKeys, w)
			}
		}
	}

	if len(wrappedKeys) == 0 {
		return "", fmt.Errorf("no keys found in db")
	}

	for _, wk := range wrappedKeys {
		decrypted, err := EnvelopeDecrypt(mk, wk, nonce, ciphertext)
		if err == nil {
			return string(decrypted), nil
		}
	}

	return "", fmt.Errorf("decryption failed with all %d available keys (invalid masterkey or wrong data)", len(wrappedKeys))
}
