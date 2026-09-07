package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/jackc/pgx/v5"
)

func main() {
	a := app.New()
	w := a.NewWindow("MitM Admin Data Decryptor")
	w.Resize(fyne.NewSize(900, 700))

	label := widget.NewLabel("Verifying Identity...")
	w.SetContent(container.NewCenter(label))

	go func() {
		verified, err := verifyWindowsHello(w)
		if err != nil || !verified {
			fmt.Println("Authentication failed:", err)
			os.Exit(1)
		}

		buildUI(w)
	}()

	w.ShowAndRun()
}

func buildUI(w fyne.Window) {
	hostEntry := widget.NewEntry()
	hostEntry.SetText("localhost")
	portEntry := widget.NewEntry()
	portEntry.SetText("5432")
	userEntry := widget.NewEntry()
	userEntry.SetText("mitm_user")
	passEntry := widget.NewPasswordEntry()
	dbNameEntry := widget.NewEntry()
	dbNameEntry.SetText("mitm")

	masterkeyEntry := widget.NewPasswordEntry()

	jsonInput := widget.NewMultiLineEntry()
	jsonInput.SetPlaceHolder(`{"SSNValue": {"nonce": "...", "ciphertext": "..."}}`)

	jsonOutput := widget.NewMultiLineEntry()

	connectBtn := widget.NewButton("Connect & Test DB", func() {
		host := hostEntry.Text
		port := portEntry.Text
		user := userEntry.Text
		pass := passEntry.Text
		dbname := dbNameEntry.Text
		connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, pass, host, port, dbname)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := pgx.Connect(ctx, connString)
		if err != nil {
			dialog.ShowError(fmt.Errorf("DB connection failed:\n%v", err), w)
			return
		}
		defer conn.Close(ctx)
		dialog.ShowInformation("Success", "Successfully connected to PostgreSQL DB!", w)
	})

	decryptBtn := widget.NewButton("Decrypt", func() {
		host := hostEntry.Text
		port := portEntry.Text
		user := userEntry.Text
		pass := passEntry.Text
		dbname := dbNameEntry.Text
		mkBase64 := masterkeyEntry.Text

		mk, err := base64.StdEncoding.DecodeString(mkBase64)
		if err != nil || len(mk) == 0 {
			mk = []byte(mkBase64)
		}

		connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, pass, host, port, dbname)

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
			processed, err := processJSON(parsed, connString, mk)
			if err != nil {
				jsonOutput.SetText(fmt.Sprintf("Error: %v", err))
				return
			}

			outBytes, _ := json.MarshalIndent(processed, "", "  ")
			jsonOutput.SetText(string(outBytes))
		}()
	})

	form := container.NewVBox(
		widget.NewLabel("PostgreSQL Connection"),
		container.NewGridWithColumns(2,
			widget.NewLabel("Host/Proxy:"), hostEntry,
			widget.NewLabel("Port:"), portEntry,
			widget.NewLabel("User:"), userEntry,
			widget.NewLabel("Password:"), passEntry,
			widget.NewLabel("Database:"), dbNameEntry,
		),
		connectBtn,
		widget.NewLabel("Masterkey (Base64 or Raw):"),
		masterkeyEntry,
		widget.NewLabel("Encrypted JSON Snippet:"),
	)

	inputScroll := container.NewScroll(jsonInput)
	inputScroll.SetMinSize(fyne.NewSize(0, 150))

	outputScroll := container.NewScroll(jsonOutput)
	outputScroll.SetMinSize(fyne.NewSize(0, 200))

	content := container.NewBorder(
		form,
		nil,
		nil,
		nil,
		container.NewVSplit(
			container.NewBorder(nil, container.NewPadded(decryptBtn), nil, nil, inputScroll),
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
