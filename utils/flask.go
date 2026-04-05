package utils

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"io"
	"strings"

	"encoding/json"
	"log"

	fernet "github.com/fernet/fernet-go"
)

// StrMap is a convenience alias for map[string]any.
type StrMap = map[string]any

type FlaskAuth struct {
	AppSecretKey string
	LogCookies   bool
}

func (f *FlaskAuth) NormalizedSecretKey() string {
	for len(f.AppSecretKey) < 32 {
		f.AppSecretKey += " "
	}
	if len(f.AppSecretKey) > 32 {
		f.AppSecretKey = f.AppSecretKey[:32]
	}
	return base64.StdEncoding.EncodeToString([]byte(f.AppSecretKey))
}

// DecodeSessionCookie decodes a Flask session cookie from its base64 representation.
func (f *FlaskAuth) DecodeSessionCookie(base64value string) (out StrMap, err error) {
	decompress := base64value[0] == '.'
	if decompress {
		base64value = base64value[1:]
	}
	orig := base64value
	base64value = strings.Map(func(ch rune) rune {
		if ch == '-' {
			ch = '+'
		}
		if ch == '_' {
			ch = '/'
		}
		return ch
	}, base64value)
	parts := strings.Split(base64value, ".")
	var timestampBytes []byte
	if len(parts) >= 1 {
		if d, err := base64.StdEncoding.DecodeString(paddedWith(parts[1], '=')); err != nil {
			log.Println("Error decoding timestamp: ", err)
		} else {
			timestampBytes = d
			if f.LogCookies {
				log.Println("Decoded TimeStamp: ", timestampBytes)
			}
		}
	}
	var hmacBytes []byte
	if len(parts) >= 2 {
		if d, err := base64.StdEncoding.DecodeString(paddedWith(parts[2], '=')); err != nil {
			log.Println("Error decoding timestamp: ", err)
		} else {
			hmacBytes = d
			if f.LogCookies {
				log.Println("Decoded HMAC: ", hmacBytes)
			}
		}
	}
	base64EncodedData := parts[0]
	padded := paddedWith(base64EncodedData, '=')
	decoded, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		log.Println("Error decoding: ", padded, err)
		log.Println("Orig Value: ", orig)
		return nil, err
	} else {
		if f.LogCookies {
			log.Println("Decoded Cookie: ", decoded)
		}
	}

	if decompress {
		if zr, err := zlib.NewReader(bytes.NewReader(decoded)); err != nil {
			log.Println("error decompressing decoded cookie: ", err)
			return nil, err
		} else if decoded, err = io.ReadAll(zr); err != nil {
			return nil, err
		}
	}

	if err = json.Unmarshal(decoded, &out); err != nil {
		log.Println("Error decoding json: ", padded, decoded, err)
		return nil, err
	}

	return
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

var alphabetReverse = alphaReverseMap(alphabet)

// DecodeSessionUserId decodes a Fernet-encrypted Flask session user ID.
func (f *FlaskAuth) DecodeSessionUserId(userid string) (out []interface{}) {
	userid = paddedWith(userid, '=')
	key := fernet.MustDecodeKeys(f.NormalizedSecretKey())
	data := fernet.VerifyAndDecrypt([]byte(userid), 0, key)
	parts := strings.Split(string(data), "|")
	for _, part := range parts {
		if part[0] == '~' {
			out = append(out, excelDecode(part[1:], alphabet, alphabetReverse))
		} else {
			out = append(out, part)
		}
	}
	return
}

// ParseSignedCookieValue decodes a Flask session cookie and extracts the user ID parts.
func (f *FlaskAuth) ParseSignedCookieValue(value string) (parts []interface{}, sessmap StrMap) {
	var err error
	sessmap, err = f.DecodeSessionCookie(value)
	if err != nil {
		log.Println("error processing session: ", err)
		return
	}
	user_id, ok := sessmap["_user_id"]
	if user_id == nil || !ok || user_id.(string) == "" {
		log.Println("could not find _user_id in cookie: ", err)
		return
	}

	parts = f.DecodeSessionUserId(user_id.(string))
	return
}

// --- inlined helpers (from goutils) ---

func paddedWith(input string, padding byte) string {
	ch := string(padding)
	for len(input)%4 != 0 {
		input += ch
	}
	return input
}

func alphaReverseMap(alpha string) map[rune]uint {
	out := make(map[rune]uint)
	for i, ch := range alpha {
		out[ch] = uint(i)
	}
	return out
}

func excelDecode(encoded string, alpha string, revmap map[rune]uint) uint64 {
	base := uint64(len(alpha))
	var n uint64 = 0
	for _, c := range encoded {
		n = n*base + uint64(revmap[c])
	}
	return n
}
