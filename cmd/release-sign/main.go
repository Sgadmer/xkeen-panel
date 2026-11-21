// release-sign creates release keys, signs the SHA256SUMS of a release and
// checks such a signature. It runs on the maintainer's computer: the private
// key must never be copied to GitHub, to CI or to a router.
//
//	release-sign keygen -dir <folder outside the repository> -name main
//	release-sign sign   -key <file.key> -tag v3.1.0 -sums SHA256SUMS [-compare build] [-append]
//	release-sign verify -tag v3.1.0 -sums SHA256SUMS -sig SHA256SUMS.sig [-pub <file.pub>]
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"xkeen-panel/internal/releasesig"
)

var (
	tagPattern  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	sumPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("нужна команда: keygen, sign или verify"))
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		err = fmt.Errorf("неизвестная команда %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "release-sign:", err)
	os.Exit(1)
}

func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := flags.String("dir", "", "папка для ключа; не внутри репозитория")
	name := flags.String("name", "main", "имя ключа: main, spare")
	flags.Parse(args)
	if *dir == "" || !namePattern.MatchString(*name) {
		return errors.New("укажите -dir и простое имя ключа")
	}
	if inRepository(*dir) {
		return errors.New("папка ключа находится внутри репозитория; выберите место вне его")
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		return err
	}
	private, public := filepath.Join(*dir, *name+".key"), filepath.Join(*dir, *name+".pub")
	for _, path := range []string{private, public} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s уже существует; ключ не перезаписывается", path)
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := base64.StdEncoding.EncodeToString(privateKey.Seed()) + "\n"
	if err := os.WriteFile(private, []byte(seed), 0600); err != nil {
		return err
	}
	encoded := releasesig.EncodePublicKey(publicKey)
	if err := os.WriteFile(public, []byte(encoded+"\n"), 0644); err != nil {
		return err
	}
	// Only the public half is ever printed.
	fmt.Printf("public_key=%s\nprivate_key_file=%s\n", encoded, private)
	return nil
}

// inRepository reports whether the path lies under a folder with a .git entry.
func inRepository(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return true
	}
	for dir := abs; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		if dir == filepath.Dir(dir) {
			return false
		}
	}
}

func readSums(path string) ([]byte, map[string]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	entries := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || !sumPattern.MatchString(fields[0]) {
			return nil, nil, fmt.Errorf("строка %q не похожа на запись SHA256SUMS", scanner.Text())
		}
		entries[strings.TrimPrefix(fields[1], "*")] = fields[0]
	}
	if len(entries) == 0 {
		return nil, nil, errors.New("в SHA256SUMS нет записей")
	}
	return body, entries, nil
}

// compare refuses to sign checksums that differ from files built here.
func compare(dir string, entries map[string]string) error {
	matched := 0
	for name, want := range entries {
		body, err := os.ReadFile(filepath.Join(dir, filepath.Base(name)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("%s: сумма в SHA256SUMS не совпадает с локальной сборкой — подпись не создана", name)
		}
		matched++
	}
	if matched == 0 {
		return fmt.Errorf("в %s нет ни одного файла из SHA256SUMS", dir)
	}
	fmt.Printf("compared_files=%d\n", matched)
	return nil
}

func sign(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := flags.String("key", "", "файл закрытого ключа")
	tag := flags.String("tag", "", "тег выпуска, например v3.1.0")
	sumsPath := flags.String("sums", "SHA256SUMS", "файл контрольных сумм выпуска")
	out := flags.String("out", "", "файл подписи; по умолчанию рядом с SHA256SUMS")
	local := flags.String("compare", "", "папка с локальной сборкой: суммы должны совпасть")
	add := flags.Bool("append", false, "добавить подпись второго ключа к существующей")
	flags.Parse(args)
	if *keyPath == "" || !tagPattern.MatchString(*tag) {
		return errors.New("укажите -key и точный тег выпуска")
	}
	seed, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	key, err := releasesig.ParsePrivateKey(string(seed))
	if err != nil {
		return err
	}
	body, entries, err := readSums(*sumsPath)
	if err != nil {
		return err
	}
	if *local != "" {
		if err := compare(*local, entries); err != nil {
			return err
		}
	}
	target := *out
	if target == "" {
		target = filepath.Join(filepath.Dir(*sumsPath), releasesig.Asset)
	}
	line := releasesig.Sign(key, *tag, body) + "\n"
	mode := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	if *add {
		mode = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	file, err := os.OpenFile(target, mode, 0644)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(line); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Printf("signed_tag=%s\nsigned_files=%d\nsignature_file=%s\npublic_key=%s\n", *tag, len(entries), target,
		releasesig.EncodePublicKey(key.Public().(ed25519.PublicKey)))
	return nil
}

func verify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	tag := flags.String("tag", "", "тег выпуска")
	sumsPath := flags.String("sums", "SHA256SUMS", "файл контрольных сумм выпуска")
	sigPath := flags.String("sig", "", "файл подписи; по умолчанию рядом с SHA256SUMS")
	pubPath := flags.String("pub", "", "файл открытого ключа; без него — ключи, встроенные в панель")
	flags.Parse(args)
	if !tagPattern.MatchString(*tag) {
		return errors.New("укажите точный тег выпуска")
	}
	body, _, err := readSums(*sumsPath)
	if err != nil {
		return err
	}
	if *sigPath == "" {
		*sigPath = filepath.Join(filepath.Dir(*sumsPath), releasesig.Asset)
	}
	signature, err := os.ReadFile(*sigPath)
	if err != nil {
		return err
	}
	trusted, err := releasesig.Trusted()
	if *pubPath != "" {
		var text []byte
		if text, err = os.ReadFile(*pubPath); err == nil {
			var key ed25519.PublicKey
			if key, err = releasesig.ParsePublicKey(string(text)); err == nil {
				trusted = []ed25519.PublicKey{key}
			}
		}
	}
	if err != nil {
		return err
	}
	if err := releasesig.Verify(trusted, *tag, body, signature); err != nil {
		return err
	}
	fmt.Printf("verified_tag=%s\n", *tag)
	return nil
}
