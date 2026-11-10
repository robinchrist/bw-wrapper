package main

// The in-memory vault. Everything is loaded once through the real CLI and
// then answered natively, following list.command.ts / get.command.ts.
//
// Item JSON (which carries passwords, TOTP seeds, cards, fields) and notes are
// kept sealed with a per-process random AES-256-GCM key and opened only for
// the request that needs them. The search index (names, subtitles, hostnames,
// ids) is plain so that searching stays a pure memory scan.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// ---------- sealing ----------

type sealer struct {
	page  []byte // the whole mapping, kept so it can be unmapped
	key   []byte // one locked page outside the Go heap
	aead  cipher.AEAD
	nonce [4]byte
	ctr   atomic.Uint64
}

func newSealer() (*sealer, error) {
	page, err := syscall.Mmap(-1, 0, syscall.Getpagesize(), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	_ = syscall.Mlock(page) // best effort: keep the key out of swap
	lockPage(page)
	s := &sealer{page: page, key: page[:32]}
	if _, err := rand.Read(s.key); err != nil {
		s.wipe()
		return nil, err
	}
	rand.Read(s.nonce[:])
	blk, err := aes.NewCipher(s.key)
	if err != nil {
		s.wipe()
		return nil, err
	}
	if s.aead, err = cipher.NewGCM(blk); err != nil {
		s.wipe()
		return nil, err
	}
	return s, nil
}

func (s *sealer) seal(plain []byte) []byte {
	if s.aead == nil {
		return nil
	}
	out := make([]byte, 12, 12+len(plain)+16)
	copy(out, s.nonce[:])
	binary.BigEndian.PutUint64(out[4:], s.ctr.Add(1))
	return s.aead.Seal(out, out[:12], plain, nil)
}

// open returns a fresh plaintext buffer; the caller wipes it.
func (s *sealer) open(sealed []byte) []byte {
	if s.aead == nil || len(sealed) < 12 {
		return nil
	}
	plain, err := s.aead.Open(nil, sealed[:12], sealed[12:], nil)
	if err != nil {
		return nil
	}
	return plain
}

// wipe zeroes the key and gives its page back to the system. Every load
// creates a sealer, so a page that stayed mapped would add up over reloads.
func (s *sealer) wipe() {
	s.aead = nil
	s.key = nil
	if s.page != nil {
		wipe(s.page)
		syscall.Munlock(s.page)
		syscall.Munmap(s.page)
		s.page = nil
	}
}

// ---------- model ----------

type item struct {
	sealed      []byte
	sealedNotes []byte // searchKey(notes), sealed
	id          string
	typ         int
	deleted     bool
	archived    bool
	folderID    string
	orgID       string
	collections []string
	name        string
	hasName     bool
	subtitle    string
	hosts       []string
	// what the get filters look at
	hasUser, hasPass, hasTotp, hasNotes, uriOK bool
	// An organization login whose password and TOTP are both null may have
	// been redacted (viewPassword=false); the real CLI still sees the values
	// while filtering, so such items force a fallback for password/totp.
	maybeRedacted bool
}

type object struct {
	raw   []byte
	idRaw []byte
	id    string
	name  string // lowercased
	orgID string
}

type vault struct {
	seal *sealer
	// items[state]: 0 active, 1 trash, 2 archived, 3 trash+archived
	items       [4][]*item
	byID        map[string]*item
	archiveOK   bool // the CLI knows --archived
	canArchive  bool // --archived is honoured for this account
	folders     []*object
	collections []*object
	orgs        []*object
	status      []byte

	mu          sync.Mutex
	memo        map[string][]byte // sealed real responses
	memoBytes   int               // keys + sealed responses retained in memo
	totpAllowed map[string]bool   // "" = personal vault, else organization id
}

type itemJSON struct {
	ID             string   `json:"id"`
	OrganizationID *string  `json:"organizationId"`
	FolderID       *string  `json:"folderId"`
	CollectionIDs  []string `json:"collectionIds"`
	Type           int      `json:"type"`
	Name           *string  `json:"name"`
	Notes          *string  `json:"notes"`
	Login          *struct {
		Username *string         `json:"username"`
		Password json.RawMessage `json:"password"`
		Totp     json.RawMessage `json:"totp"`
		Uris     []struct {
			URI   *string `json:"uri"`
			Match *int    `json:"match"`
		} `json:"uris"`
		Fido2Credentials []struct {
			UserName *string `json:"userName"`
		} `json:"fido2Credentials"`
	} `json:"login"`
	Card *struct {
		Brand  *string         `json:"brand"`
		Number json.RawMessage `json:"number"`
	} `json:"card"`
	Identity *struct {
		FirstName *string `json:"firstName"`
		LastName  *string `json:"lastName"`
	} `json:"identity"`
	SSHKey *struct {
		KeyFingerprint *string `json:"keyFingerprint"`
	} `json:"sshKey"`
	BankAccount *struct {
		BankName *string `json:"bankName"`
	} `json:"bankAccount"`
	DriversLicense *struct {
		FirstName    *string `json:"firstName"`
		LastName     *string `json:"lastName"`
		IssuingState *string `json:"issuingState"`
	} `json:"driversLicense"`
	Passport *struct {
		GivenName      *string `json:"givenName"`
		Surname        *string `json:"surname"`
		IssuingCountry *string `json:"issuingCountry"`
	} `json:"passport"`
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func joinNonEmpty(sep string, parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, sep)
}

// subtitleOf mirrors the subTitle getters of the cipher views.
func subtitleOf(j *itemJSON) string {
	switch j.Type {
	case 1:
		if j.Login == nil {
			return ""
		}
		if deref(j.Login.Username) == "" && len(j.Login.Fido2Credentials) > 0 {
			return deref(j.Login.Fido2Credentials[0].UserName)
		}
		return deref(j.Login.Username)
	case 3:
		if j.Card == nil {
			return ""
		}
		sub := deref(j.Card.Brand)
		if num, ok := unquoteJSON(j.Card.Number); ok {
			if len(num) >= 4 {
				if sub != "" {
					sub += ", "
				}
				n := 4
				if len(num) >= 5 && num[0] == '3' && (num[1] == '4' || num[1] == '7') {
					n = 5
				}
				sub += "*" + string(num[len(num)-n:])
			}
			wipe(num)
		}
		return sub
	case 4:
		if j.Identity == nil {
			return ""
		}
		return joinNonEmpty(" ", deref(j.Identity.FirstName), deref(j.Identity.LastName))
	case 5:
		if j.SSHKey != nil {
			return deref(j.SSHKey.KeyFingerprint)
		}
	case 6:
		if j.BankAccount != nil {
			return deref(j.BankAccount.BankName)
		}
	case 7:
		if d := j.DriversLicense; d != nil {
			return joinNonEmpty(", ", joinNonEmpty(" ", deref(d.FirstName), deref(d.LastName)), deref(d.IssuingState))
		}
	case 8:
		if p := j.Passport; p != nil {
			return joinNonEmpty(", ", joinNonEmpty(" ", deref(p.GivenName), deref(p.Surname)), deref(p.IssuingCountry))
		}
	}
	return ""
}

func (v *vault) addItem(raw []byte, state int) error {
	var j itemJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return err
	}
	it := &item{
		id:          j.ID,
		typ:         j.Type,
		deleted:     state&1 != 0,
		archived:    state&2 != 0,
		folderID:    deref(j.FolderID),
		orgID:       deref(j.OrganizationID),
		collections: j.CollectionIDs,
		hasName:     j.Name != nil,
		name:        searchKey(deref(j.Name)),
		subtitle:    searchKey(subtitleOf(&j)),
	}
	if n := deref(j.Notes); n != "" {
		it.hasNotes = jsTrim(n) != ""
		key := []byte(searchKey(n))
		it.sealedNotes = v.seal.seal(key)
		wipe(key)
	}
	if j.Type == 1 && j.Login != nil {
		l := j.Login
		it.hasUser = jsTrim(deref(l.Username)) != ""
		it.hasPass = !rawBlank(l.Password)
		it.hasTotp = !rawBlank(l.Totp)
		it.uriOK = len(l.Uris) > 0 && (l.Uris[0].URI == nil || *l.Uris[0].URI != "")
		it.maybeRedacted = it.orgID != "" && isNullJSON(l.Password) && isNullJSON(l.Totp)
		for _, u := range l.Uris {
			if u.URI == nil || *u.URI == "" || (u.Match != nil && *u.Match == 4) {
				continue
			}
			if h, ok := uriHostname(*u.URI); ok && h != "" {
				it.hosts = append(it.hosts, searchKey(h))
			}
		}
		wipe(l.Password)
		wipe(l.Totp)
	}
	if j.Card != nil {
		wipe(j.Card.Number)
	}
	it.sealed = v.seal.seal(raw)
	v.items[state] = append(v.items[state], it)
	if _, dup := v.byID[it.id]; !dup {
		v.byID[it.id] = it
	}
	return nil
}

func isNullJSON(raw []byte) bool {
	return len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null"
}

func parseObjects(elems [][]byte) []*object {
	out := make([]*object, 0, len(elems))
	for _, e := range elems {
		var j struct {
			ID             json.RawMessage `json:"id"`
			Name           *string         `json:"name"`
			OrganizationID *string         `json:"organizationId"`
		}
		if json.Unmarshal(e, &j) != nil {
			continue
		}
		o := &object{raw: e, idRaw: j.ID, name: jsLower(deref(j.Name)), orgID: deref(j.OrganizationID)}
		if len(o.idRaw) == 0 {
			o.idRaw = []byte("null")
		}
		if s, ok := unquoteJSON(j.ID); ok {
			o.id = string(s)
		}
		out = append(out, o)
	}
	return out
}

// realFunc runs the real CLI with `--response` and returns its stdout.
type realFunc func(args ...string) ([]byte, error)

var errLocked = errors.New("the real CLI could not read the vault with this session")

func realList(real realFunc, args ...string) ([][]byte, error) {
	out, err := real(args...)
	defer wipe(out)
	res, ok := parseRealResponse(out)
	if !ok {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected output from `bw %s`", strings.Join(args, " "))
	}
	if res.kind == rErr {
		return nil, fmt.Errorf("%w: %s", errLocked, res.msg)
	}
	if res.kind != rList {
		return nil, fmt.Errorf("`bw %s` did not return a list", strings.Join(args, " "))
	}
	return res.list, nil
}

// loadVault pulls the whole vault through the real CLI. With warmFirst the
// first item list runs alone before the other queries start: right for a
// single `bw serve` process, which decrypts the vault on the first query and
// answers the rest from its cache.
func loadVault(real realFunc, warmFirst bool) (*vault, error) {
	seal, err := newSealer()
	if err != nil {
		return nil, err
	}
	v := &vault{seal: seal, byID: map[string]*item{}, memo: map[string][]byte{}, totpAllowed: map[string]bool{}}

	itemArgs := [4][]string{
		{"list", "items"},
		{"list", "items", "--trash"},
		{"list", "items", "--archived"},
		{"list", "items", "--trash", "--archived"},
	}
	var lists [4][][]byte
	var errs [8]error
	var folders, collections, orgs [][]byte
	var wg sync.WaitGroup
	run := func(i int, f func() error) {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = f() }()
	}
	for i := range itemArgs {
		run(i, func() (err error) { lists[i], err = realList(real, itemArgs[i]...); return })
		if i == 0 && warmFirst {
			wg.Wait()
		}
	}
	run(4, func() (err error) { folders, err = realList(real, "list", "folders"); return })
	run(5, func() (err error) { collections, err = realList(real, "list", "collections"); return })
	run(6, func() (err error) { orgs, err = realList(real, "list", "organizations"); return })
	run(7, func() error {
		out, err := real("status")
		res, ok := parseRealResponse(out)
		if !ok || res.kind != rTmpl {
			if err == nil {
				err = errors.New("unexpected output from `bw status`")
			}
			return err
		}
		var st struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(res.raw, &st) != nil || st.Status != "unlocked" {
			return fmt.Errorf("%w: status is %q", errLocked, st.Status)
		}
		v.status = res.raw
		return nil
	})
	wg.Wait()
	defer func() {
		for _, l := range lists {
			for _, e := range l {
				wipe(e)
			}
		}
	}()
	for _, i := range []int{0, 1, 4, 5, 6, 7} {
		if errs[i] != nil {
			v.wipe()
			return nil, errs[i]
		}
	}
	// --archived is newer than the rest of the CLI; without it (or when the
	// account may not archive, in which case the CLI ignores the flag and
	// returns the same list again) there is no separate archived state.
	v.archiveOK = errs[2] == nil && errs[3] == nil
	v.canArchive = v.archiveOK && !(len(lists[0]) > 0 && sameLists(lists[0], lists[2]))
	states := []int{0, 1}
	if v.canArchive {
		states = []int{0, 1, 2, 3}
	}
	for _, st := range states {
		for _, raw := range lists[st] {
			if err := v.addItem(raw, st); err != nil {
				v.wipe()
				return nil, err
			}
		}
	}
	v.folders = parseObjects(folders)
	v.collections = parseObjects(collections)
	v.orgs = parseObjects(orgs)
	return v, nil
}

func sameLists(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// wipe destroys the key and every sealed buffer.
func (v *vault) wipe() {
	if v == nil {
		return
	}
	v.seal.wipe()
	for st := range v.items {
		for _, it := range v.items[st] {
			wipe(it.sealed)
			wipe(it.sealedNotes)
			*it = item{}
		}
		v.items[st] = nil
	}
	v.byID = nil
	for _, l := range [][]*object{v.folders, v.collections, v.orgs} {
		for _, o := range l {
			wipe(o.raw)
		}
	}
	v.folders, v.collections, v.orgs = nil, nil, nil
	wipe(v.status)
	v.mu.Lock()
	for k, m := range v.memo {
		wipe(m)
		delete(v.memo, k)
	}
	v.memoBytes = 0
	v.mu.Unlock()
}

func (v *vault) count() int {
	n := 0
	for _, l := range v.items {
		n += len(l)
	}
	return n
}

// ---------- search ----------

// matches is the per-item predicate of SearchService.searchCiphersBasic.
func (v *vault) matches(it *item, terms []string) bool {
	var notes []byte
	opened := false
	defer func() { wipe(notes) }()
	for _, t := range terms {
		if it.hasName && strings.Contains(it.name, t) {
			continue
		}
		if len(t) >= 8 && strings.HasPrefix(it.id, t) {
			continue
		}
		if it.subtitle != "" && strings.Contains(it.subtitle, t) {
			continue
		}
		hit := false
		for _, h := range it.hosts {
			if strings.Contains(h, t) {
				hit = true
				break
			}
		}
		if hit {
			continue
		}
		if it.sealedNotes != nil {
			if !opened {
				notes, opened = v.seal.open(it.sealedNotes), true
			}
			if bytes.Contains(notes, []byte(t)) {
				continue
			}
		}
		return false
	}
	return true
}

func searchTerms(q string) []string { return jsFields(searchKey(jsTrim(q))) }

func (v *vault) search(pool []*item, query string) []*item {
	terms := searchTerms(query)
	var out []*item
	for _, it := range pool {
		if v.matches(it, terms) {
			out = append(out, it)
		}
	}
	return out
}

// ---------- get ----------

type filterKind int

const (
	fNone filterKind = iota
	fUsername
	fPassword
	fURI
	fTotp
	fNotes
)

func (it *item) passes(f filterKind) bool {
	switch f {
	case fUsername:
		return it.typ == 1 && it.hasUser
	case fPassword:
		return it.typ == 1 && it.hasPass
	case fURI:
		return it.typ == 1 && it.uriOK
	case fTotp:
		return it.typ == 1 && it.hasTotp
	case fNotes:
		return it.hasNotes
	}
	return true
}

// getCipher is GetCommand.getCipher. It returns the item or the result to
// send instead (an error, or a fallback request).
func (v *vault) getCipher(id string, f filterKind) (*item, *result) {
	redactable := f == fPassword || f == fTotp
	if isGUID(id) {
		it := v.byID[id]
		if it == nil {
			// Not in the lists we loaded: it may be hidden by an organization
			// policy or archived on an account that cannot list archives.
			return nil, fallbackResult()
		}
		if redactable && it.maybeRedacted {
			return nil, fallbackResult()
		}
		if !it.passes(f) {
			return nil, notFound()
		}
		return it, nil
	}
	if jsTrim(id) == "" {
		return nil, notFound()
	}
	found := v.search(v.items[0], id)
	if redactable {
		for _, it := range found {
			if it.maybeRedacted {
				return nil, fallbackResult()
			}
		}
	}
	switch len(found) {
	case 0:
		return nil, notFound()
	case 1:
		if !found[0].passes(f) {
			return nil, notFound()
		}
		return found[0], nil
	}
	var keep []*item
	for _, it := range found {
		if it.passes(f) {
			keep = append(keep, it)
		}
	}
	switch len(keep) {
	case 0:
		return nil, notFound()
	case 1:
		return keep[0], nil
	}
	ids := make([][]byte, len(keep))
	for i, it := range keep {
		ids[i] = jsQuote(it.id)
	}
	return nil, multipleResults(ids)
}

// field opens an item and returns one raw JSON token of it. The caller owns
// the returned buffer and wipes it.
func (v *vault) field(it *item, f filterKind) []byte {
	plain := v.seal.open(it.sealed)
	tok, scratch := extractField(plain, f)
	wipeAll(scratch)
	return tok
}

// extractField decodes the fields the get commands can return and hands back
// the one that was asked for.
//
// Ownership: the JSON decoder allocates a separate copy for every field it
// decodes, selected or not, and each of them is plaintext from the vault
// (notes, password, TOTP seed, ...). The selected copy is transferred to the
// caller. Every other buffer this function caused to exist, including the
// plaintext item it was given, is returned in scratch for the caller to wipe:
// nothing is left behind that nobody owns.
func extractField(plain []byte, f filterKind) (tok []byte, scratch [][]byte) {
	var j struct {
		Notes json.RawMessage `json:"notes"`
		Login *struct {
			Username json.RawMessage `json:"username"`
			Password json.RawMessage `json:"password"`
			Totp     json.RawMessage `json:"totp"`
			Uris     []struct {
				URI json.RawMessage `json:"uri"`
			} `json:"uris"`
		} `json:"login"`
	}
	err := json.Unmarshal(plain, &j)
	decoded := [][]byte{j.Notes}
	if j.Login != nil {
		decoded = append(decoded, j.Login.Username, j.Login.Password, j.Login.Totp)
		for _, u := range j.Login.Uris {
			decoded = append(decoded, u.URI)
		}
	}
	var selected []byte
	if err == nil {
		switch {
		case f == fNotes:
			selected = j.Notes
		case j.Login == nil:
		case f == fUsername:
			selected = j.Login.Username
		case f == fPassword:
			selected = j.Login.Password
		case f == fTotp:
			selected = j.Login.Totp
		case f == fURI && len(j.Login.Uris) > 0:
			selected = j.Login.Uris[0].URI
		}
	}
	scratch = [][]byte{plain}
	for _, b := range decoded {
		if len(b) > 0 && (len(selected) == 0 || &b[0] != &selected[0]) {
			scratch = append(scratch, b)
		}
	}
	if len(selected) == 0 {
		return []byte("null"), scratch
	}
	return selected, scratch
}

func wipeAll(bufs [][]byte) {
	for _, b := range bufs {
		wipe(b)
	}
}

type reqCtx struct {
	real realFunc // real CLI bound to this request's session
}

func (v *vault) get(ctx *reqCtx, object, id string, opts map[string]string) *result {
	id = jsLower(id)
	switch object {
	case "item":
		it, res := v.getCipher(id, fNone)
		if res != nil {
			return res
		}
		return &result{kind: rObj, raw: v.seal.open(it.sealed), owned: true}
	case "username", "password", "uri", "notes":
		f := map[string]filterKind{"username": fUsername, "password": fPassword, "uri": fURI, "notes": fNotes}[object]
		it, res := v.getCipher(id, f)
		if res != nil {
			return res
		}
		return &result{kind: rStr, raw: v.field(it, f), owned: true}
	case "totp":
		return v.getTotp(ctx, id)
	case "folder":
		return getObject(v.folders, id, true)
	case "collection":
		return getObject(v.collections, id, true)
	case "organization":
		// A search goes over all organizations, the cached list only holds
		// the ones the user is a member of: answer id lookups only.
		return getObject(v.orgs, id, false)
	case "template":
		return v.memoized(ctx, "get", "template", id)
	}
	return fallbackResult()
}

func getObject(pool []*object, id string, searchable bool) *result {
	if isGUID(id) {
		for _, o := range pool {
			if o.id == id {
				return &result{kind: rObj, raw: o.raw}
			}
		}
		return fallbackResult()
	}
	if !searchable {
		return fallbackResult()
	}
	if jsTrim(id) == "" {
		return notFound()
	}
	var found []*object
	for _, o := range pool {
		if strings.Contains(o.name, id) {
			found = append(found, o)
		}
	}
	switch len(found) {
	case 0:
		return notFound()
	case 1:
		return &result{kind: rObj, raw: found[0].raw}
	}
	ids := make([][]byte, len(found))
	for i, o := range found {
		ids[i] = o.idRaw
	}
	return multipleResults(ids)
}

// memoized answers a query by asking the real CLI once and keeping its
// (sealed) response until the next reload.
func (v *vault) memoized(ctx *reqCtx, args ...string) *result {
	key := strings.Join(args, "\x00")
	v.mu.Lock()
	sealed := v.memo[key]
	v.mu.Unlock()
	if sealed != nil {
		if plain := v.seal.open(sealed); plain != nil {
			res, ok := parseRealResponse(plain)
			wipe(plain)
			if ok {
				res.owned = true
				return res
			}
		}
	}
	out, _ := ctx.real(args...)
	defer wipe(out)
	res, ok := parseRealResponse(out)
	if !ok {
		return fallbackResult()
	}
	if res.kind != rErr {
		// Bounded: a caller asking for ever new queries (changing URLs) gets
		// every answer, but only memoBudget bytes of them are kept until the
		// next reload. Past that, new queries simply go to the real CLI again.
		sealed := v.seal.seal(bytes.TrimSpace(out))
		v.mu.Lock()
		if _, have := v.memo[key]; !have && v.memoBytes+len(key)+len(sealed) <= memoBudget {
			v.memo[key] = sealed
			v.memoBytes += len(key) + len(sealed)
		}
		v.mu.Unlock()
	}
	res.owned = true
	return res
}

// memoBudget caps what one vault keeps of memoized real-CLI responses.
const memoBudget = 32 << 20

const premiumMsg = "Premium status is required to use this feature."

func (v *vault) getTotp(ctx *reqCtx, id string) *result {
	it, res := v.getCipher(id, fTotp)
	if res != nil {
		return res
	}
	// Whether TOTP is available depends on premium status, which only the
	// real CLI knows. Ask it once per vault (personal) or organization.
	v.mu.Lock()
	allowed, known := v.totpAllowed[""]
	if !(known && allowed) {
		allowed, known = v.totpAllowed[it.orgID]
	}
	v.mu.Unlock()
	if known && !allowed {
		return errResult(premiumMsg)
	}
	if known {
		tok := v.field(it, fTotp)
		seed, ok := unquoteJSON(tok)
		wipe(tok)
		if ok {
			code, ok := totpNow(seed)
			wipe(seed)
			if ok {
				return &result{kind: rStr, raw: jsQuote(code), owned: true}
			}
		}
	}
	out, _ := ctx.real("get", "totp", it.id)
	res, ok := parseRealResponse(out)
	wipe(out)
	if !ok {
		return fallbackResult()
	}
	v.mu.Lock()
	switch {
	case res.kind == rStr:
		v.totpAllowed[it.orgID] = true
	case res.kind == rErr && res.msg == premiumMsg:
		v.totpAllowed[it.orgID] = false
	}
	v.mu.Unlock()
	res.owned = true // a private copy of the real CLI's answer: wiped after sending
	return res
}

// ---------- list ----------

func (v *vault) list(ctx *reqCtx, what string, opts map[string]string) *result {
	search := opts["search"]
	hasSearch := jsTrim(search) != ""
	switch what {
	case "items":
		return v.listItems(ctx, opts)
	case "folders", "collections", "organizations":
		pool := map[string][]*object{"folders": v.folders, "collections": v.collections, "organizations": v.orgs}[what]
		needle := jsLower(search)
		org := opts["organizationid"]
		var out [][]byte
		for _, o := range pool {
			if what == "collections" && org != "" && o.orgID != org {
				continue
			}
			if hasSearch && !strings.Contains(o.name, needle) {
				continue
			}
			out = append(out, o.raw)
		}
		return &result{kind: rList, list: out}
	}
	return fallbackResult()
}

func (v *vault) listItems(ctx *reqCtx, opts map[string]string) *result {
	if jsTrim(opts["url"]) != "" {
		// URL matching depends on match strategies and equivalent domains
		// held by the real CLI; ask it once per distinct query.
		args := []string{"list", "items"}
		for _, k := range []string{"url", "search", "folderid", "collectionid", "organizationid"} {
			if val := opts[k]; val != "" {
				args = append(args, "--"+k, val)
			}
		}
		for _, k := range []string{"trash", "archived"} {
			if opts[k] != "" {
				args = append(args, "--"+k)
			}
		}
		return v.memoized(ctx, args...)
	}
	state := 0
	if opts["trash"] != "" {
		state |= 1
	}
	if opts["archived"] != "" {
		// Without a distinct archived state (old CLI, or an account that may
		// not archive) the real CLI decides what the flag means.
		if !v.canArchive {
			return fallbackResult()
		}
		state |= 2
	}
	pool := v.items[state]
	folder, coll, org := opts["folderid"], opts["collectionid"], opts["organizationid"]
	if folder != "" || coll != "" || org != "" {
		var keep []*item
		for _, it := range pool {
			if matchIDFilter(folder, it.folderID) || matchIDFilter(org, it.orgID) || matchCollection(coll, it.collections) {
				keep = append(keep, it)
			}
		}
		pool = keep
	}
	if jsTrim(opts["search"]) != "" {
		pool = v.search(pool, opts["search"])
	}
	out := make([][]byte, len(pool))
	for i, it := range pool {
		out[i] = v.seal.open(it.sealed)
	}
	return &result{kind: rList, list: out, owned: true}
}

// matchIDFilter implements the folderid / organizationid filters, including
// the special values "null" and "notnull".
func matchIDFilter(want, have string) bool {
	switch want {
	case "":
		return false
	case "notnull":
		return have != ""
	case "null":
		return nullFilterMatches && have == ""
	}
	return want == have
}

// nullFilterMatches: whether `--folderid null` / `--organizationid null`
// select items without a folder / organization in the real CLI.
const nullFilterMatches = true

func matchCollection(want string, have []string) bool {
	switch want {
	case "":
		return false
	case "notnull":
		return len(have) > 0
	case "null":
		return len(have) == 0
	}
	for _, c := range have {
		if c == want {
			return true
		}
	}
	return false
}
