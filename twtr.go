package twtr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/garyburd/go-oauth/oauth"
)

// AuthOption is twitter custom auth infomation
type AuthOption struct {
	RequestTokenURL  string
	AuthorizationURL string
	AccessTokenURL   string
	APIEndpointURL   string
	ConsumerCreds
}

func (o *AuthOption) fillDefauktAuthOption() {
	if o == nil {
		return
	}
	if o.RequestTokenURL == "" {
		o.RequestTokenURL = "https://api.twitter.com/oauth/request_token"
	}
	if o.AuthorizationURL == "" {
		o.AuthorizationURL = "https://api.twitter.com/oauth/authorize"
	}
	if o.AccessTokenURL == "" {
		o.AccessTokenURL = "https://api.twitter.com/oauth/access_token"
	}
	if o.APIEndpointURL == "" {
		o.APIEndpointURL = "https://api.twitter.com/1.1"
	}
}

// Credentials is request token
type Credentials struct {
	Token  string
	Secret string
}

// ConsumerCreds is consumer token and consumer secret in twitter
type ConsumerCreds Credentials

// RequestCreds is request credientials
type RequestCreds Credentials

// AccessCreds is access credientials
type AccessCreds Credentials

// AutorizationInfo is information to authorizate with twitter
type AutorizationInfo struct {
	AuthorizationURL string
	RequestCreds
}

// Auth is Twitter auth object
type Auth struct {
	client       oauth.Client
	requestCreds RequestCreds
	option       AuthOption
}

// NewAuth is create Twitter auth object using auth information
func NewAuth(opt AuthOption) *Auth {
	option := &opt
	option.fillDefauktAuthOption()
	return &Auth{
		client:       newAuthClient(*option),
		requestCreds: RequestCreds{},
		option:       *option,
	}
}

// create new auth client using option opt
func newAuthClient(opt AuthOption) oauth.Client {
	return oauth.Client{
		TemporaryCredentialRequestURI: opt.RequestTokenURL,
		ResourceOwnerAuthorizationURI: opt.AuthorizationURL,
		TokenRequestURI:               opt.AccessTokenURL,
		Credentials: oauth.Credentials{
			Token:  opt.ConsumerCreds.Token,
			Secret: opt.ConsumerCreds.Secret,
		},
	}
}

// SetRequestToken is set request information
func (a *Auth) SetRequestToken(info RequestCreds) {
	a.requestCreds = info
}

// GenerateAuthorizationInfo is getting autiorization information
func (a *Auth) GenerateAuthorizationInfo() (AutorizationInfo, error) {
	creds, err := a.client.RequestTemporaryCredentials(http.DefaultClient, "", nil)
	if err != nil {
		return AutorizationInfo{}, fmt.Errorf("failed to get request temporary credientials: %v", err)
	}
	url := a.client.AuthorizationURL(creds, nil)
	info := AutorizationInfo{
		AuthorizationURL: url,
		RequestCreds: RequestCreds{
			Token:  creds.Token,
			Secret: creds.Secret,
		},
	}

	a.SetRequestToken(info.RequestCreds)
	return info, nil
}

// CreateClient is creating new twitter client
func (a *Auth) CreateClient(pin string) (Twtr, error) {
	if (a.requestCreds == RequestCreds{}) {
		return nil, fmt.Errorf("generate autorization infomation or set request infomation first")
	}

	reqCreds := &oauth.Credentials{
		Token:  a.requestCreds.Token,
		Secret: a.requestCreds.Secret,
	}
	accCreds, _, err := a.client.RequestToken(http.DefaultClient, reqCreds, pin)
	if err != nil {
		return nil, fmt.Errorf("failed to twitter authorization")
	}

	accessCreds := AccessCreds{
		Token:  accCreds.Token,
		Secret: accCreds.Secret,
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get access credientials")
	}

	return createTwtr(a.client, accessCreds, *accCreds, a.option), nil
}

// NewTwtr is new
func NewTwtr(opt AuthOption, accessCreds AccessCreds) Twtr {
	opt.fillDefauktAuthOption()
	auth := newAuthClient(opt)
	auth.Credentials.Token = opt.ConsumerCreds.Token
	auth.Credentials.Secret = opt.ConsumerCreds.Secret

	clientCreds := oauth.Credentials{
		Token:  accessCreds.Token,
		Secret: accessCreds.Secret,
	}

	return createTwtr(auth, accessCreds, clientCreds, opt)
}

func createTwtr(client oauth.Client, accessCreds AccessCreds, clientCreds oauth.Credentials, option AuthOption) *twtr {
	req := requester{
		client:      client,
		clientCreds: clientCreds,
		option:      option,
	}
	return &twtr{
		account: account{
			requester: req,
		},
		requester:   req,
		accessCreds: accessCreds,
	}
}

// Twtr is interface of twitter object
type Twtr interface {
	Account() Account

	GetAccessCreds() AccessCreds
}

// Account is
type Account interface {
	UpdateProfileImage(opt UpdateProfileImageOption) (UpdateProfileImageResult, error)
}

type requester struct {
	client      oauth.Client
	clientCreds oauth.Credentials
	option      AuthOption
}

// twtr is twitter object
type twtr struct {
	requester

	account account

	accessCreds AccessCreds
}

func (t twtr) Account() Account {
	return t.account
}

type account struct {
	requester
}

func (t twtr) GetAccessCreds() AccessCreds {
	return t.accessCreds
}

// UpdateProfileImageOption is
type UpdateProfileImageOption struct {
	Image           []byte
	IncludeEntities OptionalBool
	SkipStatus      OptionalBool
}

// UpdateProfileImageResult is
type UpdateProfileImageResult struct {
}

func (a account) UpdateProfileImage(opt UpdateProfileImageOption) (UpdateProfileImageResult, error) {
	option := make(map[string]string)
	result := UpdateProfileImageResult{}

	option["image"] = base64.StdEncoding.EncodeToString(opt.Image)
	if opt.IncludeEntities.Valid && opt.IncludeEntities.Bool {
		option["include_entities"] = "t"
	}
	if opt.SkipStatus.Valid && opt.SkipStatus.Bool {
		option["include_entities"] = "t"
	}

	err := a.req(http.MethodPost, "/account/update_profile_image.json", option, result)
	if err != nil {
		return UpdateProfileImageResult{}, err
	}
	return result, err
}

func (r requester) req(method string, api string, opt map[string]string, res interface{}) error {
	param := make(url.Values)
	uri := r.option.APIEndpointURL + api

	for k, v := range opt {
		param.Set(k, v)
	}

	r.client.SignParam(&r.clientCreds, method, uri, param)

	var resp *http.Response
	var err error

	switch method {
	case http.MethodGet:
		uri = uri + "?" + param.Encode()
		resp, err = http.Get(uri)
	case http.MethodPost:
		resp, err = http.PostForm(uri, url.Values(param))
	default:
		return fmt.Errorf("method required GET or POST")
	}
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	if res == nil {
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(&res)
}
