package gozabbix

import (
	"context"
	"encoding/json"
	"fmt"
)

// UserService wraps the "user" API namespace.
type UserService struct{ client *Client }

// User returns the user service.
func (c *Client) User() *UserService { return &UserService{c} }

// User object.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/object
type User struct {
	UserID          string   `json:"userid,omitempty"`
	Username        string   `json:"username,omitempty"`
	Passwd          string   `json:"passwd,omitempty"`
	RoleID          string   `json:"roleid,omitempty"`
	AttemptClock    string   `json:"attempt_clock,omitempty"`
	AttemptFailed   string   `json:"attempt_failed,omitempty"`
	AttemptIP       string   `json:"attempt_ip,omitempty"`
	Autologin       string   `json:"autologin,omitempty"`
	Autologout      string   `json:"autologout,omitempty"`
	Lang            string   `json:"lang,omitempty"`
	Name            string   `json:"name,omitempty"`
	Refresh         string   `json:"refresh,omitempty"`
	RowsPerPage     string   `json:"rows_per_page,omitempty"`
	Surname         string   `json:"surname,omitempty"`
	Theme           string   `json:"theme,omitempty"`
	TsProvisioned   string   `json:"ts_provisioned,omitempty"`
	URL             string   `json:"url,omitempty"`
	UserDirectoryID string   `json:"userdirectoryid,omitempty"`
	Timezone        string   `json:"timezone,omitempty"`
	UserGroups      []UsrGrp `json:"usrgrps,omitempty"`
	Medias          []Media  `json:"medias,omitempty"`
}

// UsrGrp is a user-group reference used when creating or updating users.
type UsrGrp struct {
	UsrGrpID string `json:"usrgrpid"`
}

// Media object.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/object
type Media struct {
	MediaTypeID          string `json:"mediatypeid,omitempty"`
	SendTo               any    `json:"sendto,omitempty"` // string or []string depending on media type
	Active               string `json:"active,omitempty"`
	Severity             string `json:"severity,omitempty"`
	Period               string `json:"period,omitempty"`
	UserDirectoryMediaID string `json:"userdirectory_mediaid,omitempty"`
}

// Session describes the authenticated user returned by user.login with userData.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/login
type Session struct {
	User
	Type          int    `json:"type"`
	UserIP        string `json:"userip"`
	DebugMode     int    `json:"debug_mode"`
	GUIAccess     string `json:"gui_access"`
	MfaID         int    `json:"mfaid"`
	Deprovisioned bool   `json:"deprovisioned"`
	AuthType      int    `json:"auth_type"`
	SessionID     string `json:"sessionid"`
	Secret        string `json:"secret"`
}

type loginParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
	UserData bool   `json:"userData,omitempty"`
}

// Login authenticates with a username and password, stores the returned session
// token on the client, and returns it.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/login
func (s *UserService) Login(ctx context.Context, username, password string) (string, error) {
	var raw json.RawMessage
	if err := s.client.do(ctx, "user.login",
		loginParams{Username: username, Password: password}, &raw, true); err != nil {
		return "", err
	}
	var token string
	if err := json.Unmarshal(raw, &token); err != nil {
		return "", fmt.Errorf("gozabbix: decode login token: %w", err)
	}
	s.client.SetToken(token)
	return token, nil
}

// LoginWithUserData authenticates and returns the full session details. The
// session token is stored on the client.
func (s *UserService) LoginWithUserData(ctx context.Context, username, password string) (*Session, error) {
	var session Session
	if err := s.client.do(ctx, "user.login",
		loginParams{Username: username, Password: password, UserData: true}, &session, true); err != nil {
		return nil, err
	}
	s.client.SetToken(session.SessionID)
	return &session, nil
}

// Logout invalidates the current session token on the server and clears it from
// the client. It is a no-op for pre-created API tokens (which cannot be logged
// out); callers using WithToken should not call Logout.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/logout
func (s *UserService) Logout(ctx context.Context) error {
	var ok bool
	if err := s.client.do(ctx, "user.logout", []any{}, &ok, true); err != nil {
		return err
	}
	s.client.SetToken("")
	return nil
}

// UserGetParams are the parameters for user.get.
type UserGetParams struct {
	GetParams
	UserIDs       []string `json:"userids,omitempty"`
	MediaIDs      []string `json:"mediaids,omitempty"`
	MediaTypeIDs  []string `json:"mediatypeids,omitempty"`
	UsrGrpIDs     []string `json:"usrgrpids,omitempty"`
	SelectMedias  any      `json:"selectMedias,omitempty"`
	SelectUsrGrps any      `json:"selectUsrgrps,omitempty"`
	SelectRole    any      `json:"selectRole,omitempty"`
	GetAccess     bool     `json:"getAccess,omitempty"`
}

// Get retrieves users matching params.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/get
func (s *UserService) Get(ctx context.Context, params UserGetParams) ([]User, error) {
	var users []User
	err := s.client.Call(ctx, "user.get", params, &users)
	return users, err
}

// Create creates one or more users and returns the new user ids.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/create
func (s *UserService) Create(ctx context.Context, users ...User) ([]string, error) {
	var res struct {
		UserIDs []string `json:"userids"`
	}
	err := s.client.Call(ctx, "user.create", users, &res)
	return res.UserIDs, err
}

// Update updates one or more users and returns the affected user ids.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/update
func (s *UserService) Update(ctx context.Context, users ...User) ([]string, error) {
	var res struct {
		UserIDs []string `json:"userids"`
	}
	err := s.client.Call(ctx, "user.update", users, &res)
	return res.UserIDs, err
}

// Delete deletes users by id and returns the deleted user ids.
// https://www.zabbix.com/documentation/current/en/manual/api/reference/user/delete
func (s *UserService) Delete(ctx context.Context, userIDs ...string) ([]string, error) {
	var res struct {
		UserIDs []string `json:"userids"`
	}
	err := s.client.Call(ctx, "user.delete", userIDs, &res)
	return res.UserIDs, err
}

// Login is a convenience shortcut for User().Login that discards the token
// (which is stored on the client regardless).
func (c *Client) Login(ctx context.Context, username, password string) error {
	_, err := c.User().Login(ctx, username, password)
	return err
}
