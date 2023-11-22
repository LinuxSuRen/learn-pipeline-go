package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GetUserInfo sends the useinfo request, then returns the userInfo
func GetUserInfo(authServerURL, token string) (userInfo *UserInfo, err error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	var resp *http.Response
	if resp, err = http.DefaultClient.Do(req); err != nil {
		return
	}
	defer resp.Body.Close()

	fmt.Println("statusCode", resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		var data []byte
		if data, err = io.ReadAll(resp.Body); err != nil {
			return
		}

		fmt.Println(string(data))
		userInfo = &UserInfo{}
		err = json.Unmarshal(data, userInfo)
	}
	return
}

type UserInfo struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Picture           string   `json:"picture"`
	Groups            []string `json:"groups"`
}
