package okta

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

func (o *Okta) GroupEveryone() (*Group, error) {
	req, err := o.newRequest(
		"GET",
		"/api/v1/groups?q=Everyone",
		nil,
	)
	if err != nil {
		return nil, err
	}

	resp, err := o.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("Unexpected response code: %d, %s", resp.StatusCode, string(respBodyBytes))
	}

	var groups []Group
	err = json.Unmarshal(respBodyBytes, &groups)
	if err != nil {
		return nil, err
	}

	for _, group := range groups {
		if group.Profile.Name == "Everyone" && group.Type == "BUILT_IN" {
			return &group, nil
		}
	}
	return nil, fmt.Errorf("Everyone group not found")
}

type Group struct {
	Created               string   `json:"created"`
	ID                    string   `json:"id"`
	LastMembershipUpdated string   `json:"lastMembershipUpdated"`
	LastUpdated           string   `json:"lastUpdated"`
	ObjectClass           []string `json:"objectClass"`
	Profile               struct {
		Description string `json:"description"`
		Name        string `json:"name"`
	} `json:"profile"`
	Type string `json:"type"`
}
