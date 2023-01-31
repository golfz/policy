package main

import (
	"fmt"
	"github.com/mastertech-hq/authority/jwtutils"
)

type user struct {
	uid      string
	userType string
}

func (u *user) UserID() string {
	return u.uid
}

func (u *user) UserType() string {
	return u.userType
}

func main() {
	u := &user{
		uid:      "1234",
		userType: "employee",
	}
	fmt.Println(jwtutils.GenerateToken(u))
}
