package main

import "fmt"

type user struct {
	password string
	name     string
}

type userList []user

func (u userList) add(name, password string) {
	u = append(u, user{
		name: name, password: password,
	})
}

// This is the reversed function
func (u userList) contains(name string, password string) bool {
	for _, user := range u {
		if user.name == name && user.password == password {
			return true
		}
	}
	return false
}

func main() {
	fmt.Println("vim-go")
	users := new(userList)
	users.add("osx", "")
	users.contains("osx", "")
}
