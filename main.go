package main

import (
	"fmt"
	"os"
	"strings"
)

var blocked = []string{"rm -rf", "git push --force", "git reset --hard"}

func main() {
	cmd := strings.Join(os.Args[1:], " ")
	for _, b := range blocked {
		if strings.Contains(cmd, b) {
			fmt.Println("blocked:", cmd)
			os.Exit(1)
		}
	}
	fmt.Println("ok")
}
