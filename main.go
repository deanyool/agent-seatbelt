package main

import (
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

type rule struct {
	Command    string   `yaml:"command"`
	Subcommand string   `yaml:"subcommand"`
	Flags      []string `yaml:"flags"`
}

type rules struct {
	Deny []rule `yaml:"deny"`
}

func (r rule) matches(words []string) bool {
	if words[0] != r.Command {
		return false
	}
	if r.Subcommand != "" && (len(words) < 2 || words[1] != r.Subcommand) {
		return false
	}
	if len(r.Flags) == 0 {
		return true
	}
	for _, w := range words {
		for _, f := range r.Flags {
			if w == f {
				return true
			}
		}
	}
	return false
}

func main() {
	data, err := os.ReadFile("rules.yaml")
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	var cfg rules
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	words := strings.Fields(strings.Join(os.Args[1:], " "))
	if len(words) == 0 {
		return
	}
	for _, r := range cfg.Deny {
		if r.matches(words) {
			fmt.Println("blocked:", strings.Join(words, " "))
			os.Exit(1)
		}
	}
	fmt.Println("ok")
}
