/*
    DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                       Version 2, December 2004

    Copyright (C) 2016 Thomas Maurice <thomas@maurice.fr>

    Everyone is permitted to copy and distribute verbatim or modified
    copies of this license document, and changing it is allowed as long
    as the name is changed.

               DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
      TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

     0. You just DO WHAT THE FUCK YOU WANT TO.
*/
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/thomas-maurice/iptoas/iptoas"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("You must provide an IP to analyze !")
		os.Exit(1)
	}
	client := iptoas.NewIPToASNResolver("8.8.8.8:53")
	ipinfo, err := client.GetAddressInfo(os.Args[1])

	if err != nil {
		fmt.Println(fmt.Sprintf("Could not get IP information: %s", err))
		os.Exit(1)
	}

	var prettyJSON bytes.Buffer
	b, err := json.Marshal(ipinfo)

	if err != nil {
		fmt.Println(fmt.Sprintf("Could not marshal json: %s", err))
		os.Exit(1)
	}

	error := json.Indent(&prettyJSON, b, "", "    ")
	if error != nil {
		fmt.Println("JSON parse error: ", error)
		os.Exit(1)
	}

	fmt.Println(prettyJSON.String())
}
