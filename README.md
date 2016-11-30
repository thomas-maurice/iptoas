# iptoasn

Maps IP addresses to AS information using
[Team Cymru's API](http://www.team-cymru.org/IP-ASN-mapping.html)

## Usage

This package only makes ose of the DNS API.

```golang
import (
	"fmt"
	"github.com/thomas-maurice/iptoasn/iptoasn"
    "os"
    "encoding/json"
)

func main() {
    // You have to specify which DNS resolver you want to use
	client := iptoasn.NewIPToASNResolver("8.8.8.8:53")
	ipinfo, err := client.GetAddressInfo("74.125.195.94")

    if err != nil {
		fmt.Println(fmt.Sprintf("Could not get IP information: %s", err))
		os.Exit(1)
	}

    b, err := json.Marshal(ipinfo)

    fmt.Println(string(b))
}
```

The above code would return something like
```json
{
    "as_number": 15169,
    "network": "74.125.195.0/24",
    "country_code": "US",
    "as_name": "GOOGLE - Google Inc.",
    "as_country_code": "US"
}
```

## License

    DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                       Version 2, December 2004

    Copyright (C) 2016 Thomas Maurice <thomas@maurice.fr>

    Everyone is permitted to copy and distribute verbatim or modified
    copies of this license document, and changing it is allowed as long
    as the name is changed.

               DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
      TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

     0. You just DO WHAT THE FUCK YOU WANT TO.
