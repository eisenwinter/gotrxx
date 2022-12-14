## gotrxx app create

Creates a new oauth application

### Synopsis

this command can be used to create a new oauth application

```
gotrxx app create [flags]
```

### Options

```
  -c, --con string             application confidentiality may be public or private depending on the kind of application (default "public")
  -f, --flow strings           the allowed grant flows for the application (authorization_code,password,client_credentials,refresh_token)
  -h, --help                   help for create
  -l, --logout-url strings     allowed logout uris
  -n, --name string            the name of the application
  -p, --pkce                   enables proof key of exchange
  -r, --redirect-url strings   allowed redirect uris
  -o, --scope string           application scopes separated by spaces
  -s, --secret string          the client secret for the application
  -k, --skip-if-exists         skips creation if client_id already exists and returns no error code
  -t, --type string            application type,may be either implicit_granted or explicit_granted (default "implicit_granted")
```

### Options inherited from parent commands

```
      --config string   config file to be used
```

### SEE ALSO

* [gotrxx app](/cli/gotrxx_app.md)	 - application commands

###### Auto generated by spf13/cobra on 21-Nov-2022
