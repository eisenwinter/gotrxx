# Configuration

This section explains how to gotrxx can be configured.
You may use a configuration file or environment variables to configure gotrxx,
but it is important to understand that environment variables always will take precedence
over the configuration file and configuration values from the configuration file will be overwritten by supplied environment variables.

## Minimal working example

This is the most basic configuration to run a gotrxx instance:

!> This is not a recommended setup for a production instance, this is rather for test drives

In `yaml` format for configuration files

```yaml
database:
  type: sqlite # databse to be used
  dsn: gotrxx?cache=shared # database dsn
server:
  port: 5000 # server to listen on
  address: localhost # address to listen on
  csrf-token: c3fS7yXw87Pth659QwtnA2bD # cross site request forgery token
behaviour:
  name: Example Instance # display name of the instance
  site: https://github.com/eisenwinter/gotrxx  # the main site of your project, corporation, etc
  service-domain: http://localhost:5000  # the service domain the gotrxx instance is running on
  invite-only: true # this instance may only be joined with an invite
jwt:
  alg: HS256 # use hmac
  iss: login.example.com # JWT issuer settings
  aud: 
    - https://github.com/eisenwinter/gotrxx # JWT audience settings
  hmac-signing-key: 'Y4GDth89TfwTTSHfwjjcWX7QtcszVZHGyPuHCT8wAcmKBVh6' # key used for signing and verifying the token
smtp:
  enable: false # disable all emails
```

or as environment variables:

```
PORT=5000
ADDRESS=localhost
TRXX_SERVER_CSRF_TOKEN=c3fS7yXw87Pth659QwtnA2bD
TRXX_DATABASE_TYPE=sqlite
TRXX_DATABASE_DSN=gotrxx?cache=shared
TRXX_BEHAVIOUR_NAME=Example Instance
TRXX_BEHAVIOUR_SITE=https://github.com/eisenwinter/gotrxx
TRXX_BEHAVIOUR_SERVICE_DOMAIN=http://localhost:5000
TRXX_BEHAVIOUR_INVITE_ONLY=true
TRXX_JWT_ALG=HS256
TRXX_JWT_ISSUER=login.example.com
TRXX_JWT_AUDIENCE=https://github.com/eisenwinter/gotrxx
TRXX_JWT_HMAC_SIGNING_KEY=Y4GDth89TfwTTSHfwjjcWX7QtcszVZHGyPuHCT8wAcmKBVh6
TRXX_SMTP_ENABLE=false
```


## Configuration File and environment variables

This section explains the entire configuration file and the corresponding environment variables.

### The Server Section

The server section contains the basic host configuration:

```yaml
server:
  port: 5000 # integer, port to be listen on
  address: localhost # string, address to listen on
  csrf-token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA # cross site request forgery token, change this
  load-template-folder: false # bool, indicates that the templates folder will be used instead of the embedded ressources
```

#### Default Values

Those default values apply if the configuration is not defined:

```
load-template-folder: false, when personalized HTML templates should be used set the value to true,
```

#### Corresponding environment variables:


```
PORT or TRXX_PORT -> server.port

ADDRESS OR TRXX_ADDRESS -> server.address

TRXX_SERVER_CSRF_TOKEN -> server.csrf-token

TRXX_SERVER_LOAD_TEMPLATE_FOLDER -> server.load-template-folder
```

### The SMTP Section

Configures the email settings to be used for emails.

?> It is highly recommended to configure a valid SMTP instance otherwise a lot of gotrxxs features will
not work correctly.

```yaml
smtp:
  enable: true # enables emails
  host: localhost # smtp address
  port: 2500 # smtp port
  username:  # smtp credentials: username
  password:  # smtp credentials: password
  display-name: Gotrxx Service # Display name for sent emails  (from: NAME)
  address: noreply@example.com # Display email for sent emails  (from: EMAIL)
```

#### Corresponding environment variables:

```
TRXX_SMTP_ENABLE -> smtp.enable

TRXX_SMTP_HOST -> smtp.host

TRXX_SMTP_PORT -> smtp.port

TRXX_SMTP_USERNAME -> smtp.username

TRXX_SMTP_PASSWORD -> smtp.password

TRXX_SMTP_DISPLAYNAME -> smtp.display-name

TRXX_SMTP_ADDRESS -> smtp.address
```

#### Default Values

Those default values apply if the configuration is not defined:

```
smtp.enable false - altough this is the default value this is **not** recommended.
```

### The Database Section

```yaml
database:
  type: sqlite # database driver
  dsn: dev.db?cache=shared  # connection string
```

Possible values for type are `sqlite`, `pg` and `mysql`.

`sqlite` is only recommended for small and medium sized deployments. There have been recent advancements that 
make it more viable as production setup, check out [Litestream](https://litestream.io/) for disaster recovery. 

`pg` (PostgresSQL) is the recommended database for larger deployments but `MySQL` or `MariaDB` may also be used, though those are less tested.


#### Corresponding environment variables:

```
TRXX_DATABASE_TYPE -> database.type

TRXX_DATABASE_DSN -> database.dsn
```


### The Behaviour Section
 

```yaml
behaviour:
  name: Gotrxx Identity Service Example # string, the display name for the service
  site: https://github.com/eisenwinter/gotrxx #  string, should be the main site, 404 excpect /account/ redirect there
  service-domain: http://localhost:5000 # string, domain this service is hosted on
  invite-only: true # bool, sign up is only possible with an invite
  invite-expiry: 36h # duration, invite expires after the given duration
  invite-role: inviter # string, default role for users that may invite other users
  default-locale: en # two letter iso code, standard locale to be used
  auto-lockout-count: 10 # int, number of maximal consecutive failed login attemps, -1 to disable
  auto-lockout-duration: 10m # duration, duration of lockout after auto-lockout-count is reached
  password-min-length: 6 # minimum lenght of passwords
```

#### Default Values

Those default values apply if the configuration is not defined:

```
behaviour.invite-role: "inviter"

behaviour.default-locale: "en"

behaviour.auto-confirm-users: false

behaviour.auto-lockout-count: 5

behaviour.auto-lockout-duration: 10m

behaviour.password-min-length: 6
```

#### Corresponding environment variables:

```
TRXX_BEHAVIOUR_NAME -> behaviour.name

TRXX_BEHAVIOUR_SITE -> behaviour.site

TRXX_BEHAVIOUR_SERVICE_DOMAIN -> behaviour.service-domain

TRXX_BEHAVIOUR_INVITE_ONLY -> behaviour.invite-only

TRXX_BEHAVIOUR_INVITE_ROLE -> behaviour.invite-role

TRXX_BEHAVIOUR_INVITE_EXPIRY -> behaviour.invite-expiry

TRXX_BEHAVIOUR_AUTO_CONFIRM_USERS -> behaviour.auto-confirm-users

TRXX_BEHAVIOUR_DEFAULT_LOCALE -> behaviour.default-locale

TRXX_BEHAVIOUR_AUTO_LOCKOUT_COUNT -> behaviour.auto-lockout-count

TRXX_BEHAVIOUR_AUTO_LOCKOUT_DURATION -> behaviour.auto-lockout-duration

TRXX_BEHAVIOUR_PASSWORD_MIN_LENGTH -> behaviour.password-min-length
```

### The JWT Section

```
jwt:
  flatten-audience: false # bool, flattens the audience to be a string instead of an array in the access token
  alg: RS256 # string, access token signing algorithm, may  be HS256, HS384, HS512, RS256, RS384, RS512
  iss: login.example.com # string, access token issuer
  aud: 
    - my-super-api.subkonstrukt.at # string, access token issuer
  no-roles-claim: false # bool, this enalbes the roles claim to be added to the access token, be sure to understand the implications of this, when in doubt set it to true
  exp: 900s # duration, access token expiry
  hmac-signing-key: 'mhm-yes-sign-me' # string, IF HS* alg is set, this is the signing key
  hmac-signing-key-file: '/home/jan/keys/my-hmac-key' # path, either supply key OR file
  rsa-public-key: '' # string, IF RS* alg is set
  rsa-public-key-file: '.dev/id_rsa.pub' # path, either supply key OR file
  rsa-private-key: '' # string
  rsa-private-key-file: '.dev/id_rsa' # path
  refresh-token-expiry: 3600s # duration, expiry of the refresh token
  remember-me-duration: 168h # duration, expiry of the remember me token
```

?> It is possible for the keys to supply them directly in configuration by using `hmac-signing-key` (HS* signing) or `rsa-public-key` and `rsa-private-key`. If you want to use files instead use the `hmac-signing-key-file` or `rsa-public-key-file` and `rsa-private-key-file` properties.

#### Example with symmetric signing key (HS256)

```yaml
jwt:
  flatten-audience: false
  alg: HS256 
  iss: login.example.com
  aud: 
    - my-super-api.subkonstrukt.at
  no-roles-claim: false
  exp: 900s
  hmac-signing-key: 'Wtv7rcpWtv7rcpKPhv8uBTMQKc5bMSmKPhv8uBTMQKc5bMSm'
  refresh-token-expiry: 3600s
  remember-me-duration: 168h
```

#### Example with asymmetric signing key (RS256)

```yaml
jwt:
  flatten-audience: false 
  alg: RS256
  iss: login.example.com
  aud: 
    - my-super-api.subkonstrukt.at
  no-roles-claim: false 
  exp: 900s
  rsa-public-key-file: '.dev/id_rsa.pub'
  rsa-private-key-file: '.dev/id_rsa'
  refresh-token-expiry: 3600s
  remember-me-duration: 168h
```

#### Default Values:

Those default values apply if the configuration is not defined:

```
jwt.flatten-audience: false

jwt.exp: 900s

jwt.refresh-token-expiry: 3600s

jwt.jwt.no-roles-claim: true

jwt.remember-me-duration: 168h
```

#### Corresponding environment variables:

```
TRXX_JWT_FLATTEN_AUDIENCE -> jwt.flatten-audience

TRXX_JWT_AUDIENCE -> jwt.aud

TRXX_JWT_ISSUER -> jwt.iss

TRXX_JWT_ALG -> jwt.alg

TRXX_JWT_EXP -> jwt.exp

TRXX_JWT_NO_ROLES_CLAIM -> jwt.no-roles-claim

TRXX_JWT_REFRESH_EXP -> jwt.refresh-token-expiry

TRXX_JWT_HMAC_SIGNING_KEY -> jwt.hmac-signing-key

TRXX_JWT_HMAC_SIGNING_KEY_FILE -> jwt.hmac-signing-key-file

TRXX_JWT_RSA_PRIVATE_KEY -> jwt.rsa-private-key

TRXX_JWT_RSA_PRIVATE_KEY_FILE -> jwt.rsa-private-key

TRXX_JWT_RSA_PUBLIC_KEY -> jwt.rsa-public-key

TRXX_JWT_RSA_PUBLIC_KEY_FILE -> jwt.rsa-public-key-file

TRXX_JWT_REMEMBER_ME_DURATION -> jwt.remember-me-duration
```

### The Manage Endpoint Section

```yaml
manage-endpoint:
  enable: true # enables the /manage/* endpoints
  cors:
    allowed-origins: # allowed origins for the manage endpoints (if enabled)
      - https://www.github.com
    allowed-methods: # allowed method for the manage endpoints (if enabled)
      - GET
      - POST
      - PUT
      - DELETE
      - OPTIONS
    allow-credentials: false
```

#### Default Values:

Those default values apply if the configuration is not defined:

```
manage-endpoint.enable: false
```

#### Corresponding environment variables:

```
TRXX_MANAGE_ENDPOINT_ENABLE -> manage-endpoint.enable

TRXX_MANAGE_ENDPOINT_CORS_ALLOWED_ORIGINS -> manage-endpoint.cors.allowed-origins

TRXX_MANAGE_ENDPOINT_CORS_ALLOWED_METHODS -> manage-endpoint.cors.allowed-methods

TRXX_MANAGE_ENDPOINT_CORS_ALLOW_CREDENTIALS -> manage-endpoint.cors.allow-credentials
```


### All YAML configuration options

The example below lists all possible configuration values

```
server:
  port: 5000
  address: localhost
  csrf-token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA # you need to replace this
  load-template-folder: false # indicates that the templates folder will be used instead of the embedded ressources
smtp:
  enable: true
  host: localhost
  port: 2500
  username: 
  password: 
  display-name: Gotrxx Service
  address: noreply@example.com
database:
  type: sqlite # mysql | pg
  dsn: dev.db?cache=shared  #"root@/gotrxx" 
behaviour:
  name: Gotrxx Identity Service Example
  site: https://github.com/eisenwinter/gotrxx # should be the main site, 404 excpect /account/ redirect there
  service-domain: http://localhost:5000 # domain this service is hosted on
  invite-only: true 
  invite-expiry: 36h
  invite-role: inviter # or admin
  default-locale: en
  auto-lockout-count: 10 # -1 to disable
  auto-lockout-duration: 10m
  password-min-length: 6
jwt:
  flatten-audience: false # you will either need a patched version of netlify components or set it to true
  alg: RS256 # HS256 | HS384 | HS512 | RS256 | RS384 | RS512
  iss: login.example.com
  aud: 
    - my-super-api.subkonstrukt.at
  no-roles-claim: false # this enalbes the roles claim to be added to the access token, be sure to understand the implications of this, when in doubt set it to true
  exp: 900s
  hmac-signing-key: 'mhm-yes-sign-me' # either this or a file
  hmac-signing-key-file: '/home/jan/keys/my-hmac-key' # only supply those when using HS*
  rsa-public-key: '' #only supply these with RS*
  rsa-public-key-file: '.dev/id_rsa.pub' #either supply key OR file
  rsa-private-key: ''
  rsa-private-key-file: '.dev/id_rsa'
  refresh-token-expiry: 3600s
  remember-me-duration: 168h
manage-endpoint:
  enable: true
  cors:
    allowed-origins: 
      - https://*
      - http://*
    allowed-methods:
      - GET
      - POST
      - PUT
      - DELETE
      - OPTIONS
    allow-credentials: false
```