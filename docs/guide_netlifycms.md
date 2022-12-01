# Guide: self-hosted Netlify CMS

This guide is probably why you are here. 
It walks you through self-hosting the [netlifycms](https://www.netlifycms.org/) stack.

## Compose file deploy

This is the least friction deployment, with auto SSL (thanks to caddy) and SQLite.

We will be using docker-compose to spin up a git-gateway instance and a gotrxx instance running with SQLite.
Ingress is handled by the caddy reverse proxy.

### Checklist

Things we will need for setting this up.

- a host running docker (and compose)
- a domain, all examples below will use example.com as a placeholder
- a working email setup with useable SMTP settings.

### RSA Key

If you already have an RSA key to sign your gotrxx tokens you may skip this section.

To generate a new key open a terminal of your choice (or GitBash on Windows)

Type the following to generate a new key:

```sh
openssl genrsa -out my_key 4096
```

Now we generate a public key file by running:

```sh
openssl rsa -in my_key -RSAPublicKey_out -out my_key.pub
```

Your current working directory should contain two files now: `my_key` which is your private key and `my_key.pub` which contains your public key.

!> **Attention** keep your key safe from unauthorized access. If the key gets compromised all your issued access tokens are compromised. Take appropriate measures to protect it. 


### GitHub access token

The next step is to obtain a GitHub access token. The access token should belong to the account hosting the repository we want to 
use with netlify cms.

The GitHub documentation covers this right here: ['Creating a personal access token'](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)


### Setup the subdomains

Make sure you have two subdomains, one for gotrxx and one for the git gateway pointing to your machine. For this guide, I will be using `login.example.com` and `gitgateway.example.com`, adjust those to match your domain.

### Deply the compose stack

Replace the following environment variables in the docker-compose file below:

- example.com with your domain
- YOUR_GITHUB_ACCESS_TOKEN with your GitHub access token
- USER/REPO with your repository (Your repository is the url path marked bold github.com/**USERNAME/REPOSITORY**)
- YOUR_SMTP_USER, YOUR_SMTP_PASSWORD, smtp.example.com with your SMTP settings
- YOUR_CSRF_TOKEN with a random string, this will be used to securely generate cross-site request forgery tokens 
  - random.org for generation: [random.org](https://www.random.org/passwords/?num=1&len=24&format=html&rnd=new)
  - Generate by reading from urandom: ```</dev/urandom tr -dc 'A-Za-z0-9!"#$%&\(\)*+,.: ;<=>?@\[\]^_`{|}~-' | head -c 21  ; echo```
- /certs/private.key and /certs/public.key with the location of your key and pub file. 


Optional:
- INVITE_SEED a number to your liking to seed an initial admin account can be left blank if not wanted

> The supplied settings enable you to manage your instance with the GitHub hosted version of [gotrxx-admin](https://eisenwinter.github.io/gotrxx-admin/).  If you dont want this this feature simply remove the `TRXX_MANAGE_ENDPOINT_ENABLE`, `TRXX_MANAGE_ENDPOINT_CORS_ALLOWED_METHODS` and `TRXX_MANAGE_ENDPOINT_CORS_ALLOWED_ORIGINS` environment variables from the compose file.

Look through you the environment variables and change them as needed, if you need further information on their meaning check out [Configuration](config.md).

```docker-compose
services:
  caddy:
    image: lucaslorentz/caddy-docker-proxy:ci-alpine
    ports:
      - 80:80
      - 443:443
    environment:
      - CADDY_INGRESS_NETWORKS=caddy
    networks:
      - caddy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - caddy_data:/data
    restart: unless-stopped
  git-gateway:
    image: ghcr.io/eisenwinter/git-gateway:latest
    restart: unless-stopped
    networks:
      - caddy
    labels:
      caddy: gitgateway.example.com
      caddy.reverse_proxy: "{{upstreams http 9999}}"
    environment:
      GITGATEWAY_JWT_SIGNINGMETHOD: RS256
      GITGATEWAY_JWT_JWKS: https://login.example.com/.well-known/jwks
      GITGATEWAY_JWT_CLIENTID: "netlify-gotrue"
      GITGATEWAY_API_HOST: ""
      PORT: 9999
      GITGATEWAY_GITHUB_ACCESS_TOKEN: "YOUR_GITHUB_ACCESS_TOKEN"
      GITGATEWAY_GITHUB_REPO: "USER/REPO"
      GITGATEWAY_ROLES: "admin,cms"
  gotrxx:
    image: ghcr.io/eisenwinter/gotrxx:latest
    restart: unless-stopped
    networks:
      - caddy
    labels:
      caddy: login.example.com
      caddy.reverse_proxy: "{{upstreams http 3000}}"
    environment:
      PORT: 3000
      ADDRESS: ""
      TRXX_AUTO_SEED_INVITE: "INVITE_SEED"
      TRXX_SERVER_CSRF_TOKEN: YOUR_CSRF_TOKEN
      TRXX_SMTP_ENABLE: "true"
      TRXX_SMTP_HOST: smtp.example.com
      TRXX_SMTP_PORT: 465
      TRXX_SMTP_USERNAME: YOUR_SMTP_USER
      TRXX_SMTP_PASSWORD: YOUR_SMTP_PASSWORD
      TRXX_SMTP_DISPLAYNAME: My Service Name
      TRXX_SMTP_ADDRESS: noreply@example.com
      TRXX_DATABASE_TYPE: sqlite
      TRXX_DATABASE_DSN: /data/gotrxx/gotrxx.db?cache=shared&_journal_mode=WAL&mode=rwc
      TRXX_BEHAVIOUR_NAME: YOUR_SITE_NAME
      TRXX_BEHAVIOUR_SITE: https://example.com
      TRXX_BEHAVIOUR_SERVICE_DOMAIN: https://login.example.com
      TRXX_BEHAVIOUR_INVITE_ONLY: "true"
      TRXX_JWT_ALG: "RS256"
      TRXX_JWT_AUDIENCE: example.com
      TRXX_JWT_ISSUER: login.example.com
      TRXX_JWT_RSA_PRIVATE_KEY_FILE: "/certs/private.key"
      TRXX_JWT_RSA_PUBLIC_KEY_FILE: "/certs/public.key"
      TRXX_MANAGE_ENDPOINT_ENABLE: "true"
      TRXX_MANAGE_ENDPOINT_CORS_ALLOWED_METHODS: GET,POST,PUT,DELETE,OPTIONS
      TRXX_MANAGE_ENDPOINT_CORS_ALLOWED_ORIGINS: https://eisenwinter.github.io
    volumes:
      - gotrxx_db:/data/gotrxx/
      - ./certs/private.key:/certs/private.key:ro
      - ./certs/public.key:/certs/public.key:ro
volumes:
  gotrxx_db:
  caddy_data: 
networks:
  caddy:
```

Once you are done editing simply run:

```sh
docker-compose up
```

If everything is booting up correctly and you are satisfied with how things are launch the containers in detached mode. 

```sh
docker-compose up -d
```


### Creating your account

If you have the `INVITE_SEED` environment variable set in the compose file go to https://login.example.com/account/signup (once again replace example.com with your domain) and register using the INVITE_SEED value as the invite code.

If you did not set a `INVITE_SEED` you may create a new invite code by running: 

(replace `CONTAINERNAME` with the name or identifier of your gotrxx container)
```sh

docker container exec CONTAINERNAME /app/gotrxx invite seed --role admin --role inviter
```

Go to https://login.example.com/account/signup and register your account. 


### Creating the gotrxx-admin application

Skip this step if you did remove the `MANAGE_` variables and do not wish to use gotrxx-admin.

To generate the application needed to use the gotrxx-admin GitHub instance run the following command, but replace `CONTAINERNAME` with the name of your gotrxx container (if you are unsure run ```docker container ls```):

```sh
docker container exec CONTAINERNAME /app/gotrxx app create -c public -f authorization_code -f refresh_token -o offline_access -n gotrxx-admin -r https://eisenwinter.github.io/gotrxx-admin/#/oidc-callback -t implicit_granted -p  gotrxxadmin
```

For further information regarding gotrxx-admin see: [https://github.com/eisenwinter/gotrxx-admin](https://github.com/eisenwinter/gotrxx-admin)

### Configure netlify cms

Once everything is up and running configure netlify cms according to the documentation [https://www.netlifycms.org/docs/](https://www.netlifycms.org/docs/). I won't cover much of the details here just how to get it working with this stack.

Your index.html should look like this, as always replace example.com with your domain:

```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Content Manager</title>
  <script src="https://identity.netlify.com/v1/netlify-identity.js"></script>
  <!-- your config.yml location -->
  <link href="/admin/config.yml" type="text/yaml" rel="cms-config-url">
</head>
<body>
  <!-- Include the script that builds the page and powers Netlify CMS -->
  <script src="https://unpkg.com/netlify-cms@^2.0.0/dist/netlify-cms.js"></script>
<script>
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      netlifyIdentity.init({
        APIUrl: "https://login.example.com/.netlify"
      });
    });
  } else {
    netlifyIdentity.init({
      APIUrl: "https://login.example.com/.netlify"
    });
  }
</script>

</body>
</html>
```

In your `config.yml` set the backend section like this, once again replace example.com with your domain and USERNAME/repo with your repository:

```yaml
backend:
  name: git-gateway
  branch: master # Branch to update (optional; defaults to master)
  repo: USERNAME/repo
  identity_url: "https://login.example.com"
  gateway_url:  "https://gitgateway.example.com"
  site_domain:  "https://www.example.com" # or wherever your site is running on
... # rest of the configuration part ommited, please refer to the netlify cms docs for more information
```

### Things to consider

Don't forget to back up your docker volumes (gotrxx_db, caddy_data) so you can easily recover from disaster.

### Enjoy

If you made it this far you have a working self-hosted version of netlify cms now.
Enjoy.

If you had any trouble or something is unclear you can open an issue at: https://github.com/eisenwinter/gotrxx/issues 