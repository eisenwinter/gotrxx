# Guide: self-hosted Netlify CMS

## Compose file deploy

explain how to run the whole stack

Least friction deploys, with auto SSL and SQLite.

This assumes you have a domain, `example.com`` is used as a placeholder.


Required:

- a domain (example.com is used as a placeholder)
- a GitHub access token (YOUR_GITHUB_ACCESS_TOKEN is used as a placeholder)
- a GitHub repository with your site hosted (USER/REPO is used as a placeholder)
- an email address (with valid SMTP settings, YOUR_SMTP_USER, YOUR_SMTP_PASSWORD placeholders)
- a random string for the cross-site request forgery token (YOUR_CSRF_TOKEN is used as a placholder) ([random.org](https://www.random.org/passwords/?num=1&len=24&format=html&rnd=new) or ```</dev/urandom tr -dc 'A-Za-z0-9!"#$%&\(\)*+,.: ;<=>?@\[\]^_`{|}~-' | head -c 21  ; echo``` 
- an RSA certificate 


Optional:
- INVITE_SEED a number to your liking to seed an initial admin account can be left blank if not wanted

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

## Manual walkthrough