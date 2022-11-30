<p align="center">
    <img alt="gotrxx" height="125" src="./docs/assets/logo.svg">
</p>
<a name="readme-top"></a>
<p align="center">
<strong>gotrxx</strong> is a <a href="https://github.com/netlify/gotrue">gotrue</a> API-compatible authorization server written in go, with support for OAuth <strong>Authorization Code Grant with PKCE</strong>, <strong>Client Credentials Grant</strong> and <strong>Password Grant</strong> (for gotrue compatibility).
</p>

[![Go Report Card](https://goreportcard.com/badge/github.com/eisenwinter/gotrxx)](https://goreportcard.com/report/github.com/eisenwinter/gotrxx) [![Go](https://github.com/eisenwinter/gotrxx/actions/workflows/go.yml/badge.svg)](https://github.com/eisenwinter/gotrxx/actions/workflows/go.yml) [![Project Status: WIP - Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip) [![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) [![DeepSource](https://deepsource.io/gh/eisenwinter/gotrxx.svg/?label=active+issues&show_trend=true&token=me84C5VKS4He2vcgb2VzJF2M)](https://deepsource.io/gh/eisenwinter/gotrxx/?ref=repository-badge) [![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org)


# gotrxx

> **Warning**
> I am moving stuff to github right now, a lot still needs furhter testing and polishing and docs are lacking

## Whats in the box

- **Authorization Code Grant** with Proof Key of Exchange for all your SPA and public needs.
- **Client Credentials Grant** for all your Backend and confidential client needs.
- **Password Grant** for gotrue compatibility
- **Discovery Endpoint** although it does **not** support OpenID-connect it has a discovery endpoint for convenient use with [oidc-client-ts](https://github.com/authts/oidc-client-ts)
- **Flexible signing and verification choice**  (HS256, HS384, HS512, RS256, RS384, RS512) token signing and verification (very special thanks to [jwx](https://github.com/lestrrat-go/jwx))
- **jwk** Endpoint when using RS* signing
- **Localization** of the pages
- **Administration Endpoints** which can be enabled if needed and wanted
- **2FA** with TOTP - works with MS Authenticator, Google Authenticator and Authy and others[^1]
- **Roles** for optional ACL implementations
- optional **Invite Only Setup** with pre-defined roles and application authorizations
- optional **Clicky Clicky Admin UI** gotrxx-admin

[^1]: Can not be used with Password Grant

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usecase

This authorization server can be used for either a restricted pool of people (like I do for my family and friends) or for public use. 
The main reason for this to exist is that I wanted to limit the access to applications to certain users, but still be able to make 
access-for-everyone applications as well.

Use this **if**
- you want an easy setup authorization server with OAuth support
- you have clients, friends, or family you wanna share certain (pre-approved) applications with them
- you don't need OpenID-connect
- a full-blown solution (ory, keycloak, identity server) is way too much
- want to set up a self-hosted Netlify CMS setup with something else then gotrue
- want an authorizations server that works with either SQLite, Postgres or MariaDB/MySQL

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Why

Well, I went a bit overboard. It all started when a family member of mine wanted to edit the static site I made for her and I went on to set up a self-hosted
version of netlify CMS. And things did not go as I wanted. Fast-forward - we are here after maniacally coding for weeks (okay it's been on and off for months at this point) because I disliked a few minor things about gotrue[^2].

[^2]: gotrue still is a good and well-thought-out solution tough (only love)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Quickstart

### Building from source

gotrxx is written and tested against Go 1.18+

```
git clone https://github.com/eisenwinter/gotrxx.git
```

```
go build main.go -o gotrxx
```

adapt the supplied `config.yml` to your needs and you are ready.

For further setup please refer to the documentation https://eisenwinter.github.io/gotrxx.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Docker Images

Yes. We have em.

```
docker run -v ./config.yml:/app/config.yml:ro ghcr.io/eisenwinter/gotrxx:latest
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Documentation 

If you want a deeper dive check out the documentation https://eisenwinter.github.io/gotrxx or see the `docs` folder. 
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## MFA

NOTE: the password flow will fail if you enable MFA on a user

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## OpenIDConnect

No. 

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Thanks and shout-outs to 

Thank everyone who wrote anything I used, this list in no special order.

go-chi for their awsome router
- github.com/go-chi/chi/

lestrrat for the awsome jwx libraries (wich do a lot of the heavy lifting)
- github.com/lestrrat-go/jwx

jaytaylor for not having me make plain text templates as well
- github.com/jaytaylor/html2text 

spf13 for cobra and viper
- github.com/spf13/cobra 
- github.com/spf13/viper

Masterminds for squirrel
- github.com/Masterminds/squirrel

jmoiron for sqlx
- github.com/jmoiron/sqlx 

joho for godotenv
- github.com/joho/godotenv 

jeremywohl for flatten 
- github.com/jeremywohl/flatten

mattn for the sqlite driver
- github.com/mattn/go-sqlite3

go-mail ... for mails
- github.com/go-mail/mail

adlio for the migrations
- github.com/adlio/schema

11ty - for making me not regret my static template choice twice
- https://www.11ty.dev/

AnandChowdhary for the language icons
- github.com/AnandChowdhary/language-icons

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Special thanks

Well, and of course ``gotrue``, this main inspiration to start this.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue for further questions or recommendations.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


## License

Distributed under the BSD-2-Clause license. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>