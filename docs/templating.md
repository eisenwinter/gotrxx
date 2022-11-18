# How to template it to your needs

Gotrxx uses go HTML templates[^1]. Templates and all their needed assets are located in the `templates` folder.


```
templates
│   404.html
│   change_email.html
│   change_mfa.html
│   change_password.html
│   confirm.html
│   error.html
│   index.html
│   provision_mfa.html
│   recover_password.html
│   request_password_recovery.html
│   signin.html
│   signup.html
│   user.html
│
├───email
│       template.html
| ...
```

## Creating your templates

### Option A - Edit templates in the `template` folder. 

Edit all the HTML files in the template folder to your needs. 
Each template file consists of a single page, there is no templating mechanism such as `layouts` or `masterpages` in place.

Do not remove ``{{ .csrfField }}`` fields as those are used to protect against CSRF attacks.

If you want a more pleasant editing experience you may consider `Option B` below.


### Option B - Use `template_dev` 11ty template to create templates

Since the HTML files in the template folder are whole sites per file and updating them proved quite cumbersome I created a 11ty[^2] template to manage templating.

11ty is a static site generator, its main purpose is to generate static HTML.

To get started with 11ty you need an NPM package manager of your choice installed (yarn, npm, etc).

Change into the `template_dev` folder.

```
cd template_dev\
```

Install the dependencies either

with yarn 

```
yarn
```

with npm 

```
npm install
```

Once the dependencies are finished installing launch the dev server with

```
yarn dev
```

or 

```
npm run dev 
```

After starting the dev server you may navigate to `http://localhost:8000/`. 
You should see a list of all templates now.

Now you can begin editing the files in `template_dev/src`, any changes will be `hot reloaded` and displayed in your browser.

Once you are satisfied with your templates run 

```
yarn build 
```

or 

```
npm run build 
```


to generate the HTML templates. 
Your new templates are now located in `template_dev/templates`.

## Using the templates 

The templates can be integrated into the binary by building gotrxx from the source, just the binary needs to be deployed without any additional files. 

If no custom build is wanted the template files can be used with an existing binary, to archive this put the `templates` folder next to your gotrxx binary.

```
gotrxx
+ templates
│   404.html
│   change_email.html
│   ...
```

and configure your gotrxx with 

```
server:
  load-template-folder: true
```

or if you are using the environment variable-based configuration

```
TRXX_SERVER_LOAD_TEMPLATE_FOLDER=true
```


[^1]: https://pkg.go.dev/html/template
[^2]: https://www.11ty.dev/