# Translating gotrxx

Gotrxx uses the same approach as various `i18n` libraries for handling translations.

Navigate to the the `templates/i18n` folder. 

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
|
├───i18n
│       email.confirm.en.json
│       email.invite.en.json
│       email.reset_password.en.json
│       page.404.en.json
│       page.change_email.en.json
│       page.change_mfa.en.json
│       page.change_password.en.json
│       page.confirm.en.json
│       page.error.en.json
│       page.provision_mfa.en.json
│       page.recover_password.en.json
│       page.request_password_recovery.en.json
│       page.signin.en.json
│       page.signup.en.json
│       page.user.en.json
````

Each `json` file matches a template. 
The pattern for naming this files is always `type.template.locale.json`. 
Type can be either `email` or `page`. 


The locale string is a two ISO 2 letter language codes (ISO 639-1). 

If we want to translate it to German for example, we would copy the English files and change the locale code to `de`. 

```
├───i18n
│       email.confirm.en.json
│       email.invite.en.json
│       email.reset_password.en.json
│       page.404.en.json
│       page.change_email.en.json
│       page.change_mfa.en.json
│       page.change_password.en.json
│       page.confirm.en.json
│       page.error.en.json
│       page.provision_mfa.en.json
│       page.recover_password.en.json
│       page.request_password_recovery.en.json
│       page.signin.en.json
│       page.signup.en.json
│       page.user.en.json
|
│       email.confirm.de.json
│       email.invite.de.json
│       email.reset_password.de.json
│       page.404.de.json
│       page.change_email.de.json
│       page.change_mfa.de.json
│       page.change_password.de.json
│       page.confirm.de.json
│       page.error.de.json
│       page.provision_mfa.de.json
│       page.recover_password.de.json
│       page.request_password_recovery.de.json
│       page.signin.de.json
│       page.signup.de.json
│       page.user.de.json
```

The next step is to open each of our newly created `json` files with a text editor of you choice.

For example `page.signin.de.json`:

```
{
    "change_password": "change password",
    "change_email": "change email",
    "change_mfa": "change two-factor settings",
    "signout": "signout"
}
```

and translate all the right hand strings to German:


```
{
    "change_password": "Passwort ändern",
    "change_email": "Email ändern",
    "change_mfa": "Zwei-Faktor-Authentisierung",
    "signout": "Abmelden"
}
```

Repeat this for all `json` files and the German translation is done.


?> There are also various `i18n` tools which can assist you with this task, for a brief overview you can check out https://github.com/jpomykala/awesome-i18n#-desktop-apps-for-translation-management or do a quick Google search.


## ISO 639-1 codes


|  Language                                                                        |  ISO Code |
|----------------------------------------------------------------------------------|-----------|
| Abkhazian                                                                        | ab        |
| Afar                                                                             | aa        |
| Afrikaans                                                                        | af        |
| Akan                                                                             | ak        |
| Albanian                                                                         | sq        |
| Amharic                                                                          | am        |
| Arabic                                                                           | ar        |
| Aragonese                                                                        | an        |
| Armenian                                                                         | hy        |
| Assamese                                                                         | as        |
| Avaric                                                                           | av        |
| Avestan                                                                          | ae        |
| Aymara                                                                           | ay        |
| Azerbaijani                                                                      | az        |
| Bambara                                                                          | bm        |
| Bashkir                                                                          | ba        |
| Basque                                                                           | eu        |
| Belarusian                                                                       | be        |
| Bengali                                                                          | bn        |
| Bislama                                                                          | bi        |
| Bosnian                                                                          | bs        |
| Breton                                                                           | br        |
| Bulgarian                                                                        | bg        |
| Burmese                                                                          | my        |
| Catalan, Valencian                                                               | ca        |
| Chamorro                                                                         | ch        |
| Chechen                                                                          | ce        |
| Chichewa, Chewa,   Nyanja                                                        | ny        |
| Chinese                                                                          | zh        |
| Church Slavic, Old Slavonic, Church Slavonic, Old Bulgarian, Old Church Slavonic | cu        |
| Chuvash                                                                          | cv        |
| Cornish                                                                          | kw        |
| Corsican                                                                         | co        |
| Cree                                                                             | cr        |
| Croatian                                                                         | hr        |
| Czech                                                                            | cs        |
| Danish                                                                           | da        |
| Divehi, Dhivehi, Maldivian                                                       | dv        |
| Dutch, Flemish                                                                   | nl        |
| Dzongkha                                                                         | dz        |
| English                                                                          | en        |
| Esperanto                                                                        | eo        |
| Estonian                                                                         | et        |
| Ewe                                                                              | ee        |
| Faroese                                                                          | fo        |
| Fijian                                                                           | fj        |
| Finnish                                                                          | fi        |
| French                                                                           | fr        |
| Western Frisian                                                                  | fy        |
| Fulah                                                                            | ff        |
| Gaelic, Scottish Gaelic                                                          | gd        |
| Galician                                                                         | gl        |
| Ganda                                                                            | lg        |
| Georgian                                                                         | ka        |
| German                                                                           | de        |
| Greek, Modern (1453)                                                             | el        |
| Kalaallisut,   Greenlandic                                                       | kl        |
| Guarani                                                                          | gn        |
| Gujarati                                                                         | gu        |
| Haitian,   Haitian Creole                                                        | ht        |
| Hausa                                                                            | ha        |
| Hebrew                                                                           | he        |
| Herero                                                                           | hz        |
| Hindi                                                                            | hi        |
| Hiri Motu                                                                        | ho        |
| Hungarian                                                                        | hu        |
| Icelandic                                                                        | is        |
| Ido                                                                              | io        |
| Igbo                                                                             | ig        |
| Indonesian                                                                       | id        |
| Interlingua (International Auxiliary   Language Association)                     | ia        |
| Interlingue, Occidental                                                          | ie        |
| Inuktitut                                                                        | iu        |
| Inupiaq                                                                          | ik        |
| Irish                                                                            | ga        |
| Italian                                                                          | it        |
| Japanese                                                                         | ja        |
| Javanese                                                                         | jv        |
| Kannada                                                                          | kn        |
| Kanuri                                                                           | kr        |
| Kashmiri                                                                         | ks        |
| Kazakh                                                                           | kk        |
| Central Khmer                                                                    | km        |
| Kikuyu, Gikuyu                                                                   | ki        |
| Kinyarwanda                                                                      | rw        |
| Kirghiz, Kyrgyz                                                                  | ky        |
| Komi                                                                             | kv        |
| Kongo                                                                            | kg        |
| Korean                                                                           | ko        |
| Kuanyama, Kwanyama                                                               | kj        |
| Kurdish                                                                          | ku        |
| Lao                                                                              | lo        |
| Latin                                                                            | la        |
| Latvian                                                                          | lv        |
| Limburgan,   Limburger, Limburgish                                               | li        |
| Lingala                                                                          | ln        |
| Lithuanian                                                                       | lt        |
| Luba-Katanga                                                                     | lu        |
| Luxembourgish,   Letzeburgesch                                                   | lb        |
| Macedonian                                                                       | mk        |
| Malagasy                                                                         | mg        |
| Malay                                                                            | ms        |
| Malayalam                                                                        | ml        |
| Maltese                                                                          | mt        |
| Manx                                                                             | gv        |
| Maori                                                                            | mi        |
| Marathi                                                                          | mr        |
| Marshallese                                                                      | mh        |
| Mongolian                                                                        | mn        |
| Nauru                                                                            | na        |
| Navajo, Navaho                                                                   | nv        |
| North Ndebele                                                                    | nd        |
| South Ndebele                                                                    | nr        |
| Ndonga                                                                           | ng        |
| Nepali                                                                           | ne        |
| Norwegian                                                                        | no        |
| Norwegian Bokmål                                                                 | nb        |
| Norwegian Nynorsk                                                                | nn        |
| Sichuan Yi, Nuosu                                                                | ii        |
| Occitan                                                                          | oc        |
| Ojibwa                                                                           | oj        |
| Oriya                                                                            | or        |
| Oromo                                                                            | om        |
| Ossetian, Ossetic                                                                | os        |
| Pali                                                                             | pi        |
| Pashto, Pushto                                                                   | ps        |
| Persian                                                                          | fa        |
| Polish                                                                           | pl        |
| Portuguese                                                                       | pt        |
| Punjabi, Panjabi                                                                 | pa        |
| Quechua                                                                          | qu        |
| Romanian, Moldavian, Moldovan                                                    | ro        |
| Romansh                                                                          | rm        |
| Rundi                                                                            | rn        |
| Russian                                                                          | ru        |
| Northern Sami                                                                    | se        |
| Samoan                                                                           | sm        |
| Sango                                                                            | sg        |
| Sanskrit                                                                         | sa        |
| Sardinian                                                                        | sc        |
| Serbian                                                                          | sr        |
| Shona                                                                            | sn        |
| Sindhi                                                                           | sd        |
| Sinhala, Sinhalese                                                               | si        |
| Slovak                                                                           | sk        |
| Slovenian                                                                        | sl        |
| Somali                                                                           | so        |
| Southern Sotho                                                                   | st        |
| Spanish, Castilian                                                               | es        |
| Sundanese                                                                        | su        |
| Swahili                                                                          | sw        |
| Swati                                                                            | ss        |
| Swedish                                                                          | sv        |
| Tagalog                                                                          | tl        |
| Tahitian                                                                         | ty        |
| Tajik                                                                            | tg        |
| Tamil                                                                            | ta        |
| Tatar                                                                            | tt        |
| Telugu                                                                           | te        |
| Thai                                                                             | th        |
| Tibetan                                                                          | bo        |
| Tigrinya                                                                         | ti        |
| Tonga (Tonga Islands)                                                            | to        |
| Tsonga                                                                           | ts        |
| Tswana                                                                           | tn        |
| Turkish                                                                          | tr        |
| Turkmen                                                                          | tk        |
| Twi                                                                              | tw        |
| Uighur, Uyghur                                                                   | ug        |
| Ukrainian                                                                        | uk        |
| Urdu                                                                             | ur        |
| Uzbek                                                                            | uz        |
| Venda                                                                            | ve        |
| Vietnamese                                                                       | vi        |
| Volapük                                                                          | vo        |
| Walloon                                                                          | wa        |
| Welsh                                                                            | cy        |
| Wolof                                                                            | wo        |
| Xhosa                                                                            | xh        |
| Yiddish                                                                          | yi        |
| Yoruba                                                                           | yo        |
| Zhuang, Chuang                                                                   | za        |
| Zulu                                                                             | zu        |
