# Changelog

## [0.0.17](https://github.com/eisenwinter/gotrxx/compare/0.0.16...0.0.17) (2022-12-05)


### Bug Fixes

* loading external templates is working as intended now ([7c81907](https://github.com/eisenwinter/gotrxx/commit/7c81907e6c9dd17d26883b37b9f99f59a68aa597))
* qr code showing again, enabling mfa requires reentering the password ([9a5e18b](https://github.com/eisenwinter/gotrxx/commit/9a5e18b181b6299837272274ee6323e3385f181e))
* use safehtml over html/template, typed viewmodels instead of map[string]interface, fixed changed password ([bbb1421](https://github.com/eisenwinter/gotrxx/commit/bbb142103a15bfc6c659cc58fdcee9e5e1fc9f30))

## [0.0.16](https://github.com/eisenwinter/gotrxx/compare/0.0.15...0.0.16) (2022-12-04)


### Bug Fixes

* basic guard rails for preventing possible log injections ([00b0fc5](https://github.com/eisenwinter/gotrxx/commit/00b0fc5b03751dcf12933dfd8d4694cb36c76e1a))
* checkup for allowed redirectURI ([eea3a65](https://github.com/eisenwinter/gotrxx/commit/eea3a6507d0279220e9ca8cc095614bc870071a3))
* forced all redirects  within account to be on the same host to avoid pishin attacks ([726bcd2](https://github.com/eisenwinter/gotrxx/commit/726bcd23139dc00aeedae40906cdc3ea23f0f6bc))
* wrong invite code error fixed ([87bf034](https://github.com/eisenwinter/gotrxx/commit/87bf034bcb14bf6b0da50ec8bce564a18ac22e9a))
* wrong invite code error fixed ([c4e04ad](https://github.com/eisenwinter/gotrxx/commit/c4e04adea7fde29b9f714b511b1d10c3d8dc84ac))

## [0.0.15](https://github.com/eisenwinter/gotrxx/compare/0.0.14...0.0.15) (2022-12-03)


### Features

* added command to list all applications ([c0f0893](https://github.com/eisenwinter/gotrxx/commit/c0f0893e9fdc38a7cff60fa0bb8623d2ded704d7))
* command to list all invites ([adcbfbd](https://github.com/eisenwinter/gotrxx/commit/adcbfbdb9186edc45a8b257c8b297dcf848fe6eb))


### Bug Fixes

* clientcreds: removed check for app support of refreshtoken (pointless), changed bearer_token to the more common bearer type ([f135a34](https://github.com/eisenwinter/gotrxx/commit/f135a34403fb4a868c5f5b2bf2e8fd2f948ae019))

## [0.0.14](https://github.com/eisenwinter/gotrxx/compare/v0.0.13...0.0.14) (2022-12-02)


### Bug Fixes

* broken key loading introduced in a9cca51c9bb2e4e5fb5243f42ab1d78d4bdf48a5 ([01a6d9f](https://github.com/eisenwinter/gotrxx/commit/01a6d9fea266448e1de2fbb7f23fc4c3190319b8))

## [0.0.13](https://github.com/eisenwinter/gotrxx/compare/0.0.12...v0.0.13) (2022-12-01)


### Bug Fixes

* broken key loading introduced in a9cca51c9bb2e4e5fb5243f42ab1d78d4bdf48a5 ([01a6d9f](https://github.com/eisenwinter/gotrxx/commit/01a6d9fea266448e1de2fbb7f23fc4c3190319b8))
