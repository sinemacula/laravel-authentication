# Changelog

## 1.0.0 (2026-10-31)


### ⚠ BREAKING CHANGES

* refresh through the session service and return its refusals ([#111](https://github.com/sinemacula/laravel-authentication/issues/111))
* name the outcomes of verification links ([#104](https://github.com/sinemacula/laravel-authentication/issues/104))
* name the outcomes of passkey and code verification ([#100](https://github.com/sinemacula/laravel-authentication/issues/100))
* report lifecycle events before binding the guard and make event snapshots queue-safe ([#96](https://github.com/sinemacula/laravel-authentication/issues/96))
* resolve every package table's connection from one storage setting ([#95](https://github.com/sinemacula/laravel-authentication/issues/95))
* keep earlier bindings and own the auth manager binding ([#94](https://github.com/sinemacula/laravel-authentication/issues/94))
* password policy and reset, identifier change, testing helpers and README ([#88](https://github.com/sinemacula/laravel-authentication/issues/88))
* one-time codes, passkeys, API keys, client credentials and scopes ([#87](https://github.com/sinemacula/laravel-authentication/issues/87))
* session lifecycle, event model, refresh transport and process safety ([#86](https://github.com/sinemacula/laravel-authentication/issues/86))
* add the session service, sign-in methods and per-guard policy ([#85](https://github.com/sinemacula/laravel-authentication/issues/85))
* device schema v2, refresh replay revocation and session lifetimes ([#84](https://github.com/sinemacula/laravel-authentication/issues/84))
* harden the guard, token and refresh paths ([#83](https://github.com/sinemacula/laravel-authentication/issues/83))
* remove legacy surfaces and require an HMAC signing key map ([#82](https://github.com/sinemacula/laravel-authentication/issues/82))

### Features

* add the session service, sign-in methods and per-guard policy ([#85](https://github.com/sinemacula/laravel-authentication/issues/85)) ([9295421](https://github.com/sinemacula/laravel-authentication/commit/92954215d8d6cff9e00c3b3bc477509f419e80cb))
* device schema v2, refresh replay revocation and session lifetimes ([#84](https://github.com/sinemacula/laravel-authentication/issues/84)) ([baeb834](https://github.com/sinemacula/laravel-authentication/commit/baeb834f85028ae4cd69e98dbc2a2ef766a87430))
* localise the messages the package shows consumers ([#105](https://github.com/sinemacula/laravel-authentication/issues/105)) ([50a40da](https://github.com/sinemacula/laravel-authentication/commit/50a40dac1107d2a5be19f044b70a9dd89e0afe74))
* name the outcomes of passkey and code verification ([#100](https://github.com/sinemacula/laravel-authentication/issues/100)) ([b7318fc](https://github.com/sinemacula/laravel-authentication/commit/b7318fc43c6bbf38a0fe74576562b328db4285b9))
* name the outcomes of verification links ([#104](https://github.com/sinemacula/laravel-authentication/issues/104)) ([6a6c1e7](https://github.com/sinemacula/laravel-authentication/commit/6a6c1e764df374e133db217177112aee657aff6a))
* one-time codes, passkeys, API keys, client credentials and scopes ([#87](https://github.com/sinemacula/laravel-authentication/issues/87)) ([3e57c06](https://github.com/sinemacula/laravel-authentication/commit/3e57c06c05f095779be125ae451dc15c08997414))
* password policy and reset, identifier change, testing helpers and README ([#88](https://github.com/sinemacula/laravel-authentication/issues/88)) ([27abe5b](https://github.com/sinemacula/laravel-authentication/commit/27abe5bac451f7871d8327e02d92fef7449147cb))
* refresh through the session service and return its refusals ([#111](https://github.com/sinemacula/laravel-authentication/issues/111)) ([624b571](https://github.com/sinemacula/laravel-authentication/commit/624b571c59d28703853c13e8126926687d8fbe5f))
* resolve every package table's connection from one storage setting ([#95](https://github.com/sinemacula/laravel-authentication/issues/95)) ([969a954](https://github.com/sinemacula/laravel-authentication/commit/969a95403982278a504ff9980e6dcac4d53ba38d))
* session lifecycle, event model, refresh transport and process safety ([#86](https://github.com/sinemacula/laravel-authentication/issues/86)) ([9abc553](https://github.com/sinemacula/laravel-authentication/commit/9abc55372c36acd16572d84cfe89696a111bc1a5))


### Bug Fixes

* **benchmarks:** widen anonymous CacheFactory::store() phpdoc ([#34](https://github.com/sinemacula/laravel-authentication/issues/34)) ([9c5b6f0](https://github.com/sinemacula/laravel-authentication/commit/9c5b6f0c357d422fee40b47a6af3639411637027))
* harden the guard, token and refresh paths ([#83](https://github.com/sinemacula/laravel-authentication/issues/83)) ([107f1a3](https://github.com/sinemacula/laravel-authentication/commit/107f1a3517b264f90420a530e554d5ff236a3d31))
* keep earlier bindings and own the auth manager binding ([#94](https://github.com/sinemacula/laravel-authentication/issues/94)) ([e1e4db3](https://github.com/sinemacula/laravel-authentication/commit/e1e4db392c8931724a01f7db68ad6d5b4d8324c1))
* report lifecycle events before binding the guard and make event snapshots queue-safe ([#96](https://github.com/sinemacula/laravel-authentication/issues/96)) ([22b98eb](https://github.com/sinemacula/laravel-authentication/commit/22b98eb5ca051ccf680be146c005d420ecc68677))
* send every deferred event through the dispatcher current at commit ([#109](https://github.com/sinemacula/laravel-authentication/issues/109)) ([ba51077](https://github.com/sinemacula/laravel-authentication/commit/ba5107709c4f3dbb0fc3f6a0aebe9559c38da738))


### Code Refactoring

* remove legacy surfaces and require an HMAC signing key map ([#82](https://github.com/sinemacula/laravel-authentication/issues/82)) ([3acb60d](https://github.com/sinemacula/laravel-authentication/commit/3acb60d5c2c663252029528760c39831903b7b91))
