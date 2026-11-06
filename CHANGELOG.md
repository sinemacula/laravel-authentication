# Changelog

## 1.0.0 (2026-11-06)


### ⚠ BREAKING CHANGES

* tokens borrow RFC 9068's claims, and sessions record their proofs ([#119](https://github.com/sinemacula/laravel-authentication/issues/119))
* the device record becomes a session, and every sign-in starts one ([#118](https://github.com/sinemacula/laravel-authentication/issues/118))
* British prose, American identifiers ([#117](https://github.com/sinemacula/laravel-authentication/issues/117))
* applications, not audiences or principal types ([#114](https://github.com/sinemacula/laravel-authentication/issues/114))
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

* a per-session issuance guard and an opaque provider context on provenance ([#129](https://github.com/sinemacula/laravel-authentication/issues/129)) ([86ec3ba](https://github.com/sinemacula/laravel-authentication/commit/86ec3ba68fa9545a51fc8b5345a4473944a4fb7a))
* add the session service, sign-in methods and per-guard policy ([#85](https://github.com/sinemacula/laravel-authentication/issues/85)) ([9295421](https://github.com/sinemacula/laravel-authentication/commit/92954215d8d6cff9e00c3b3bc477509f419e80cb))
* an authentication context, plain-value event context, Octane isolation, API keys after a failed JWT and conformant client credentials ([#128](https://github.com/sinemacula/laravel-authentication/issues/128)) ([a29d275](https://github.com/sinemacula/laravel-authentication/commit/a29d2751ceeb1ff9ef5a3ec65ac4bf52b0076c21))
* device schema v2, refresh replay revocation and session lifetimes ([#84](https://github.com/sinemacula/laravel-authentication/issues/84)) ([baeb834](https://github.com/sinemacula/laravel-authentication/commit/baeb834f85028ae4cd69e98dbc2a2ef766a87430))
* end an identity's or principal's sessions when it is deleted ([#139](https://github.com/sinemacula/laravel-authentication/issues/139)) ([5cc1417](https://github.com/sinemacula/laravel-authentication/commit/5cc1417d815678137bda3672f0a70ba5b00b4109))
* external sign-in and re-authentication through a link, assurance evidence and link-scoped revocation ([#127](https://github.com/sinemacula/laravel-authentication/issues/127)) ([c7b6b11](https://github.com/sinemacula/laravel-authentication/commit/c7b6b1198ca760d32ac44241d5c9e79fbb4d5127))
* factor package seams, code challenges, password changes, mandatory revocation and passkeys as a factor ([#123](https://github.com/sinemacula/laravel-authentication/issues/123)) ([193458e](https://github.com/sinemacula/laravel-authentication/commit/193458ee52d9ced6747981ae7e4fa8494e0d79a3))
* hand a passkey factor gate the client and a pending sign-in's credential ([#148](https://github.com/sinemacula/laravel-authentication/issues/148)) ([b3226d8](https://github.com/sinemacula/laravel-authentication/commit/b3226d803a9d99ce29b82e09f79b7a1f2e969c74))
* judge the current session again after a factor change ([#131](https://github.com/sinemacula/laravel-authentication/issues/131)) ([e38031e](https://github.com/sinemacula/laravel-authentication/commit/e38031e2cbb147049b8e56d92e2e564ab6971615))
* load listed principals' tenants, say when a token pair expires, and store active state as a deactivation time ([#132](https://github.com/sinemacula/laravel-authentication/issues/132)) ([3aa9577](https://github.com/sinemacula/laravel-authentication/commit/3aa9577405d650ab12d85c54bb142515992c2a91))
* localise the messages the package shows consumers ([#105](https://github.com/sinemacula/laravel-authentication/issues/105)) ([50a40da](https://github.com/sinemacula/laravel-authentication/commit/50a40dac1107d2a5be19f044b70a9dd89e0afe74))
* name the outcomes of passkey and code verification ([#100](https://github.com/sinemacula/laravel-authentication/issues/100)) ([b7318fc](https://github.com/sinemacula/laravel-authentication/commit/b7318fc43c6bbf38a0fe74576562b328db4285b9))
* name the outcomes of verification links ([#104](https://github.com/sinemacula/laravel-authentication/issues/104)) ([6a6c1e7](https://github.com/sinemacula/laravel-authentication/commit/6a6c1e764df374e133db217177112aee657aff6a))
* one plain-value method per action, with request helpers that feed it ([#143](https://github.com/sinemacula/laravel-authentication/issues/143)) ([d290a53](https://github.com/sinemacula/laravel-authentication/commit/d290a534e272349e5284cca3962f8242a7ef8f27))
* one-time codes, passkeys, API keys, client credentials and scopes ([#87](https://github.com/sinemacula/laravel-authentication/issues/87)) ([3e57c06](https://github.com/sinemacula/laravel-authentication/commit/3e57c06c05f095779be125ae451dc15c08997414))
* password policy and reset, identifier change, testing helpers and README ([#88](https://github.com/sinemacula/laravel-authentication/issues/88)) ([27abe5b](https://github.com/sinemacula/laravel-authentication/commit/27abe5bac451f7871d8327e02d92fef7449147cb))
* pending sessions, tenant policies, an active tenant and one switch ([#120](https://github.com/sinemacula/laravel-authentication/issues/120)) ([6fdbf6e](https://github.com/sinemacula/laravel-authentication/commit/6fdbf6ef52f1461a362b107dda3fdfabe0423a1d))
* read an active session's proofs and first factor, from the session service and a contribution subject ([#135](https://github.com/sinemacula/laravel-authentication/issues/135)) ([9fe6dc3](https://github.com/sinemacula/laravel-authentication/commit/9fe6dc3e7ba6297b8692bc9871104655de475d87))
* read an identity's passkey credential ids, and tell a passkey challenge that expired from one already used ([#147](https://github.com/sinemacula/laravel-authentication/issues/147)) ([9368fb5](https://github.com/sinemacula/laravel-authentication/commit/9368fb5f7f3efc45c207281d3f054bf7a906fca7))
* refresh through the session service and return its refusals ([#111](https://github.com/sinemacula/laravel-authentication/issues/111)) ([624b571](https://github.com/sinemacula/laravel-authentication/commit/624b571c59d28703853c13e8126926687d8fbe5f))
* refresh transport per application, sign-out by refresh token, held secrets and the request's caller ([#121](https://github.com/sinemacula/laravel-authentication/issues/121)) ([6361f00](https://github.com/sinemacula/laravel-authentication/commit/6361f004721114f92d3ba6941edfb24aeaf17a26))
* refresh, sign out and act on a pending session from plain values ([#138](https://github.com/sinemacula/laravel-authentication/issues/138)) ([b67df37](https://github.com/sinemacula/laravel-authentication/commit/b67df373d9cef8810ea36865bda8ced0a311b9aa))
* refuse a refresh credential proving another session than the one expected ([#145](https://github.com/sinemacula/laravel-authentication/issues/145)) ([6b72c4b](https://github.com/sinemacula/laravel-authentication/commit/6b72c4b30dee11af0851ce08a7ce1c1fa6b4de1b))
* resolve every package table's connection from one storage setting ([#95](https://github.com/sinemacula/laravel-authentication/issues/95)) ([969a954](https://github.com/sinemacula/laravel-authentication/commit/969a95403982278a504ff9980e6dcac4d53ba38d))
* say when another code may be requested on a sent code request ([#130](https://github.com/sinemacula/laravel-authentication/issues/130)) ([8bc971c](https://github.com/sinemacula/laravel-authentication/commit/8bc971cd0f870f3bfe2707b5cda711092558a284))
* session lifecycle, event model, refresh transport and process safety ([#86](https://github.com/sinemacula/laravel-authentication/issues/86)) ([9abc553](https://github.com/sinemacula/laravel-authentication/commit/9abc55372c36acd16572d84cfe89696a111bc1a5))
* tell a factor code's absent and used challenges apart from a wrong code ([#146](https://github.com/sinemacula/laravel-authentication/issues/146)) ([109564a](https://github.com/sinemacula/laravel-authentication/commit/109564abfa0703fedac7e0280ba4607c07159353))
* tokens borrow RFC 9068's claims, and sessions record their proofs ([#119](https://github.com/sinemacula/laravel-authentication/issues/119)) ([6448fba](https://github.com/sinemacula/laravel-authentication/commit/6448fba27cf5dec4f77c71607ed6d4120a2329db))


### Bug Fixes

* **benchmarks:** widen anonymous CacheFactory::store() phpdoc ([#34](https://github.com/sinemacula/laravel-authentication/issues/34)) ([9c5b6f0](https://github.com/sinemacula/laravel-authentication/commit/9c5b6f0c357d422fee40b47a6af3639411637027))
* end a session written while its subject was being deactivated or deleted, and bind plain-value calls with the client given ([#142](https://github.com/sinemacula/laravel-authentication/issues/142)) ([4603cca](https://github.com/sinemacula/laravel-authentication/commit/4603cca0cb912dc5382f08e2842df95042b2a7a2))
* harden the guard, token and refresh paths ([#83](https://github.com/sinemacula/laravel-authentication/issues/83)) ([107f1a3](https://github.com/sinemacula/laravel-authentication/commit/107f1a3517b264f90420a530e554d5ff236a3d31))
* keep earlier bindings and own the auth manager binding ([#94](https://github.com/sinemacula/laravel-authentication/issues/94)) ([e1e4db3](https://github.com/sinemacula/laravel-authentication/commit/e1e4db392c8931724a01f7db68ad6d5b4d8324c1))
* read a session's proofs current in every requirement judgement made under its lock ([#133](https://github.com/sinemacula/laravel-authentication/issues/133)) ([cbe7804](https://github.com/sinemacula/laravel-authentication/commit/cbe7804d6f7569e6af7daead94241c761a5da149))
* read a session's proofs current in freshness judgements under its lock, and run a password reset in the connection's transaction() ([#140](https://github.com/sinemacula/laravel-authentication/issues/140)) ([c2e9bfb](https://github.com/sinemacula/laravel-authentication/commit/c2e9bfb0ccfab6a26365aef6f4b510dedf53771d))
* refuse a cookie application's cross-site sign-in, start and pending-session actions ([#136](https://github.com/sinemacula/laravel-authentication/issues/136)) ([eafc95b](https://github.com/sinemacula/laravel-authentication/commit/eafc95b61a0654f9139f38a2499075e4136ceb49))
* remove control and bidirectional formatting characters from text a client supplies ([#144](https://github.com/sinemacula/laravel-authentication/issues/144)) ([d9becf8](https://github.com/sinemacula/laravel-authentication/commit/d9becf87fd4580823a7fc5495b382dd327162167))
* report lifecycle events before binding the guard and make event snapshots queue-safe ([#96](https://github.com/sinemacula/laravel-authentication/issues/96)) ([22b98eb](https://github.com/sinemacula/laravel-authentication/commit/22b98eb5ca051ccf680be146c005d420ecc68677))
* send every deferred event through the dispatcher current at commit ([#109](https://github.com/sinemacula/laravel-authentication/issues/109)) ([ba51077](https://github.com/sinemacula/laravel-authentication/commit/ba5107709c4f3dbb0fc3f6a0aebe9559c38da738))
* take a code check's attempt limit before judging the input's shape ([#149](https://github.com/sinemacula/laravel-authentication/issues/149)) ([3035caf](https://github.com/sinemacula/laravel-authentication/commit/3035cafbe797a47f1f7a528fd1e605132ae0d2b9))


### Code Refactoring

* applications, not audiences or principal types ([#114](https://github.com/sinemacula/laravel-authentication/issues/114)) ([3470b84](https://github.com/sinemacula/laravel-authentication/commit/3470b84e2e077a781bdbec5fe8cf938794f39dab))
* British prose, American identifiers ([#117](https://github.com/sinemacula/laravel-authentication/issues/117)) ([31878ca](https://github.com/sinemacula/laravel-authentication/commit/31878ca02c7f19afa7cbd5c5784d2d848bf3a483))
* remove legacy surfaces and require an HMAC signing key map ([#82](https://github.com/sinemacula/laravel-authentication/issues/82)) ([3acb60d](https://github.com/sinemacula/laravel-authentication/commit/3acb60d5c2c663252029528760c39831903b7b91))
* the device record becomes a session, and every sign-in starts one ([#118](https://github.com/sinemacula/laravel-authentication/issues/118)) ([c91ab14](https://github.com/sinemacula/laravel-authentication/commit/c91ab1418507ec3760d12881c9aacb58593474fb))
