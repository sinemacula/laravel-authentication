# Identity Models

## 2D adoption (identity is the principal)

One model implements both `Identity` and `Principal` - the user who logs in *is* the acting principal:

```php
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;

class AppUser extends User implements Identity, Principal
{
    use Authenticatable, ActsAsPrincipal;
}
```

Point `auth.providers.users.model` at `AppUser::class`. `Auth::identity()` and `Auth::principal()` both return
the same instance.

Add `HasSessions` for session tracking and refresh-token rotation:

```php
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Models\Session;

class AppUser extends User implements Identity, Principal, HasSessions
{
    use Authenticatable, ActsAsPrincipal;

    public function sessions(): MorphMany
    {
        return $this->morphMany(Session::class, 'authenticatable');
    }
}
```

The relation must query the configured session model, or another model that implements `EloquentSession`: the bearer
path, sign-in pins, the session list and revocations all read it, and a relation over any other model throws a
`LogicException`.

`Models\Session` shares its short name with Laravel's `Session` facade and `Illuminate\Contracts\Session\Session`. The
explicit `use` above takes precedence over the facade alias in that file; a file that needs Laravel's session as well
imports one of them under another name, for example
`use SineMacula\Laravel\Authentication\Models\Session as AuthenticationSession;`. The package's sessions table is
`authentication_sessions`, so it never collides with the `sessions` table of Laravel's database session driver.

## 3D adoption (separate identity, principal, tenant)

For multi-tenant apps where the logged-in human acts on behalf of a tenant-scoped actor, split identity and
principal into two models. The identity implements `HasPrincipals` and returns its own principals query:

```php
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal as PrincipalContract;
use SineMacula\Laravel\Authentication\Contracts\Tenant as TenantContract;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;

class AppIdentity extends User implements Identity, HasSessions, HasPrincipals
{
    use Authenticatable;

    public function principals(): HasMany
    {
        return $this->hasMany(AppMembership::class, 'identity_id');
    }

    public function sessions(): MorphMany
    {
        return $this->morphMany(Session::class, 'authenticatable');
    }

    public function resolveDefaultPrincipal(): ?PrincipalContract
    {
        return $this->principals()->where('is_active', true)->first();
    }
}

class AppMembership extends Model implements CanBeActive, PrincipalContract
{
    use ActsAsPrincipal, ProvidesActiveState;

    protected $fillable = ['identity_id', 'tenant_id', 'role', 'is_active'];

    public function identity(): BelongsTo
    {
        return $this->belongsTo(AppIdentity::class, 'identity_id');
    }

    public function tenant(): BelongsTo
    {
        return $this->belongsTo(AppTenant::class);
    }
}

class AppTenant extends Model implements TenantContract
{
    use ActsAsTenant;
}
```

With that shape:

- `Auth::identity()` returns the `AppIdentity`.
- `Auth::principal()` returns the `AppMembership` - resolved via `principals()->find($principalId)` from the token's
  `principal` (every access token carries one), or via `resolveDefaultPrincipal()` on sign-in and on a refresh token
  issued without a principal.
- `Auth::tenant()` returns the `AppTenant` the membership belongs to.
- A membership whose `is_active` is `false` cannot sign in, refresh, or authenticate a request (see
  [Active-state enforcement](#active-state-enforcement)).

Implement `ResolvesHintedPrincipal` on the identity to replace the default `principals()->find($hint)` lookup
with a custom query - for example, joining the tenant row in one SQL so `Auth::tenant()` does not lazy-load.

For domain-specific resolution (subdomain, header, session claim), implement `PrincipalResolver` and bind it in
a service provider. A hint can come from a caller pinning a principal on `attempt()`, so a custom resolver or
`resolveHintedPrincipal()` must look the hint up among the identity's own principals only, never by the hint alone:

```php
$this->app->singleton(PrincipalResolver::class, MyTenantScopedResolver::class);
```

## Which principals may use an application

Which principals may use an application is the `ApplicationAccess` contract's answer: the package's admits every
principal, so bind your own to refuse some (see
[Extending](extending.md#deciding-which-principals-may-use-an-application)). Which tenants a principal may act in is
`TenantAccess`'s: by default only its own, or none for a platform principal. What a principal may do is
authorisation's.

## The active tenant

A session acts in one tenant, its active tenant, or in none. By default it is the principal's own tenant (the one its
`getTenant()` returns), or none for a platform principal. A sign-in may ask for another
(`new SignInContext($client, tenant: TenantSelection::of($tenantId))`), and a switch may move to another, once the
application lets the principal act there (see
[Extending](extending.md#letting-principals-act-in-other-tenants)). The package never sees the tenant tree: it carries
a tenant only as an opaque identifier, a string the session records in `tenant_id`, and finds a tenant other than the
principal's own through the `TenantResolver` you bind. Every access token of the session names it in `tenant_id`, and
`Auth::tenant()` returns it.

On every request a session's token must name the tenant the session acts in (`session_tenant_mismatch`), and that
tenant must still resolve and be active (`tenant_inactive`), as must the principal's own tenant: deactivating either
stops the session's tokens at once. A refresh asks `TenantAccess` again, so a principal no longer allowed in its active
tenant cannot refresh there (`tenant_ineligible`). `tenantDeactivated()` ends the sessions of the principals you list
for the tenant and every session acting in it, whichever principal it acts as.

## Identifiers

Designate the attributes people sign in with as identifiers, so each is stored and looked up in one normal form. Cast
the attribute with `NormalizedIdentifier`, naming its identifier type:

```php
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;

class AppUser extends User implements Identity, Principal
{
    use Authenticatable, ActsAsPrincipal;

    protected function casts(): array
    {
        return [
            'email' => NormalizedIdentifier::using('email'),
        ];
    }
}
```

Setting the attribute stores what the type's normaliser returns: the `email` normaliser trims surrounding whitespace
and lower-cases the whole address, so `Ben@Example.com` is stored as `ben@example.com`. A value it rejects (blank, or
not valid UTF-8) throws an `InvalidArgumentException` naming the attribute but never the value; `null` stays `null`.
Reading returns the stored value unchanged. The `model` provider normalises a credential for a designated attribute
the same way before it looks the identity up (`attempt(['email' => ' BEN@example.com', ...])` finds `ben@example.com`),
element by element for an array, and a value the normaliser rejects finds nobody without a query. Closures and
attributes that are not designated are applied as given.

Normalisers are registered by identifier type in the published config, as container abstracts resolving to a
`Contracts\IdentifierNormalizer`. A type is a lower-case letter followed by lower-case letters, digits and
underscores:

```php
'identifiers' => [
    'normalizers' => [
        'email'         => SineMacula\Laravel\Authentication\Identifiers\EmailNormalizer::class,
        'phone'         => SineMacula\Laravel\Authentication\Identifiers\E164PhoneNormalizer::class,
        'member_number' => App\Auth\MemberNumberNormalizer::class,
    ],
],
```

A normaliser must be deterministic and idempotent (normalising a normal form returns it unchanged), and return `null`
for a value that cannot be an identifier of its type. A malformed map, or an abstract that does not resolve to a
normaliser, fails closed with an `InvalidArgumentException`.

The shipped `phone` normaliser accepts only a number already in E.164 form (`+`, a country code, at most 15 digits in
all, surrounding whitespace removed) and refuses anything else: spaces, dashes, brackets, a national format or a leading
`00`. It does not parse numbers, since turning what a person types into E.164 depends on their country and on numbering
plans that change. To take mobile or free-form numbers, install `giggsey/libphonenumber-for-php` (the package suggests
it but does not require it) and bind a normaliser of your own under `phone`:

```php
use libphonenumber\NumberParseException;
use libphonenumber\PhoneNumberFormat;
use libphonenumber\PhoneNumberType;
use libphonenumber\PhoneNumberUtil;
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;

final readonly class MobileNumberNormalizer implements IdentifierNormalizer
{
    public function normalize(string $identifier): ?string
    {
        $numbers = PhoneNumberUtil::getInstance();

        try {
            $number = $numbers->parse($identifier, 'GB'); // the region a number without `+` belongs to
        } catch (NumberParseException) {
            return null;
        }

        $mobile = in_array($numbers->getNumberType($number), [PhoneNumberType::MOBILE, PhoneNumberType::FIXED_LINE_OR_MOBILE], true);

        return $numbers->isValidNumber($number) && $mobile ? $numbers->format($number, PhoneNumberFormat::E164) : null;
    }
}
```

```php
'identifiers' => ['normalizers' => ['email' => EmailNormalizer::class, 'phone' => App\Auth\MobileNumberNormalizer::class]],
```

It must return E.164 (so normalising its own output returns it unchanged), and existing rows must be normalised to it
before a unique index is added, as below.

Make the identifier unique on its normalised value, with a unique index on the stored column:

1. Normalise the rows you already have before adding the index, in a migration or a one-off command that saves each
   identity again (the cast normalises on set), or with SQL equivalent to the normaliser (`UPDATE users SET email =
   LOWER(TRIM(email))` for email, checking first for addresses that collide once normalised).
2. Then add the unique index on the column itself, not on an expression, so it holds whoever writes the row.

Why both engines need it: PostgreSQL compares strings case-sensitively, so without normalisation `Ben@x.com` and
`ben@x.com` are two accounts and a lookup with the other casing finds neither; MySQL's default `_ci` collations
compare them as equal, so lookups match but a unique index rejects the second address only by accident of the
collation, and `LOWER()` and the collation can disagree on non-ASCII letters. Storing the normal form makes both
behave the same, and lets the index mean what the application means.

A successful password sign-in rehashes the password when the hasher reports the stored hash outdated (a new algorithm or
cost) and Laravel's `hashing.rehash_on_login` is on; never on bearer requests, refresh, `validate()`, or a session
started with `start()` or `signInExternally()` or activated with `satisfy()` or `choose()`, which check no password. The
`model` provider writes the new hash with one conditional update, `WHERE <key> = :id AND <password> = :checkedHash`, so
a password changed between the check and the rehash is never overwritten with a hash of the old one; the write fires no
model events and leaves `updated_at` alone. A hash that does not come from the model's own password attribute (a
`getAuthPassword()` that reads another table) is not rehashed by the provider.

## Identifier verification

Implement `HasVerifiableIdentifiers` on the identity to let the package verify its identifiers and gate sign-in on
them. The `ProvidesIdentifierVerification` trait reads the identifier of a type from the column named after it
(`email`) and its verification time from `<type>_verified_at` (`email_verified_at`, as Laravel's own verification
uses), and throws a `LogicException` for an identity loaded without either column:

```php
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;

class AppUser extends User implements HasVerifiableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierVerification;
}
```

A type is a lower-case letter followed by lower-case letters, digits and underscores (`email`, `phone`). Recording a
verification reads the identity's row again under a lock (`SELECT ... FOR UPDATE`) and sets `<type>_verified_at` only
when the row's identifier is the proven one byte for byte and still unverified, all in one transaction, so a proof for
one address can never verify another, even when the address changes while the proof is checked to one the column's
collation counts as equal (`Ben@` or `bén@` for `ben@`); it fires no model events and leaves `updated_at` alone. When
an identifier changes, clear its `<type>_verified_at` with it, or change it through
[`Auth::identifierChanges()`](identifier-changes.md), which records the proven one as verified.

Verify by signed link with `Verification\VerificationLinks`. The application owns the route, the message and its
delivery:

```php
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;

// Send it: a signed link to your route, valid for `verification.link_ttl_minutes` (60 by default), held as a
// Secret until you reveal it into the message.
$url = app(VerificationLinks::class)->create('api', $user, 'email', 'verification.verify')->reveal();

// Your route: verified, already_verified, mismatch, invalid or expired.
Route::get('/verify-email', function (Request $request, VerificationLinks $links) {
    return match ($links->consume(SignedLink::fromRequest($request), ClientContext::fromRequest($request))) {
        VerificationLinkOutcome::VERIFIED, VerificationLinkOutcome::ALREADY_VERIFIED => response()->noContent(),
        VerificationLinkOutcome::EXPIRED                                             => abort(410, 'Request a new link.'),
        VerificationLinkOutcome::MISMATCH, VerificationLinkOutcome::INVALID          => abort(403),
    };
})->name('verification.verify');
```

A link is signed for its purpose (`verify_identifier`), its JWT guard, its identity, the identifier type and a SHA-256
digest of the identifier in its normal form; it never carries the identifier itself. It stops working when it expires or
when the identifier changes, and it verifies nothing for a guard that is not a JWT guard or an identity that cannot
verify identifiers. `create()` takes the route's own parameters (but not the reserved `guard`, `identity`, `type`,
`purpose`, `hash`, `expires` or `signature`, which the route's path may not use as placeholders either) and an optional
lifetime in minutes (1 to 10080, a week, like the configured one). Consuming a link loads the identity through the
guard's identity provider from the write connection and verifies the identifier; it never signs anyone in. Following it
again reports `already_verified`.

`consume($link, $client)` takes the link as `SignedLink::fromRequest($request)` captured it from the request (the address
the client used, through the application's trusted proxies, and the raw query string as received) and the request's
`ClientContext`, which its events describe, and answers a `VerificationLinkOutcome`. It checks the link's fields and
purpose, then its signature (with every key and previous key the application signs with), then its expiry, again from
those values, before it reads any identity: a link that was tampered with, signed for something else or carries no
well-formed expiry is `invalid` (expired or not), and an authentic link past its lifetime is `expired`, whatever has
become of its identity since. A link for a guard that is no longer a JWT guard, an identity that is gone or cannot
verify identifiers, or an identifier that has changed or been removed is `invalid` too, so the answer says nothing
about the account. Each refusal is reported by `AuthenticationFailed` on the `identifier_verification` flow, as
`invalid_credentials` or `link_expired`; its context names the guard only once the signature is correct, and the
identity only when it was loaded to check the digest. `verified` dispatches `IdentifierVerified` once the record
commits. `mismatch` is the verifier's answer for an identifier that changed while the link was being checked: nothing
is recorded or reported. Laravel's `signed` middleware, if you add it to the route, answers an expired link with its own
403 before `consume()` runs, so the route never sees `expired` and nothing is reported; leave it off to tell the two
apart.

`consume()` answers one enum, `VerificationLinkOutcome`. Match it:

```php
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\Verification\Enums\VerificationLinkOutcome;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;

$outcome = app(VerificationLinks::class)->consume(SignedLink::fromRequest($request), ClientContext::fromRequest($request));

return match ($outcome) {
    VerificationLinkOutcome::VERIFIED, VerificationLinkOutcome::ALREADY_VERIFIED => response()->noContent(),
    VerificationLinkOutcome::EXPIRED                                             => abort(410, 'Request a new link.'),
    VerificationLinkOutcome::MISMATCH, VerificationLinkOutcome::INVALID          => abort(403),
};
```

Verify by one-time code with `Auth::codes($guard)`: `sendVerification()` sends a code to the identity's current
identifier of the type and answers its challenge id, and `verify()` checks the code for that challenge and records the
verification:

```php
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;

// Send it: a code to the signed-in identity's phone number, delivered by your OneTimeCodeSender.
$sent = Auth::codes('mobile')->sendVerification(Auth::identity(), 'phone', ClientContext::fromRequest($request)); // sent, rate_limited, deliveries_exhausted or identifier_invalid
$sent->challengeId;                                                                                                // hand it to the client with the request

// Check it: verified, already_verified, mismatch, invalid, expired, exhausted or rate_limited.
$result = Auth::codes('mobile')->verify(Auth::identity(), 'phone', $input['challenge'], $input['code'], ClientContext::fromRequest($request));

abort_unless(in_array($result->outcome, [VerificationOutcome::VERIFIED, VerificationOutcome::ALREADY_VERIFIED], true), 422);
```

A verification code is bound to its purpose, its guard, its identity and the identifier in its normal form, so it
verifies nothing else, signs no one in, and stops working when the identifier changes: `sendVerification()` and
`verify()` read the identifier from the identity they are given (load it from the write connection, as the guard does),
and the delivery job reads the identity again from the write connection and sends nothing once its identifier is no
longer the one the code is bound to. Requests are held to the `code_request` limits, the resend cooldown and the
delivery cap, and the code to the same lifetime, attempts and single use as a sign-in code, a resend keeping its
challenge (see [One-time codes](configuration.md#one-time-codes)). Each check of a well-formed code and challenge id
counts against the identity's account and the IP address (`rate_limits.identifier_verification`), and a correct one
gives its slots back; an identity or address out of checks answers `rate_limited`, with the wait on the result and on
the report. `verify()` answers a `RateLimiting\LimitedOutcome`, whose `outcome`, a `VerificationOutcome`, is `verified`
when this call recorded the identifier verified (`is(VerificationOutcome::VERIFIED)`), `already_verified` when it was
before. A refused check answers `invalid`, `expired` or `exhausted` as it is (the caller already holds the identity),
and reports `invalid_credentials`, `code_expired` or `code_exhausted` with `AuthenticationFailed` on the
`identifier_verification` flow. A right code whose identifier changed after the identity you passed was loaded is used
up and answers `mismatch`, as a link does: nothing is recorded or reported, and the identity can request a code for its
new identifier. An identity with no identifier of the type, or one its normaliser rejects, is `identifier_invalid` when
a code is sent and `invalid` when one is checked; an identity that cannot verify identifiers throws a `LogicException`,
and a machine identity, which has none to verify, an `InvalidArgumentException`.

Match the result's `outcome`, and answer `rate_limited` with its `retryAfter`:

```php
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use SineMacula\Laravel\Authentication\Facades\Auth;

$result = Auth::codes('mobile')->verify($identity, 'phone', $challenge, $code, $client);

return match ($result->outcome) {
    VerificationOutcome::VERIFIED, VerificationOutcome::ALREADY_VERIFIED => response()->noContent(),
    VerificationOutcome::EXPIRED, VerificationOutcome::EXHAUSTED         => abort(422, 'Request a new code.'),
    VerificationOutcome::MISMATCH, VerificationOutcome::INVALID          => abort(422, 'The code is not valid.'),
    VerificationOutcome::RATE_LIMITED                                    => response()->json(['message' => 'Too many attempts.'], 429)->header('Retry-After', (string) $result->retryAfter),
};
```

`Verification\IdentifierVerifier::verify($guard, $identity, $type, $identifier, $client)` is the step a link or a
one-time code ends in: the proven identifier must be the identity's current one, compared in its normal form. Only
the call that records the verification dispatches `Events\IdentifierVerified` (guard, identity, type and client, never
the identifier), once the record is committed on the identity's connection; a rolled-back verification is never
reported.

## Active-state enforcement

Activation is opt-in. A model that does not implement `CanBeActive` is always active, so the 2D example above, on
Laravel's default `users` table, signs in without an activation column. Implement `CanBeActive` on an identity or a
principal to have the guard consult `isActive()` on every credential, bearer, and refresh path and reject
authentication when it returns `false`:

```php
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;

class AppUser extends User implements Identity, Principal, CanBeActive
{
    use Authenticatable, ActsAsPrincipal;

    public function isActive(): bool
    {
        return $this->suspended_at === null;
    }
}
```

To read the flag from a column instead, implement `CanBeActive` and use the `ProvidesActiveState` trait, as
`AppMembership` does above. The trait alone is never consulted: only models that implement `CanBeActive` are checked,
and PHPStan reports a class that uses the trait without the interface. It reads `is_active` (override
`getActiveAttributeName()` to use another column) and throws a `LogicException` when the model was loaded without that
column, so a partial select is reported instead of being read as either active or inactive.

When your schema records deactivation as a time instead, a nullable timestamp that is `null` while the model is active,
use the `ProvidesDeactivationTime` trait in place of `ProvidesActiveState` (pointing the boolean trait at such a column
would invert its meaning):

```php
use SineMacula\Laravel\Authentication\Concerns\ProvidesDeactivationTime;

// In a migration: $table->timestamp('deactivated_at')->nullable();

class AppMembership extends Model implements CanBeActive, PrincipalContract
{
    use ActsAsPrincipal, ProvidesDeactivationTime;
}
```

It reads `deactivated_at` (override `getDeactivatedAtName()` to use another column): the model is active exactly while
the value is `null`, and any other value is inactive, whether the time is past, present or future, so a deactivation you
schedule for later is yours to write when it falls due. The value is read as the model holds it, unsaved changes
included, without its cast, so a stored time that cannot be parsed reads as inactive rather than throwing. Like the
boolean form, it throws a `LogicException` when the model was loaded without the column. Either trait reads only the
attributes the model holds, and Eloquent holds no value for a column a model was created without (one left to its
database default) until the model is read again, so give the column on create (`'deactivated_at' => null`) when the
model's activity is asked before it is read back, as `RevokeSessionsOnDeactivation` does on its first update. A model
uses one trait or the other: both define `isActive()`.

A tenant opts in the same way, with either trait. When a principal's own tenant, or the active tenant a session acts in,
implements `CanBeActive` and reports inactive, every principal in it, and every session acting in it, is rejected on the
same paths (refresh fails with `tenant_inactive`):

```php
class AppTenant extends Model implements CanBeActive, TenantContract
{
    use ActsAsTenant, ProvidesActiveState;
}
```

A principal whose opted-in tenant cannot be loaded is rejected on the same paths: when the principal's `BelongsTo`
tenant key names a `CanBeActive` tenant that is deleted, soft-deleted, or hidden by a scope,
`ActsAsPrincipal::getTenant()` throws a `TenantUnavailableException`, which the check reads as an inactive tenant,
instead of returning `null` as if the principal acted within no tenant. The default model a `withDefault()` relation
returns for such a missing row counts as missing too, rather than as a present tenant. A `Principal` that implements
`getTenant()` itself should do the same, and give the exception the tenant's class, the name of the attribute its key
refers to and that key (`new TenantUnavailableException($message, Team::class, 'id', $this->team_id)`), as
`ActsAsPrincipal` does, so `tenantDeactivated()` recognises the deleted tenant it names. As with `ProvidesActiveState`,
a principal loaded without the key of an opted-in tenant (a partial select) throws a `LogicException` rather than being
read as acting within no tenant. A polymorphic (`MorphTo`) tenant relation names its model through its type column, so a
principal loaded without that column throws a `LogicException` as well, and one whose type is empty while its key is set
is rejected like a tenant that cannot be loaded. A tenant that does not implement `CanBeActive` is never checked, so a
missing one reads as no tenant, and a `tenant` relation to a model that is not a `Tenant` is not a tenant at all.

Checking the tenant reads `$principal->getTenant()` on every request, so eager-load the tenant in your principal
resolver (or `ResolvesHintedPrincipal`) to avoid a lazy load per request.

Deactivation stops every token at once through these checks, and ending the sessions as well (the optional
`RevokeSessionsOnDeactivation` observer, or `identityDeactivated()`, `principalDeactivated()` and `tenantDeactivated()`,
see [Revoking on security changes](sessions.md#revoking-on-security-changes)) makes the end outlast a reactivation. A
sign-in, a choice of principal or a switch that admitted the identity, principal or tenant before the deactivation
committed outlasts it no more, for Eloquent models whose standing is read on their own connection (see [Sign-ins racing
a deactivation or deletion](sessions.md#sign-ins-racing-a-deactivation-or-deletion) for its bounds): each checks its
session again once it commits, and refuses or ends it when what it acts as was deactivated meanwhile. A deactivation
undone before such a call checks its session is recorded only by the identity's or principal's "tokens valid after"
cutoff, so give identities and principals `HasTokensValidAfter` (`ProvidesTokensValidAfter`).

Where the package lists an identity's principals for admission (a sign-in, a pending session, `Auth::sessions()`'s
`principals()` for a choice or switch screen, and `principal()` for a lookup by identifier), it loads their tenants
itself: once the identity's `principals()` has been read on the write connection and each principal's own activity
checked, the tenant relation of every active principal judged that uses `ActsAsPrincipal` (the one
`getTenantRelationName()` names) is loaded on the writer of the tenant's own connection, in one query per principal
class (one per tenant type for a polymorphic relation, plus whatever the tenant model's own `$with` loads), however many
principals there are. An inactive principal is refused without its tenant being read. So listing any number of
principals reads their tenants once, and the listing works under `Model::preventLazyLoading()`, which forbids a lazy
load on models read together; you need not eager-load the tenant in `principals()`. Whatever `principals()` eager-loaded
under that name, through `with()` or a global scope, is replaced by the relation as a lazy load would read it, so a
constraint there cannot change which tenant is checked. Eloquent pairs the tenants it loads together with their
principals by each key's PHP value, where a lazy load lets the database compare the key, so a key the database matches
but PHP does not (another case under a case-insensitive collation, `'01'` against `1`) loads no tenant. A principal the
load finds no tenant for while its relation may still name one is therefore read alone, as a lazy load reads it, so a
present tenant is never taken for none; only those principals cost a query. The load builds the relation without any
principal's attributes, as every eager load does, so keep the tenant relation's definition free of the principal's own
attributes: one that reads them (a constraint on the principal's region, say) is read alone when the load finds nothing,
but could be paired with a tenant the principal's own relation would not read. Relations nested under the name are
replaced with it: a `with('tenant.plan')` on `principals()` does not leave `plan` loaded on the listed principals'
tenants, so eager-load what you read on a listed tenant in the tenant model's `$with`, which the package's load applies.
The tenants loaded allow lazy loading as a tenant read on its own does, so a tenant whose `isActive()` reads a relation
of its own keeps working under strict mode, and a relation you read on a listed tenant without putting it in `$with` is
read once per tenant rather than refused. A `Principal` that implements `getTenant()` itself has no relation the package
can know: eager-load its tenant in `principals()`.

## Deleting identities and principals

Deleting an identity or a principal stops its tokens while it no longer resolves (Eloquent's `SoftDeletes` scope hides a
soft-deleted one from the provider and the principal resolver). Its sessions stay rows, listed by owner with no reason
recorded, until they are pruned or you end them: register the optional `RevokeSessionsOnDeletion` observer, or call
`identityDeleted()` or `principalDeleted()` yourself (see [Revoking on security
changes](sessions.md#revoking-on-security-changes)). A soft delete counts as deletion, and a restore brings no session
back, a session a sign-in, choice or switch admitted before the delete and wrote after it included (see [Sign-ins racing
a deactivation or deletion](sessions.md#sign-ins-racing-a-deactivation-or-deletion)). For a model that records a "tokens
valid after" cutoff (`HasTokensValidAfter`), the soft delete also moves the cutoff, so its session-less access tokens
issued before stay refused after a restore; without one, they work again until they expire.

A principal deleted by a database cascade from its identity fires no model event, but the identity's own revocation
already ends every session acting as its principals, since an identity's sessions are all those it holds: register the
observer on the identity model and do not rely on the principal's observer for cascades. A principal a cascade removes
with its tenant is covered by no identity's revocation, so call `tenantDeactivated()` with the tenant's principals
inside the transaction that deletes the tenant, before the delete: it ends their sessions again once the delete commits,
so a sign-in racing the delete keeps none, which a call made before the delete outside a transaction does not ensure.
