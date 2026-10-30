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

Add `HasDevices` for device tracking and refresh-token rotation:

```php
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Models\Device;

class AppUser extends User implements Identity, Principal, HasDevices
{
    use Authenticatable, ActsAsPrincipal;

    public function devices(): MorphMany
    {
        return $this->morphMany(Device::class, 'authenticatable');
    }
}
```

The relation must query the configured device model, or another model that implements `EloquentDevice`: the bearer
path, sign-in pins, the device list and revocations all read it, and a relation over any other model throws a
`LogicException`.

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
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal as PrincipalContract;
use SineMacula\Laravel\Authentication\Contracts\Tenant as TenantContract;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ActsAsTenant;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;

class AppIdentity extends User implements Identity, HasDevices, HasPrincipals
{
    use Authenticatable;

    public function principals(): HasMany
    {
        return $this->hasMany(AppMembership::class, 'identity_id');
    }

    public function devices(): MorphMany
    {
        return $this->morphMany(Device::class, 'authenticatable');
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

class AppTenant extends Model implements HasType, TenantContract
{
    use ActsAsTenant, ProvidesType;
}
```

With that shape:

- `Auth::identity()` returns the `AppIdentity`.
- `Auth::principal()` returns the `AppMembership` - resolved via `principals()->find($pid)` from the token's `pid`
  (every access token carries one), or via `resolveDefaultPrincipal()` on sign-in and on a refresh token issued
  without a principal.
- `Auth::tenant()` returns the `AppTenant` the membership belongs to.
- `Auth::type()` returns the tenant's type string (see [Principal type](#principal-type)).
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

## Principal type

A principal can carry a type: a categorical label such as `staff`, `client_admin`, `client_staff`, or `service` that
access tokens carry, `Auth::type()` returns, and a guard can key on. Implement `HasType` on the principal, the tenant,
or both, and use the `ProvidesType` trait to read it from a `type` column (override `getTypeAttributeName()` for
another column; a backed enum reads as its value, a unit enum as its name):

```php
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;
use SineMacula\Laravel\Authentication\Contracts\HasType;

class AppMembership extends Model implements CanBeActive, HasType, PrincipalContract
{
    use ActsAsPrincipal, ProvidesActiveState, ProvidesType;
}
```

The principal's type is its own when it implements `HasType` and reports one, otherwise the type of the tenant it acts
within when that tenant implements `HasType`, otherwise `null`; an empty string counts as no type, so a membership with
an empty `type` column takes its tenant's. `ProvidesType` throws a `LogicException` for a model loaded without its type
column (a resolver that selects only some columns, say), rather than reading it as untyped and handing it its tenant's
type. The tenant is loaded only when the principal has no type of its own, and both are read from the write
connection. `Audience\PrincipalType::of($principal)` reads it the same way outside a request.

Every access token carries the type in its `pty` claim when there is one (`typ` stays the token type, `access` or
`refresh`); refresh tokens never carry it, so a refreshed access token carries the type the principal has at the
refresh. Nothing checks `pty` on a bearer request: `Auth::type()` reads the bound principal as it is now, not the claim,
and a type change shows on the next request. The claim is for consumers of the token, such as a gateway or a client
choosing which screens to show, not a credential.

## Identifiers

Designate the attributes people sign in with as identifiers, so each is stored and looked up in one normal form. Cast
the attribute with `NormalisedIdentifier`, naming its identifier type:

```php
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;

class AppUser extends User implements Identity, Principal
{
    use Authenticatable, ActsAsPrincipal;

    protected function casts(): array
    {
        return [
            'email' => NormalisedIdentifier::using('email'),
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
`Contracts\IdentifierNormaliser`. A type is a lower-case letter followed by lower-case letters, digits and
underscores:

```php
'identifiers' => [
    'normalisers' => [
        'email'         => SineMacula\Laravel\Authentication\Identifiers\EmailNormaliser::class,
        'phone'         => SineMacula\Laravel\Authentication\Identifiers\E164PhoneNormaliser::class,
        'member_number' => App\Auth\MemberNumberNormaliser::class,
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
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormaliser;

final readonly class MobileNumberNormaliser implements IdentifierNormaliser
{
    public function normalise(string $identifier): ?string
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
'identifiers' => ['normalisers' => ['email' => EmailNormaliser::class, 'phone' => App\Auth\MobileNumberNormaliser::class]],
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
started with `start()` or `complete()`, which check no password. The `model` provider writes the new hash with one
conditional update, `WHERE <key> = :id AND <password> = :checkedHash`, so a password changed between the check and the
rehash is never overwritten with a hash of the old one; the write fires no model events and leaves `updated_at` alone. A
hash that does not come from the model's own password attribute (a `getAuthPassword()` that reads another table) is not
rehashed by the provider.

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
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;

// Send it: a signed link to your route, valid for `verification.link_ttl_minutes` (60 by default).
$url = app(VerificationLinks::class)->create('api', $user, 'email', 'verification.verify');

// Your route: verified, already_verified, mismatch, or null for an invalid link.
Route::get('/verify-email', function (Request $request, VerificationLinks $links) {
    return match ($links->consume($request)?->value) {
        'verified', 'already_verified' => response()->noContent(),
        default                        => abort(403),
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

Verify by one-time code with `Auth::codes($guard)`: `sendVerification()` sends a code to the identity's current
identifier of the type, and `verify()` checks it and records the verification:

```php
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use SineMacula\Laravel\Authentication\Facades\Auth;

// Send it: a code to the signed-in identity's phone number, delivered by your OneTimeCodeSender.
$request = Auth::codes('mobile')->sendVerification(Auth::identity(), 'phone');   // sent, rate_limited or identifier_invalid

// Check it: verified, already_verified, mismatch, invalid, expired or exhausted.
$outcome = Auth::codes('mobile')->verify(Auth::identity(), 'phone', $input['code']);

abort_unless(in_array($outcome, [VerificationOutcome::VERIFIED, VerificationOutcome::ALREADY_VERIFIED], true), 422);
```

A verification code is bound to its purpose, its guard, its identity and the identifier in its normal form, so it
verifies nothing else, signs no one in, and stops working when the identifier changes: `sendVerification()` and
`verify()` read the identifier from the identity they are given (load it from the write connection, as the guard does),
and the delivery job reads the identity again from the write connection and sends nothing once its identifier is no
longer the one the code is bound to. Requests are held to the `code_request` limits and the resend cooldown, and the
code to the same lifetime, attempts and single use as a sign-in code (see
[One-time codes](configuration.md#one-time-codes)). `verify()` answers a `VerificationOutcome`: `verified` when this
call recorded the identifier verified, `already_verified` when it was before. A refused check answers `invalid`,
`expired` or `exhausted` as it is (the caller already holds the identity), and reports `invalid_credentials`,
`code_expired` or `code_exhausted` with `AuthenticationFailed` on the `identifier_verification` flow. A right code whose
identifier changed after the identity you passed was loaded is used up and answers `mismatch`, as a link does: nothing
is recorded or reported, and the identity can request a code for its new identifier. An identity with no identifier of
the type, or one its normaliser rejects, is `identifier_invalid` when a code is sent and `invalid` when one is checked;
an identity that cannot verify identifiers throws a `LogicException`, and a machine identity, which has none to verify,
an `InvalidArgumentException`.

`verify()` used to answer the verifier's `IdentifierVerification` for an accepted code and the `FailureReason` for a
refused one. A check written for those still runs, wrongly: an `instanceof` check against either enum is now never
true, and a `match` on their cases never matches. Match the one enum instead:

```php
// Before
$result = Auth::codes('mobile')->verify($identity, 'phone', $code);

if ($result instanceof FailureReason) {
    return response()->json(['error' => $result->value], 422);   // invalid_credentials, code_expired, code_exhausted
}

// After
$outcome = Auth::codes('mobile')->verify($identity, 'phone', $code);

return match ($outcome) {
    VerificationOutcome::VERIFIED, VerificationOutcome::ALREADY_VERIFIED => response()->noContent(),
    VerificationOutcome::EXPIRED, VerificationOutcome::EXHAUSTED         => abort(422, 'Request a new code.'),
    VerificationOutcome::MISMATCH, VerificationOutcome::INVALID          => abort(422, 'The code is not valid.'),
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

A tenant opts in the same way. When the tenant a principal acts within implements `CanBeActive` and reports inactive,
every principal in it is rejected on the same paths (refresh fails with `tenant_inactive`):

```php
class AppTenant extends Model implements CanBeActive, HasType, TenantContract
{
    use ActsAsTenant, ProvidesActiveState, ProvidesType;
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
