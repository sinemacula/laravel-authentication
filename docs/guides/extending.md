# Extending and the suite

## Extensibility

Concrete classes in this package are `final` except `AuthManager` (the package's subclass of Laravel's manager), the
shipped `Models\Session` model, and the extension points noted below. Extension is through composition and the
container:

| Extension point                   | How                                                                                                                                                      |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Custom identity / principal model | Implement `Identity`, `Principal` (and optional capability interfaces)                                                                                   |
| Custom session model              | Implement `EloquentSession`, use `ActsAsSession` (and `PrunesSessions` to be pruned), on the storage connection                                          |
| Ending session-less access tokens | Implement `HasTokensValidAfter` on the identity or principal (only ever called on a model loaded from its row), or use `ProvidesTokensValidAfter`        |
| Custom principal resolution       | Implement `PrincipalResolver`, bind per-guard or globally                                                                                                |
| Custom identity retrieval         | Subclass `ModelProvider` (non-final)                                                                                                                     |
| Custom `auth` middleware          | Subclass `Http\Middleware\Authenticate` (non-final)                                                                                                      |
| Guard and provider drivers        | Register them with `Auth::extend()` / `Auth::provider()` as usual: the package's manager inherits them                                                   |
| Custom auth manager               | Extend `AuthManager` and bind it to `auth` in a `register()`; the package keeps it                                                                       |
| Guard-scoped JWT settings         | Override `jwt.*` keys in `auth.guards.<name>.jwt`                                                                                                        |
| Sign-in methods                   | Implement `SignInMethod`, register it with `SignInMethodManager::extend()` under a name the package does not use                                         |
| Additional factors (MFA)          | Bind your own `AdditionalFactorPolicy`; call `factorRemoved()` (factor removed or replaced) or `factorReset()`, and `factorChanged()` after an addition  |
| Gating factor changes             | Call `Auth::sessions()->factorChange()` before adding, replacing or removing a factor or making recovery codes                                           |
| Passkeys as a further factor      | Call `Auth::passkeys()->factorOptions()` and `verifyFactor()` from your further-factor package                                                           |
| Passkeys registered as factors    | Bind your own `PasskeyFactorGate`; it is asked inside each passkey registration and removal, and may answer a completion                                 |
| Application decisions             | Implement `ApplicationPolicy` (methods, body client credentials, lifetimes, identifiers) and bind it                                                     |
| Who may use an application        | Implement `ApplicationAccess` and bind it in the container                                                                                               |
| Tenants a principal may act in    | Implement `TenantAccess` and bind it in the container                                                                                                    |
| Tenants named by identifier       | Implement `TenantResolver` and bind it in the container                                                                                                  |
| Tenant authentication policies    | Implement `TenantAuthenticationPolicy` and bind it; call `tenantPolicyChanged()` when it changes                                                         |
| Judging a further factor          | Implement `RequirementCheck` and bind it in the container (a further-factor package binds one)                                                           |
| Linking external results          | Implement `ExternalIdentityLinks` and bind it in the container (by default no external result is linked)                                                 |
| Accepting a provider's evidence   | Implement `ExternalEvidencePolicy` and bind it in the container (by default no evidence is accepted)                                                     |
| Attempt limits                    | Implement `AttemptLimiter` and bind it in the container                                                                                                  |
| Identifier normal forms           | Implement `IdentifierNormalizer`, register it by type in the config                                                                                      |
| One-time code delivery            | Implement `OneTimeCodeSender` and bind it in the container                                                                                               |
| Further-factor code counts        | Implement `FactorCodeCounters` and bind it in the container (a further-factor package binds one)                                                         |
| Breached-password checks          | Implement `BreachedPasswordChecker` and bind it in the container                                                                                         |
| Password reset links              | Implement `PasswordResetLinkSender` and bind it in the container                                                                                         |
| Identifier change notices         | Implement `IdentifierChangeNotifier` and bind it in the container                                                                                        |
| Freshness of sensitive operations | Configure `freshness` per operation and guard, or implement `FreshnessPolicy` and bind it in the container                                               |
| Code sign-in for another type     | Register `CodeSignIn` for the type with `SignInMethodManager::extend()`                                                                                  |
| Credential scope validation       | Implement `ScopeRegistry` and bind it in the container                                                                                                   |
| Configuration checks              | Implement `ConfigurationCheck` and register it with `ConfigurationChecks::register()`; `authentication:check` runs it                                    |
| Authentication context keys       | Implement `AuthenticationContextContributor` and register it with `ContextContributors::register()`                                                      |
| Authentication context source     | Type-hint `AuthenticationContexts` (rebind it in a test), or call `Auth::context()`                                                                      |

The `password` method is the package's own: `attempt()`, `validate()` and the password rehash use it directly, so
`extend('password', ...)` throws an `InvalidArgumentException` rather than replace it for `signIn()` alone. Register a
different password scheme under a name of its own and allow that name in the application. The package's other
methods (`phone_code`, `email_code` and `passkey`) are reserved the same way, as are `api_key` and `client_credentials`,
which an application lists for machine credentials and which never resolve to a sign-in method. Names are lower case
(a letter, then letters, digits or underscores), and a method resolves only by the exact name it was registered under,
so one method never has a second spelling for a guard to allow or a session to record.

An `AttemptLimiter` of your own counts a subject's `account` in one counter that every guard shares, held to each
guard's `per_identifier` limit (and not counted where that limit is `null`), as well as the identifier's and the IP
address's counters of the guard. Without that, the account bounds under [Rate limits](configuration.md#rate-limits) and
[In order](signing-in.md#in-order) do not hold: a limiter keyed only by guard, identifier and IP
address (one built on Laravel's `RateLimiter`, say) lets every spelling of an identifier, and every guard, guess an
account's password and its further factor anew. It records in each granted reservation's `windows` everything its
`release()` needs to give the slots back (string keys and values), and gives them back from the windows alone. A sign-in
that waits for a further factor stores the windows of each reservation it holds and, when it completes, gives each back
through a reservation rebuilt from its own windows, whose subject carries the guard, the flow, the identifier type and
the IP address but no identifier or account. Two reservations may record the same key (a method that checks two secrets
reserves the account twice), and each is given back.

### Deciding which principals may use an application

Which principals may use an application is the `ApplicationAccess` contract's answer, and the package's default
(`AdmitAnyPrincipal`) lets any principal use any application. To keep some principals out of an application, bind your
own. The package never interprets the answer beyond yes or no: a refused principal gets `principal_ineligible` at
sign-in, at the choice of principal (and is left out of `principals()`), on every refresh and switch, and for an API key
or a client credentials exchange (`unauthorized_client`); its sessions are kept and refresh again once it is let back
in:

```php
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;

final readonly class StaffOnlyConsole implements ApplicationAccess
{
    public function mayUse(string $application, Principal $principal): bool
    {
        return $application !== 'console' || $principal instanceof StaffMembership;
    }
}

$this->app->singleton(ApplicationAccess::class, StaffOnlyConsole::class);
```

The package asks `mayUse()` inside `WriteConnection::during()` for the principal, so a model your contract reads there,
or a query-builder read on the principal's connection, comes from the primary: a grant withdrawn moments ago is not
still found on a lagging replica. Pin any other read that decides access yourself, as
[Operations](operations.md#read-replicas) shows. A contract that holds request state is bound `scoped`, not
`singleton`, so a long-running worker does not carry it into the next request.

### Letting principals act in other tenants

A session acts in one tenant, its active tenant: by default the principal's own, or none for a platform principal. The
`TenantAccess` contract says whether a principal may act in a tenant (`null` for none), and the package's default
(`OwnTenantOnly`) allows only that default. An application whose principals may act in a tenant below their own, or
whose platform principals may act in any tenant, binds its own, answered from its own tree and roles, with a
`TenantResolver` that finds a tenant by its opaque identifier. The package never sees the tree: it asks the resolver
only for a tenant other than the principal's own, and its default (`ResolveNoTenant`) finds none, so binding
`TenantAccess` alone still refuses every other tenant:

```php
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

final readonly class DescendantTenants implements TenantAccess, TenantResolver
{
    public function mayActIn(Principal $principal, ?Tenant $tenant): bool
    {
        $own = $principal->getTenant();

        return $tenant === null ? $own === null : $own !== null && Organisation::isWithin($tenant, $own);
    }

    public function resolve(string $tenantId): ?Tenant
    {
        return Organisation::query()->useWritePdo()->find($tenantId);
    }
}

$this->app->singleton(DescendantTenants::class);
$this->app->singleton(TenantAccess::class, DescendantTenants::class);
$this->app->singleton(TenantResolver::class, DescendantTenants::class);
```

A refused or unresolved tenant is `tenant_ineligible`, and an inactive one (`CanBeActive`) `tenant_inactive`, which is
reported only for a tenant the principal may act in. The selected tenant is asked at sign-in
(`SignInContext::$tenant`), at the choice of principal and on every switch, and the session's active tenant again on
every refresh; a bearer request checks only that the active tenant is still active. Both contracts are asked inside
`WriteConnection::during()` for the principal and the tenant, as `ApplicationAccess` is.

`authentication:check` asks a policy of your own, this one included, whether it allows every registered sign-in method
and `client_credentials` on each `jwt` guard, and reports an exception it throws as a problem for the guard. It still
holds an `api_key` guard to allowing `api_key`, and checks the passkey relying party of a guard your policy allows
`passkey`. It does not warn about an application that allows nothing: that warning reads the package's settings, and
the names your policy allows are its own.

### Tenant authentication policies

Bind `Contracts\TenantAuthenticationPolicy` to say what a tenant requires of the sessions active in it. It is asked with
a `Tenancy\TenantPolicyContext` (the application, the identity, the principal acting in the tenant, the tenant, and the
session, or `null` before one is written; `connectionId()` adds the connection the session was established through, or
`null` when no external provider established it) and answers a `Tenancy\TenantRequirement`: a `version` (1 to 64
characters, or `null`), a further factor as a `Requirements\Requirement` (empty asks for none), and the `connections` a
session must have been established through (`null` for no such requirement, `[]` for none that satisfies). Exemptions
are the policy's own answer: answer an exempt identity's sessions with nothing required. The `connectionId()` is the
sign-in's own while its session is not yet written, and otherwise the one the session's provenance records. It is found
when first asked and kept, so a policy that never calls it, and a judgement that names no connections, cost no read; one
that does read it shares that single read with the judgement. Read it inside `requirementFor()`: when the check ends, a
connection not yet read is never read, and asking for it throws a `LogicException` (the session's key may name another
session by then), so do not keep the context to read it later; one already read stays readable. In a test, build the
context with a closure, `new TenantPolicyContext(..., connectionId: fn (): ?string => 'conn-a')`.

```php
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;

final class OrganisationPolicy implements TenantAuthenticationPolicy
{
    public function requirementFor(TenantPolicyContext $context): TenantRequirement
    {
        $settings = TenantSecurity::query()->where('tenant_id', $context->tenant->getTenantIdentifier())->first();

        return new TenantRequirement(
            version: $settings?->version,
            factor: $settings?->requires_mfa ? new Requirement(new RequirementPart(maxAgeSeconds: 43200)) : new Requirement,
            connections: $settings?->sso_connections,
        );
    }
}

$this->app->singleton(TenantAuthenticationPolicy::class, OrganisationPolicy::class);
```

The package asks it inside `WriteConnection::during()` for the tenant, so read the policy's own state from the write
connection, as there. Change the version whenever anything the answer depends on changes, the exemptions included, and
call `Auth::sessions()->tenantPolicyChanged($tenant)` when it does (see [Tenant authentication
policies](sessions.md#tenant-authentication-policies)). A `null` version is never taken as already checked.

Whether a session's proofs meet a further factor is `Contracts\RequirementCheck`'s to judge: `evaluate()` takes a
`Requirements\RequirementSubject` (the identity, the application, the session, the first factor it signed in with, the
time, and `proofs($since, $kinds, $limit)`, a bounded query over its counting proofs, newest first, at most
`RequirementSubject::MAX_LIMIT`, only those made at or after `$since` when it is given, any Carbon time, the same
instant in any time zone) and the `Requirement`, and answers a `Requirements\RequirementEvaluation` listing the kinds
left unmet. It judges the identity-level requirement the additional-factor policy answers as well as a tenant's. The
default, `MeetNoRequirement`, meets nothing: an identity or a tenant that requires a further factor admits no session
until a factor package binds its check. The package never asks it with an empty requirement, nor when an external
provider's accepted evidence already meets the whole requirement (see below). An external provider's proof reads back
with no evaluation: its evidence was accepted for the whole application, of any age and for no tenant, so the evidence
policy alone judges it, and a check counts no part of a requirement met by one.

Whether an external identity provider's evidence counts is `Contracts\ExternalEvidencePolicy`'s to say, in two
questions about an `External\ExternalEvidence` (the provider's `amr` values, its `acr` value or SAML authentication
context class reference, and the time it is for), a `Requirement` and an `External\EvidenceSubject` (the identity, the
application, the connection that asserted it, the time it is judged at, and the tenant whose requirement it is judged
against: `null` for the identity-level requirement and for the evidence's acceptance). `accepts()` answers whether the
evidence, from that connection, is credible for the requirement, of any age, to anyone it may later be judged for: the
identity level, or any tenant that trusts the connection. `meets()` answers whether accepted evidence meets the whole
requirement for the subject. One tenant's trust in a connection is not another's: the administrators of the tenant a
connection belongs to control what its provider asserts, so `meets()` judging a tenant's requirement must refuse
evidence from a connection that tenant does not trust, or an identity linked through one tenant's connection would meet
another tenant's requirement with it. The default, `External\InsufficientEvidence`, accepts and meets nothing, so a
provider's evidence counts for nothing until you bind a policy that trusts it:

```php
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;

final class TrustedProviderEvidence implements ExternalEvidencePolicy
{
    public function accepts(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        $trusted = TrustedConnection::query()
            ->where('connection_id', $subject->connectionId) // any tenant's row, or the identity level's
            ->exists();

        return $trusted && $requirement->phishingResistance === null && in_array('mfa', $evidence->methods, true);
    }

    public function meets(ExternalEvidence $evidence, Requirement $requirement, EvidenceSubject $subject): bool
    {
        if ($requirement->minimumLevel !== null || $requirement->phishingResistance !== null) {
            return false; // parts this policy cannot vouch for
        }

        $trusted = TrustedConnection::query()
            ->where('connection_id', $subject->connectionId)
            ->where('tenant_id', $subject->tenant?->getTenantIdentifier()) // null: trusted for the identity level
            ->exists();

        $maxAge = RequirementPart::shorter(
            $requirement->additionalVerification?->maxAgeSeconds,
            $requirement->multifactor?->maxAgeSeconds,
        ) ?? 43200;

        return $trusted
            && in_array('mfa', $evidence->methods, true)
            && $evidence->authenticatedAt->greaterThan($subject->now->subSeconds($maxAge));
    }
}

$this->app->singleton(ExternalEvidencePolicy::class, TrustedProviderEvidence::class);
```

The package asks it in two places, inside `WriteConnection::during()` for the identity:

- When a sign-in or reauthentication at a provider brings evidence, it asks `accepts()` whether the evidence is credible
  for multifactor authentication and, if not, an additional verification, then phishing resistance, then the lowest
  assurance level (AAL1, so evidence credible for any level is accepted and `meets()` judges the level), each of any age
  and for no tenant. Evidence accepted for any of them is accepted: it is recorded with the proof (and, at sign-in, with
  the session's provenance), the proof's evaluation is accepted, and multifactor when it was accepted for multifactor
  authentication, so `amr` gains `mfa` in every token of the session (the claims say how the session authenticated, not
  what a tenant accepts). Evidence accepted for none is not recorded and counts for nothing; a reauthentication at the
  provider then renews `auth_time` and nothing else. Accept evidence from a connection that only one tenant trusts:
  `meets()` keeps it to that tenant.
- When the identity-level requirement or a tenant's is judged on a session an external provider established that holds
  accepted evidence, it asks `meets()` whether any of that evidence meets the whole requirement, the newest by its own
  time first and no further once one does, so newer evidence accepted for less never hides older evidence that still
  meets it. When one does, the requirement is met and `RequirementCheck` is not asked; when none does,
  `RequirementCheck` judges the session's proofs as it does any other session's, an external proof among them with no
  evaluation. Evidence never meets part of a requirement and leaves the rest to the factor package's proofs: which
  factors combine stays the factor package's.

Judge any maximum age the requirement gives, the shortest of those its parts set, on `$evidence->authenticatedAt`
against `$subject->now`, and refuse a part you cannot vouch for; evidence dated after the time it is judged at is judged
as of that time. Both questions may be asked while the package holds a session's row lock (a reauthentication at the
provider judges its tenant's requirement under it), so only read: take no lock your adapter does not already hold. An
exception the policy throws reaches the caller and rolls back the transaction it was asked in.

`AbstractGuard` is not final and may be extended for entirely new guard types.

### Writing a guard type

`AbstractGuard`'s constructor takes the guard's name, identity provider, principal resolver, event dispatcher, request
and `Timebox`, and keeps them in the guard's context, `$this->context` (a `Runtime\GuardContext`): the one copy every
flow of the guard reads, which the guard's `setRequest()`, `setDispatcher()` and `setPrincipalResolver()` rebind. A
guard type has no `$this->name`, `$this->provider`, `$this->resolver`, `$this->events`, `$this->request` or
`$this->timebox` of its own; it reads each collaborator from the context when it uses it, and runs a check of a secret
in the guard's credential timebox, the one `attempt()` and `validate()` run in.

`bindVerifiedContext()` binds what it is given and checks none of it, so a guard type admits what its credential named
first, as the package's guards do: the application must allow the method it reports, the identity, the principal and the
principal's tenant must be active (`Admission\ActivationPolicy`), the application policy must admit the identity, and
`ApplicationAccess` must let the principal use the application, each asked inside `WriteConnection::during()` as the
package asks them. The tenant the activity check loaded is the one it binds. A guard type that authenticated a
credential the request presented names its kind last (`kind:`, a `Context\Enums\CredentialKind`), so the request's
[authentication context](#authentication-context) says what was presented; one that names none reports `credential` as
`null`, as a sign-in in the request does. A guard type may also name the credential's id (`credentialId:`), which its
events and `boundCaller()` report: an identifier, such as the id of the key's row, never the credential itself:

```php
use Illuminate\Container\Container;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

final class HeaderKeyGuard extends AbstractGuard
{
    protected function resolveUserFromRequest(): ?Identity
    {
        $key = $this->context->request()->header('X-Api-Key');

        if (!is_string($key) || $key === '') {
            return null;
        }

        $identity = $this->context->timebox()->run(function (Timebox $timebox) use ($key): ?Identity {

            $identity = $this->context->provider()->retrieveByCredentials(['api_key' => $key]);

            if ($identity instanceof Identity) {
                $timebox->returnEarly();

                return $identity;
            }

            return null;
        });

        return $identity === null ? null : $this->admit($identity);
    }

    private function admit(Identity $identity): ?Identity
    {
        $guard  = $this->context->name();
        $policy = Container::getInstance()->make(ApplicationPolicy::class);

        if (!$policy->allowsMethod($guard, 'header_key') || !ActivationPolicy::isActive($identity)) {
            return null;
        }

        if (WriteConnection::during($identity, fn (): ?FailureReason => $policy->admitIdentifier($guard, $identity, null)) !== null) {
            return null;
        }

        $principal = $this->resolvePrincipal($identity);
        $tenant    = $principal === null || !ActivationPolicy::isActive($principal) ? false : ActivationPolicy::activeTenant($principal);

        if ($principal === null || $tenant === false) {
            return null;
        }

        $access = Container::getInstance()->make(ApplicationAccess::class);

        if (!WriteConnection::during($principal, fn (): bool => $access->mayUse($guard, $principal))) {
            return null;
        }

        $this->bindVerifiedContext($identity, $principal, null, $tenant, 'header_key', false, kind: CredentialKind::API_KEY);

        return $identity;
    }
}
```

The context also gives the guard's `name()`, `resolver()`, `events()` and the request's `client()`, and `dispatch()`
sends an event to the guard's dispatcher as it is then. Read the request's client when an operation starts and build its
events then, so a deferred event reports the request it came from (see `docs/design/guard-context.md`).

The package registers the container's rebinds on the guards it builds (the `jwt` and `api_key` drivers) and on no other.
A guard type's driver registers them itself, so the next request's `request`, `Event::fake()` and other rebinds of
`events`, and a rebind of the global `PrincipalResolver` reach the guard's context. A guard given a resolver of its own
leaves out the last, which would replace that resolver with the global one:

```php
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

Auth::extend('header_key', function ($app, string $name, array $config): HeaderKeyGuard {

    $guard = new HeaderKeyGuard(
        $name,
        Auth::createUserProvider($config['provider']),
        $app->make(PrincipalResolver::class),
        $app->make('events'),
        $app->make('request'),
        $app->make(Timebox::class),
    );

    $app->refresh('request', $guard, 'setRequest');
    $app->refresh('events', $guard, 'setDispatcher');
    $app->refresh(PrincipalResolver::class, $guard, 'setPrincipalResolver');

    return $guard;
});
```

Without them the guard keeps the dispatcher and resolver it was built with for its life. A queued job's reset,
`AuthManager::forgetGuardState()`, gives every resolved guard built on `AbstractGuard` the current request, however its
driver was registered.

### Adding checks to `authentication:check`

A package that adds settings of its own can have `php artisan authentication:check` check them with the package's
(see [Checking the configuration](operations.md#checking-the-configuration)). Implement
`Contracts\ConfigurationCheck`, which answers `Console\ConfigurationFinding`s for the guards being checked, and register
it in a service provider's `boot()`:

```php
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Console\ConfigurationChecks;
use SineMacula\Laravel\Authentication\Console\ConfigurationFinding;
use SineMacula\Laravel\Authentication\Contracts\ConfigurationCheck;

final class FactorConfigurationCheck implements ConfigurationCheck
{
    public function __construct(private readonly Repository $config) {}

    public function findings(array $guards): array
    {
        $findings = [];

        if (!is_int($this->config->get('factors.code_ttl_seconds'))) {
            $findings[] = ConfigurationFinding::error('`factors.code_ttl_seconds` must be an integer.');
        }

        foreach ($guards as $guard) {
            if ($this->config->get("auth.guards.{$guard}.factors") === null) {
                $findings[] = ConfigurationFinding::warning('It sets no `factors` block, so it asks for no further factor.', $guard);
            }
        }

        return $findings;
    }
}

$this->app->make(ConfigurationChecks::class)->register(FactorConfigurationCheck::class);
```

The registration is a container abstract, resolved each time the command runs, so a check may take configuration and
bindings in its constructor; registering the same abstract twice registers it once. A finding is an error
(`ConfigurationFinding::error()`), which fails the command exactly as a built-in problem does, or a warning
(`ConfigurationFinding::warning()`), which is shown and leaves the exit code alone. It names a guard, or none for a
package-wide setting, and is printed as `[<guard>] <message>`, or as the message alone without a guard:

```text
[storage] OK
...
[api] OK
[api] It sets no `factors` block, so it asks for no further factor.
`factors.code_ttl_seconds` must be an integer.
```

(the warning is shown with the other warnings, and the error after the guards' own problems). The registered checks run
after the package's own, for the same guards: with `--guard`, a check is given only the guards named. The findings are
shown in the order the checks were registered, then package-wide findings first and the guards in the order they are
checked, then in the order the check gave them.

A check reads configuration and bindings only: it opens no database connection and makes no network call, and anything
else with a side effect, as the command runs in deploy pipelines and readiness probes. A finding's message names the
settings at fault and never their values, since the output reaches deploy logs; control characters are removed from
every message and guard name, and a message is cut to a thousand characters. A check that cannot be resolved, that
throws, or that answers anything but findings does not stop the command: it is reported as an error naming the check and
the exception's class (never the exception's message, which may carry a value), and the checks after it still run.

### Binding order

Every default the package binds is bound only when nothing is bound yet: `PrincipalResolver`, `ApplicationPolicy`,
`ApplicationAccess`, `TenantAccess`, `TenantResolver`, `AttemptLimiter`, `AdditionalFactorPolicy`, `PasskeyFactorGate`,
`TenantAuthenticationPolicy`, `ExternalIdentityLinks`, `RequirementCheck`, `ExternalEvidencePolicy`,
`FactorCodeCounters`, `FreshnessPolicy`, `ScopeRegistry`, `BreachedPasswordChecker`, `PasswordResetLinkSender`,
`AuthenticationContexts`, the `IdentifierNormalizers`, `SignInMethodManager`, `ContextContributors` and
`ConfigurationChecks` registries, and the package's own `WebAuthn`, `Rehashing`, `JwtTokenServiceFactory` and the
`Authenticate` middleware that stands in for Laravel's. Bind yours in a service provider's `register()`, before or
after the package's provider: one bound before is kept, and one bound after replaces the default, so a factor policy is
never replaced by `NeverRequireAdditionalFactor`, nor a scope registry by `AcceptAnyScope`. A `bind()` or `singleton()`
replaces a default even once it has resolved, for every caller that resolves it afterwards; a deferred provider does
not, as Laravel loads one only for a service that has no instance yet. Resolve none of them while providers register,
or a deferred provider's binding of it is passed over.

A package that ships its own adapter for one of these contracts but should give way to the application's binds it only
when `AuthenticationServiceProvider::isPackageDefault($app, $contract)` is `true`, from its `register()` or after boot:

```php
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;

if (AuthenticationServiceProvider::isPackageDefault($this->app, AdditionalFactorPolicy::class)) {
    $this->app->singleton(AdditionalFactorPolicy::class, FactorPolicy::class);
}
```

It is `true` for a contract from `PrincipalResolver` to `AuthenticationContexts` still bound to the package's default,
resolved or not, and `false` for anything else: an unbound contract, another binding, an alias, an `extend()` or an
`instance()` of another class. An `extend()` of a resolved default that returns the default's class goes unseen.

A `FreshnessPolicy` of your own is asked `freshProof()` plainly wherever the package judges a session without its lock,
and with the read mode set (`current: true`) under a session's lock (the factor-change gate, an identifier change
request, a password establishment), and `freshUntil()` takes the same mode for a caller of yours. Honour it: one that
decorates `Freshness\ConfiguredFreshness` passes `$current` on, and one of your own reads the session as the package's
does when asked (its row locked and judged, its proofs current, through `Auth::sessions()->proofs()` inside the
transaction, say, only inside a transaction on the session model's connection).
A policy that ignores it judges the transaction's snapshot under the package's locks: on MySQL and MariaDB at REPEATABLE
READ a proof voided before the judgement may still count there, and one recorded since may be missed.

Register a sign-in method once the registry resolves, which works in either order (a registry made with `make()` before
the package registers is not the one the package uses):

```php
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;

$this->callAfterResolving(SignInMethodManager::class, static function (SignInMethodManager $methods): void {
    $methods->extend('magic_link', fn ($app) => $app->make(MagicLinkSignIn::class));
});
```

An identifier normaliser is configuration: a package that adds one sets `authentication.identifiers.normalizers.<type>`
in `boot()`. Laravel merges a package's configuration one level deep, so a value set under `authentication.identifiers`
while providers register, before the application has published the configuration, replaces the package's normalisers.

### The auth manager

The package owns Laravel's `auth` binding: its guards, the contextual accessors and the `Auth` facade rely on its
`AuthManager`. When it boots it replaces any other manager there with its own, which takes over what was registered on
the one it replaces (`AuthManager::inheritStateFrom()`): the drivers from `Auth::extend()`, `Auth::viaRequest()` and
`Auth::provider()`, the user resolver from `Auth::resolveUsersUsing()`, and the guards already resolved, which stay the
same instances. Those calls keep working from any provider's `register()` or `boot()`, and `Auth::` reaches the
package's manager even when it was used before the package booted.

The flows that change a session's proofs reach the guards the request already resolved through the internal
`AuthManager::resolvedGuard()`, which never creates one.

What a subclass of Laravel's manager adds itself, its methods and overrides, is not kept: the replacement is not a
decorator. To customise the manager, extend the package's `AuthManager` and bind it to `auth` in a `register()`; the
package keeps it and registers its drivers on it. Bind `auth` only there: a manager bound to it after the package boots
is not supported, and an object that captured the manager before the swap keeps the one it had.

## Suite integration

The package authenticates; its siblings decide everything else, each through a seam here, and none is required. Every
seam has a default that works alone.

### Further factors (`laravel-mfa`)

- Bind `Contracts\AdditionalFactorPolicy` (the default, `NeverRequireAdditionalFactor`, asks for nothing). It answers
  what a session's authentication must include beyond its first factor as this package's own `Requirements\Requirement`
  (an additional verification, multifactor, a minimum assurance level, phishing resistance, each with an optional
  maximum age). It is asked about every admitted identity's sign-in, from `signIn()` and `start()`, before any principal
  is chosen, again whenever its pending session is acted on, and when a refresh or a switch returns the session to
  pending under its destination tenant's policy or `factorRemoved()` or `factorChanged()` judges the current session
  again (never on a refresh or switch that tenant's policy lets through), inside `WriteConnection::during()` for the
  identity, with an `AdditionalFactorContext`: the application, the identity, the first factor's whole recorded proof
  (`Proofs\RecordedProof`: method, channel, observed properties, `amr` values, time), the client, and the session the
  client proved; it names no principal or tenant (see [Additional factors](signing-in.md#additional-factors)).
- Bind `Contracts\RequirementCheck` (the default, `MeetNoRequirement`, meets nothing). It is the one judge of whether a
  session's proofs meet a requirement: the identity-level one above and the further factor a tenant's authentication
  policy requires, at sign-in (the first factor alone, in memory: a requirement the first factor meets activates the
  session at once), at the choice, on refresh, on a switch, when a pending session is acted on and when
  `Auth::caller()` reads a refresh credential. Without it, a non-empty requirement never activates a session that
  holds no accepted provider evidence meeting it: it fails closed (see [Tenant authentication
  policies](#tenant-authentication-policies)).
- When a requirement is unmet, the sign-in's session waits pending with `mfa` outstanding: `SignInResult::isPending()`,
  its `PendingSession` and pending credential (read from a request with `PendingCredential::extract($request)`), then
  `Auth::sessions()->pending($credential, $action)` to check an
  `mfa.*` action (`Sessions\Enums\PendingAction`) before the factor package acts, `satisfy()` once the factor is
  verified, or `discard()` (see [Pending sessions](signing-in.md#pending-sessions)). The `PendingSession` tells the
  factor package what it needs: `$requirement` (what its authentication still falls short of: the strictest of the
  identity-level requirement and the destination tenant's, each only while it is unmet; empty while only the choice is
  outstanding), `$firstFactor`, `proofs($since, $kinds, $limit)` (its counting proofs, newest first, one bounded read
  each call) and `$expiresAt` (when the pending credential ends). `attempt()` cannot wait, so it fails as
  `additional_factor_required` whenever the password alone does not meet the requirement.
- A pending session's bootstrap enrolment (its first factor, enrolled while it waits) goes through its credential:
  `pending($credential, PendingAction::START_BOOTSTRAP_ENROLLMENT)` and `CONFIRM_BOOTSTRAP_ENROLLMENT`, allowed only
  while the factor is its first outstanding requirement and until the credential expires, then `satisfy()` with the
  confirming factor's proof for `enrollment`. It never goes through the factor-change gate below, which refuses a
  pending session.
- Before it adds, replaces or removes one of an identity's further factors, or generates its recovery codes, from an
  active session, the factor package asks the gate inside the transaction that makes the change, on the storage
  connection, after its own identity and factor locks: `Auth::sessions()->factorChange($session, FactorChange::REMOVE,
  $requirement, $factor)` (`Factors\Enums\FactorChange`: `mfa.add_factor`, `mfa.add_first_additional_factor`,
  `mfa.replace_factor`, `mfa.remove_factor`, `mfa.generate_recovery_codes`). It locks the session's row until that
  transaction ends, checks it is still the session given, one of this guard's live, active sessions, and a person's,
  then asks the freshness policy, on the session's proofs as committed (`current: true`): every change takes a
  fresh step-up (`factor_change`, refused as `step_up_required`), except an identity's first additional factor
  (`ADD_FIRST`, which the factor package names, knowing the identity has none), which takes a fresh reauthentication
  with the first factor (`first_additional_factor`, refused as `reauthentication_required`): the sign-in's own first
  factor never counts, so whoever holds a session cannot enrol a factor on it without proving the first factor again. A
  replacement or removal names its factor (required for those, refused for the others), whose own proofs never count for
  its change. The answer, a `Factors\FactorChangeVerdict`, carries the fresh proof and `freshUntil` (when the session
  stops being fresh for it, for a grant that outlives the request), or the reason; it writes and reports nothing.
- A factor removed, inside the same transaction and after the same locks: `Auth::sessions()->factorRemoved($identity,
  $factor->reference(), Auth::session())` ends the identity's other sessions, voids the current session's proofs made
  with that factor, and judges the current session again: it stays active, returns to pending (its
  `Sessions\FactorRemoval` carries the pending session and credential for the client) or is revoked; a current session
  already pending stays pending, judged without those proofs at its next action. Every factor reset:
  `Auth::sessions()->factorReset($identity)` ends every session and, once committed, the request's authentication as the
  identity. Both are mandatory: no setting turns them off, and they are called synchronously, never through a listener
  (see [Sign-in factors](sessions.md#sign-in-factors)). The identity must live on the storage connection.
- After an addition to an identity's factors made from an active session (a further factor's enrolment confirmed, a
  passkey associated as a factor, or any other change that removes no factor), inside the same transaction and after
  the same locks: `Auth::sessions()->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $current)`, where
  `$current` is `Auth::session()` once you have checked it is not `null` (a change made with no current session has
  nothing to judge and does not call it). `Factors\Enums\FactorChangeMade` has `FACTOR_CONFIRMED`,
  `PASSKEY_FACTOR_REGISTERED`, `FACTOR_REMOVED` and `OTHER`. It judges the current session again exactly as
  `factorRemoved()` judges it, voiding no proof and touching no other session. A replacement removes the factor it
  replaces, so it calls `factorRemoved()` for that factor, which voids its proofs and ends the other sessions. A new set
  of recovery codes removes no factor, so it never goes through `factorRemoved()` (the session's proofs made with a
  recovery code stay recorded and count), and goes through this call with `OTHER` only when your factor policy can
  change with the codes. A removal needs nothing more than `factorRemoved()`, which has already judged the session:
  `FACTOR_REMOVED` is only for a factor package that hands every change to this judgement once it is made, after
  `factorRemoved()` and never in its place. There it judges a session the removal kept again at its own time, so it can
  still return it to pending or revoke it (a maximum age lapsing between the two calls, say): hand the client the
  credential of whichever result is pending, `FactorRemoval::$credential` or this call's. This call's
  `Sessions\FactorChangeResult` says whether the session stayed `active`, returned to `pending` (carrying the pending
  session and credential for the client), was `revoked` (`factor_changed`, or `factor_removed` for `FACTOR_REMOVED`) or
  was `skipped` (no longer the session given, or no longer live and active). It locks the session's row after your
  locks, writes its issuance guard before it reads the proofs, and runs as a savepoint of your transaction when that is
  on the storage connection, so the return to pending commits or rolls back with the change; its events and the guard's
  forgetting of the session follow the commit. It reads the proofs current, so whatever your transaction read before
  the call, a step-up committed before it counts and a proof voided before it never does; on MySQL and MariaDB at
  REPEATABLE READ those reads hold shared locks until you commit, so keep the transaction short, and at PostgreSQL's
  REPEATABLE READ a change of the session's proofs committed after your snapshot fails the call to serialise. On a lock
  wait timeout, a deadlock or a serialisation failure roll your whole transaction back and retry it whole (see [Issuance
  order](sessions.md#issuance-order)). The identity's other sessions are not judged: only the current session's client
  can receive a pending credential, and an added factor ends nothing, so they keep running as they were admitted; end
  them yourself in the same transaction, before the call (`revokeSessions(..., except: $current)`), if they must meet
  the new requirement: the call has read the current session's proofs under shared locks, and the package takes every
  session row before any proof. The identity may live on any connection, since nothing of it is written.
- Passkeys verify as a factor through `Auth::passkeys()->factorOptions($identity, $binding, $credentialIds)` and
  `verifyFactor($identity, $binding, $challenge, $credential, $client)`, which count and report nothing: the factor's
  outcome is the factor package's to limit and report. The ceremony is bound to the `ProofBinding`'s session and purpose
  and allows only the credential ids named; `verifyFactor()` answers a `PasskeyFactorResult` (see [Using
  passkeys](signing-in.md#using-passkeys)), never `null`, whose `PasskeyFactorAssertion` carries the assertion's own
  observed properties for the factor package's `ProofResult`.
- Bind a `Contracts\PasskeyFactorGate` to take part in the passkeys' lifecycle: `registering()` is asked inside the
  transaction that inserts a new passkey and may associate it as a factor (`PasskeyFactorAssociation`, carried in the
  `PasskeyRegistration`'s `factor`), and `removing()` inside the one that deletes it; either may refuse by throwing,
  which rolls the change back whole. Each is handed the `ClientContext` the registration or removal was given, and
  `registering()` also the pending credential (a `Secret`, or `null`) of a registration made on a pending sign-in,
  which the package has already proved names a live pending session of the identity (see [Registering on a pending
  sign-in](signing-in.md#registering-on-a-pending-sign-in)): the gate completes that session's factor by calling
  `satisfy()` itself, whose refusal is answered, not thrown, so a gate that requires the completion throws to roll the
  registration back. A gate that associates a passkey as a factor from an active session calls
  `factorChanged(..., FactorChangeMade::PASSKEY_FACTOR_REGISTERED, ...)`, and one that removes a passkey factor calls
  `factorRemoved()`; each may hand its completion of the change (the judgement, with any pending credential) back to the
  passkey service's caller, uninterpreted: as the association's `completion`
  (`PasskeyRegistration::$factor->completion`), or as what `removing()` returns (`PasskeyRemoval::$completion`). A
  change rolled back (a credential registered meanwhile, a passkey removed meanwhile) answers no completion. The
  default, `Passkeys\NoPasskeyFactors`, associates nothing, completes nothing and refuses nothing.
- Every failed check of one of this package's challenges reports `AuthenticationFailed` with the challenge's id
  (`challengeId`), the id the factor package's own per-attempt events carry, so both can be followed per challenge; the
  context is plain values the factor package reads as scalars (see [Events](events.md#events)).
- A factor's one-time codes (a text message or email factor, and the confirmation of one being enrolled) are this
  package's challenges: `Auth::codes($guard)->sendFactorCode($binding, $client)` sends one and answers a `CodeRequest`
  with its `challengeId`, and `verifyFactorCode($binding, $challengeId, $code, $client)` checks it and answers a
  `Codes\FactorCodeCheck`. The `Codes\FactorCodeBinding` names the `ProofBinding` (identity, this guard, the session's
  key, and `sign_in` or `step_up` for an `mfa` challenge, `enrollment` for an enrolment's), the factor's reference, the
  `Channel` (`sms` or `email`, with the destination in its normal form) and, for an enrolment, its grant. A code is
  accepted only for that very binding: another session, factor, purpose or grant, and an `mfa` code as an `enrollment`
  one or the reverse, is `not_found`, as a malformed, unknown or replaced challenge id is, so another binding's
  challenge cannot be told from an absent one; the binding's own challenge, once used, is `used`; a wrong code is
  `invalid` and counted, while a malformed one is `invalid` and not counted
  against the challenge (it still takes its IP slot, before it is judged); neither `not_found` nor `used` counts an
  attempt or is reported to the counters. The delivery key is the destination and the identity, never the factor, so the
  cooldown and the delivery cap hold across an enrolment restarted with a new factor and grant. Bind
  `Contracts\FactorCodeCounters` (the default, `RefuseFactorCodes`, refuses every code): `admit()` is asked before each
  delivery and each check, and `report($binding, $challengeId, $passed)` exactly once for each attempt a check counts,
  both inside the package's transaction on the storage connection (a savepoint of yours, when you opened one). `admit()`
  runs before the challenge's row is locked, so take your identity and factor locks there, on that same connection;
  `report()` runs after the row is locked and the attempt counted, so it must take no lock that comes before the
  challenge (it writes the counts of rows `admit()` already locked). The report's answer stands: a matching code is
  `verified` only when it answers `admitted`. This package counts per challenge, per destination and per IP address
  (`codes.max_attempts`, `codes.max_deliveries`, the `code_request` and `factor_code` limits); the per-factor and
  per-identity counts and lockouts are yours. Turn a verified check into a `ProofResult` (its method, the channel, the
  factor, the binding) and hand it to `satisfy()` or `stepUp()`, inside the same transaction when both are to commit
  together. A sent code's `CodeRequest` also says when another may be sent (`resendAvailableAt`).
- A factor package's proof store and first-factor resolver read an active session's proofs through the session service:
  `Auth::sessions($guard)->proofs($session, $since, $kinds, $limit)` (its counting proofs, newest first, as
  `PendingSession::proofs()` reads a pending session's) and `firstFactor($session)` (the first factor it signed in
  with), the session named by its id (whichever session holds the key now) or given as a `Session` (answered only while
  its key still holds that very session), each `[]` or `null`, without saying why, for a session that is not one of the
  guard's live, active sessions of a person; a pending session's are read through its `PendingSession`. Inside the
  factor package's transaction, after its own locks and before a `stepUp()` or `factorChanged()` of the same session,
  the read locks the session's row until the transaction ends and reads its proofs current, so the change is decided on
  what is committed; on MySQL and MariaDB at REPEATABLE READ it holds shared locks on the proofs until you commit, and
  at PostgreSQL's REPEATABLE READ it fails to serialise when the session changed after your snapshot. `factorRemoved()`
  moves the identity's token cutoff and revokes its other sessions before it judges the current one again, so do not
  read the proofs before it in the same transaction unless your transaction already holds those rows: two removals from
  two of the identity's sessions could deadlock (see [Reading a session's
  proofs](sessions.md#reading-a-sessions-proofs)).
- A factor package's credentials and enrolments are its own; the proofs of a session are this package's (see [Proofs
  and provenance](sessions.md#proofs-and-provenance)). The adapter hands each factor it verified to the session service
  as a `Proofs\ProofResult`: its kind (`additional_factor`, or `recovery_code` for the fallback, kept apart), method,
  channel, factor, what it observed (`null` for anything it did not), its `Evaluation` (accepted, and multifactor as it
  judged it: `amr` carries `mfa` only from there, never counted from the values, and a proof's own values may not name
  `mfa`), its `amr` values (at most 8, each 1 to 48 printable ASCII characters other than `"` and `\`; anything else is
  an `InvalidArgumentException`), its time and its `ProofBinding` (identity, application, session, purpose). Satisfy a
  pending session with `satisfy($credential, $proof, $client)`, the client the request's `ClientContext`, bound to
  `PendingSession::$id` for `sign_in`, or `enrollment` for the factor that confirms a bootstrap enrolment (see
  [Satisfying a further factor](signing-in.md#satisfying-a-further-factor)). Called inside the factor package's own
  transaction, on the storage connection, the activation commits with it: the guard is bound, and the sign-in's slots
  given back, only once that transaction commits, and never when it rolls back. It reads the pending session's proofs
  current, and locks the session the sign-in proved before them, whenever the sign-in recorded one, whatever it then
  decides; on MySQL and MariaDB at REPEATABLE READ those reads hold shared locks until you commit, so keep the
  transaction short and take any session row your transaction needs before the call (a bulk revocation over both
  sessions, `revokeSessions()` or `factorReset()` among them, locks the older first and can deadlock with it). On a lock
  wait timeout, a deadlock or a serialisation failure, which reaches you as Laravel's `DeadlockException`, roll your
  whole transaction back and retry it whole (see [Issuance order](sessions.md#issuance-order)). Nothing a factor package
  keeps about a session survives a sign-in: every sign-in starts a new session with a new id and its own proofs, and the
  session the client proved (`AdditionalFactorContext::$provenSession`) is revoked with its proofs left on it when the
  new one first activates.
- Step a signed-in session up with a factor the factor package has just verified: `Auth::sessions()->stepUp($proof,
  $client)`, with the `ProofResult` bound to the session's key for `step_up` and the `ClientContext` of the request it
  serves. The session keeps its refresh token and deadlines, and every access token issued for it from then on carries
  the factor in `auth_time` and `amr`; the session then proves an identifier change, or any operation whose freshness
  takes a further factor (see [Stepping up](sessions.md#stepping-up)). A factor verified outside a session proves
  nothing on its own. A session the application started itself with `start()` records the channel its `FirstFactor`
  described (`password`, `recovery` for its own account recovery, or `unknown`), which the factor package can weigh when
  it judges a further factor's independence; a channel never implies multifactor authentication, and `recovery` is a
  first factor, not an accepted further one.
- Before a sensitive operation of its own that the gate does not cover, the factor package asks
  `FreshnessPolicy::freshProof($session, 'mfa.some_operation')`, under a namespaced operation name of its own that the
  application configures under `freshness`, and passes a `FreshnessRequirement` of its own for a floor the
  configuration may not lower (see [Freshness](sessions.md#freshness)). A caller that means only "within so many
  seconds" passes `FreshnessRequirement::within($seconds)`, which takes every proof kind: a list of kinds of its own
  narrows the configured kinds to those both take. `freshUntil()` answers until when the session stays fresh, and both
  take an excluded factor (`$excludingFactor`), whose proofs never count: a removal's requirement is met only by the
  session's other proofs. When it acts on the answer in the same transaction, it asks with the read mode set
  (`freshProof($session, 'mfa.some_operation', current: true)`, and `freshUntil(..., current: true)` for a grant's
  expiry) inside that transaction, on the storage connection, after its own identity and factor locks and after any
  other session's row it needs (take those before the call), and never acts on a plain answer there: the policy locks
  and judges the session's row and reads its proofs current, so a step-up voided meanwhile never counts.
- The factor package's own requirement for a change (its `mfa.add_factor`, say) is the caller's requirement the gate
  takes as `$requirement`: the stricter of it and `factor_change` (or `first_additional_factor`) applies.
- The active tenant the factor package acts in comes from the validated session or caller, never from an event's
  context: `Auth::tenant()` on the request, `Auth::caller()?->tenant`, or the session's own `getTenantId()`.
- When every sign-in requires a further factor, a password is no longer the only factor, and `passwords.min_length`
  may be lowered from 15 to 8, as NIST SP 800-63B allows (see [Password policy](passwords.md#password-policy)).

`verifyFactor()` answers a result: ask it, never check it for `null` or truthiness:

```php
$result = Auth::passkeys()->verifyFactor($identity, $binding, $challenge, $credential, $client);
$passed = $result->isVerified();   // else $result->reason
```

### Authorisation (`laravel-authorization`)

- `Auth::principal()` and `Auth::tenant()` are the subject an authorisation decision is about; a caller's category is
  authorisation's to model, from the principal and its tenant.
- `Auth::scopes()` is the ceiling the request's credential grants: `null` for a human's session, which no credential
  limits, the granted list for an API key or a client credentials token, and `[]` for a machine bound without one.
  Intersect the principal's permissions with it; a scope never grants anything by itself (see
  [Credential scopes](machine-credentials.md#credential-scopes)).
- Bind `Contracts\ScopeRegistry` to hold the scopes a credential is issued with to real permissions (the default,
  `AcceptAnyScope`, accepts any well-formed scope).
- A policy condition reads the request's authentication context (see [Authentication context](#authentication-context)):
  type-hint `Contracts\AuthenticationContexts` and call `current()`, the seam a test rebinds, or call `Auth::context()`.
- A requirement checker of authorisation's own that judges a session's proofs reads them as a factor package does:
  `Auth::sessions($guard)->proofs($session, $since, $kinds, $limit)` and `firstFactor($session)`, read current under
  the session's lock inside a transaction (see [Reading a session's proofs](sessions.md#reading-a-sessions-proofs)).

### Authentication context

`Auth::context()` answers a `Context\AuthenticationContext` (`null` for a guest, and on a guard that is not one of the
package's): what the request is authenticated as, in plain values, for an authorisation policy's conditions. It is the
bound `Contracts\AuthenticationContexts` that answers; the default, `Context\GuardAuthenticationContexts`, asks the
default guard, which the route's `auth` middleware made the one that authenticated it (`auth:admin,api` gives the
context of whichever guard did). The guard builds it from what it validated (the request's credential, the session and
the session's proofs, the request as the trusted proxies resolve it), never from input or from a token's claims, on the
first ask after its bound state last changed, and holds it while that state is unchanged: a request reads the session's
proofs for it at most once however often it asks (one aggregate read on the write connection, and none for an API key or
a client credentials token), and nothing outlives the request, under Octane too. Every bind, sign-out and
`setPrincipal()` or `setSession()` forgets it, and so does a step-up, a reauthentication, a satisfied further factor and
a further factor's removal once each commits, for every guard the request resolved that is bound to the session. One
rolled back forgets it too, so a context built inside its transaction never outlives the proofs it read there.

The package's own keys are under the reserved `authentication` namespace, read with `get('authentication.<key>')`,
`has()` (true for a key held with a `null` value) or `toArray()`, and are stable once released:

| Key                              | Value                                                                                                                                                                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `subject_type`                   | `person`, or `machine` for a `MachineIdentity`                                                                                                                                                                                                                                            |
| `identity_type`, `identity_id`   | The identity's morph class (an Eloquent model's morph class, else its class name) and auth identifier                                                                                                                                                                                     |
| `principal_type`, `principal_id` | The principal's, the identity's own in two-dimensional mode                                                                                                                                                                                                                               |
| `tenant_type`, `tenant_id`       | The active tenant's, `null` when the request acts in none; a trusted bind's tenant that cannot be loaded throws `TenantUnavailableException`, as `Auth::tenant()` does                                                                                                                    |
| `application`                    | The guard's name, a token's `client_id`                                                                                                                                                                                                                                                   |
| `session_id`                     | The bound session's identifier, `null` without one                                                                                                                                                                                                                                        |
| `amr`                            | The session's `amr` values from its proofs, as an access token carries them: `mfa` only for multifactor authentication, `otp` for an email code, `urn:sinemacula:amr:external_provider` for an external sign-in; `[]` without a session                                                   |
| `auth_time`                      | Unix seconds of the session's newest counting proof, `null` without a session                                                                                                                                                                                                             |
| `mfa`                            | `true` when an accepted additional verification is on the session: a further factor its adapter accepted, or an external provider's evidence the evidence contract accepted for an additional verification or multifactor authentication. Never counted from `amr`, never a recovery code |
| `recovery_code`                  | `true` when an accepted recovery code is on the session                                                                                                                                                                                                                                   |
| `multifactor`                    | `true` when an accepted evaluation on the session reported multifactor authentication, exactly when `amr` carries `mfa`                                                                                                                                                                   |
| `seconds_since_step_up`          | Seconds from the newest proof that set `mfa` or `recovery_code`, at sign-in or later, to when the context was built; `null` for none                                                                                                                                                      |
| `credential`                     | `access_token`, `api_key` or `client_credentials`; `null` for a sign-in or a trusted bind (`login()`, `setUser()`, `authenticateAs()`) made in the request, and for a guard type that names none                                                                                          |
| `scopes`                         | As `Auth::scopes()`: `null` for a person's session, the granted list otherwise                                                                                                                                                                                                            |
| `ip`                             | The client's address as Laravel resolves it through the application's trusted proxies, `null` when it is not a valid one                                                                                                                                                                  |

`mfa` and `multifactor` answer different questions: `mfa` is "MFA present" (an additional verification was accepted),
`multifactor` is whether multifactor authentication was reported. Evidence the evidence contract accepted only for
phishing resistance or a minimum level is neither, and is recorded on its proof as such
(`Proofs\Evaluation::$additionalVerification`); an adapter's further factor is always an additional verification and
its recovery code never is, whatever its evaluation says, and each is recorded on its proof so.

A sibling package or the application adds keys under a namespace of its own: implement
`Contracts\AuthenticationContextContributor` and register it in a service provider's `boot()`:

```php
use SineMacula\Laravel\Authentication\Context\ContextContributors;

$this->app->make(ContextContributors::class)->register('sso', SsoContextContributor::class);
```

It is resolved from the container serving the request each time a context is built, in the order registered, and asked
once with a `Context\ContributionSubject`: the package's keys, the live identity, principal, tenant and session, and
`provenance()`, the session's external provenance (`Proofs\Provenance`: the connection and its tenant, the provider's
authentication time and deadline, the policy version, the link, the accepted evidence with the provider's own `amr`, and
the provider context the adapter gave with the result, its keys the adapter's own), read on the write connection the
first time it is asked for, in one query. `proofs($since, $kinds, $limit)` and `firstFactor()` read the counting proofs
and the first factor of the session the subject was given, never the request's, by the session service's rule (see
[Reading a session's proofs](sessions.md#reading-a-sessions-proofs)): `[]` and `null` without a session, for one that is
not an Eloquent session, and for one that is no longer one of the context's application's live, active sessions of a
person or whose key now holds another session; read again on every call (the session and then its proofs), and locked
and read current inside a transaction on the session model's connection. Each answer is as of its call, so it can show a
step-up or a void committed after the package's own keys (`amr`, `mfa`, ...) were worked out: nothing makes the two
agree. It answers its keys without the namespace: each a lower-case letter and then up to 63 lower-case letters, digits
or underscores, each value `null`, a scalar or an array of them. Anything else fails loudly with a `LogicException`
naming the namespace and key, and so does asking for the context it is being asked to build; an exception it throws
reaches the caller (a policy cannot be judged on part of a context). A namespace is a lower-case letter and then up to
31 lower-case letters, digits or underscores; `authentication` is the package's, and a second registration of a
namespace is a `LogicException`, so no contributor's keys can overwrite another's. `mfa` and `sso` are kept for the
further-factor and single sign-on packages' adapters, which register them; the package registers none. A test builds an
`AuthenticationContext` itself (its constructor is public, and refuses contributed keys no contributor could give) or
binds a fake `AuthenticationContexts`.

### Single sign-on (`laravel-sso`)

- Bind `Contracts\ExternalIdentityLinks`. Given the connection, the issuer and the subject of a result the provider
  verified, `find()` answers the link made through exactly that connection for exactly that issuer and subject
  (`External\ExternalLink`: the identity and the link's own id, opaque and compared exactly), or `null`. It never
  matches by email or any other attribute the provider asserted. It is asked inside the adapter's transaction, before
  any lock of the package's, so read the links on the write connection. The default, `NoExternalLinks`, links nothing,
  so no external result signs anyone in until the identity package's adapter binds `laravel-sso`'s links. Linking, and
  the links, are `laravel-sso`'s; this package stores none.
- Inside the transaction in which it redeems a handoff, after `laravel-sso`'s own locks, the adapter hands the verified
  result, naming the link it redeemed it through (`linkId`), the authorisation request's public reference
  (`requestReference`) and, if it wants one, its provider context (`providerContext`, below), to
  `Auth::sessions($guard)->signInExternally(new ExternalResult(...), $context)` (see [External
  sign-in](signing-in.md#external-sign-in)). On a cookie application `signInExternally()` makes no same-site check (the
  provider's callback is a cross-site navigation by design), so the adapter must bind the `state` and nonce it sends the
  provider to the browser that began the flow, refuse a callback that does not match them, and redeem the handoff once,
  for that browser: otherwise a cross-site page could sign a victim's browser into the attacker's account (see [the
  refresh token cookie](refreshing.md#refresh-token-cookie)). The application must list `external_provider` in its
  `methods`. The identity is reloaded through the guard's provider, and activity, the application policy, the
  additional-factor policy, the choice of principal and the tenant's authentication policy all apply; no attempt limit
  or timebox does, since nothing is guessed. The package takes no lock before the link contract is asked, so every row
  of its own it locks (the link's connection guard, then any session the sign-in replaces) is locked after the adapter's
  own. A database error, a PostgreSQL serialization failure included, propagates for the adapter to retry the whole
  transaction. The contract must answer exactly the link the result names (`link_mismatch` otherwise). Once committed,
  `ExternalResultRedeemed` reports the redemption with the connection and the request reference, which the redemption's
  failures carry too, so they correlate with `laravel-sso`'s completion events.
- A result linked to no identity dispatches `ExternalResultUnlinked` and fails as `external_result_unlinked`. The event
  is informational: `laravel-iam` provisions on `laravel-sso`'s own unlinked-result event, before any handoff is issued,
  never on this one, since provisioning on both would provision twice.
- An external result never arrives as a sign-in's input: `external_provider` is reserved, so no sign-in method can be
  registered under it, `signIn()` cannot reach it and `start()` refuses it.
- The session records the method `external_provider` and its provenance once (the connection and its tenant, the
  provider's authentication time, its session deadline, the policy version, the link's id and the provider context),
  indexed by connection and by tenant. Its first proof is the provider's, with the private `amr` value
  `urn:sinemacula:amr:external_provider`, and the provider's deadline caps the session. The provider's own `amr` values
  never become this package's: its evidence counts only once the application's `ExternalEvidencePolicy` accepts it (see
  [Tenant authentication policies](#tenant-authentication-policies)), and is recorded only then. The application can
  stop allowing `external_provider`, and those sessions stop refreshing.
- The adapter keeps details of how the provider established the session (the protocol, say, or whether the link was
  verified by domain or made explicitly) with it by passing an `External\ProviderContext` as the result's
  `providerContext`. Its keys are the contributing package's own: this package reserves none, names none and never
  interprets them. It is a map with string keys whose values are `null`, booleans, integers, finite floats, strings or
  arrays (lists or maps) of them, nesting at most `MAX_DEPTH` (4) arrays, the map the first, and taking at most
  `STORED_MAX_BYTES` (4096) bytes as the JSON the package stores, every character outside ASCII escaped; anything else
  is refused with an `InvalidArgumentException` whose message repeats no value, never truncated. It is written once,
  with the provenance, by the sign-in (pending or active), carried through activation, refresh and switch, and never
  rewritten: `reauthenticateExternally()` ignores a result's provider context, so the session keeps the one it was
  established with. The package never logs it, never puts it in an event, the event context or an exception message, and
  hides its column from the provenance model's serialisation; it is provider metadata, not a place for a secret or a
  credential. The adapter's own contributor reads it as `$subject->provenance()?->providerContext?->toArray()`, in the
  same read as the rest of the provenance, and reports what it wants of it under its own namespace (`sso.*`, say); the
  package's own `authentication` keys carry nothing of it.
- A tenant that requires sign-in through its connections says so through its `TenantAuthenticationPolicy` (see
  [Tenant authentication policies](#tenant-authentication-policies)): a session established through none of them is
  refused as `sso_required`, at sign-in and at refresh (which also revokes it).
- Inside the transaction in which it redeems a reauthentication handoff, the adapter hands the identifier of the session
  the handoff names, the result and the request's client, to
  `Auth::sessions($guard)->reauthenticateExternally($sessionId, $result, $client)` (see [At
  the external provider](sessions.md#at-the-external-provider)): only the very link that established the session
  reauthenticates it (`link_mismatch` otherwise, and for a session no link established), the session's row is locked
  after the adapter's own locks, and `auth_time` becomes the later of the session's and the provider's, under that lock
  and after the session's issuance guard (see [Issuance order](sessions.md#issuance-order)), so another issuance of the
  session that overlaps it is counted or waits; at PostgreSQL's REPEATABLE READ, a redemption whose snapshot predates
  one fails to serialise, for the adapter to retry the whole transaction. The tenant's authentication policy and the
  evidence policy are then asked under that lock, so neither may take a lock the adapter takes after the session's row.
  An adapter that must answer a session's standing (`laravel-sso`'s re-authentication sessions) asks
  `externalStanding($sessionId, $identity, $connectionId, $linkId)`: with no link id and outside a transaction when a
  flow starts, which locks nothing, and with the link id inside the redemption's transaction, which locks the row and
  reads its provenance current (see [Issuance order](sessions.md#issuance-order)), so a key another sign-in reused
  after the transaction's first read is answered on its own provenance; it answers `null` or the reason.
- When a link is removed, or its scope widened so it may act for more than its sessions were established for, the
  adapter calls `linkRemoved($identity, $connectionId, $linkId)` or `linkScopeWidened(...)` in the same transaction (see
  [Connections and links](sessions.md#connections-and-links)): each ends only the identity's sessions established
  through that link. `linkScopeWidened()` is mandatory and safe to repeat; `linkRemoved()` honours its setting. Any
  isolation level will do: a sign-in through the link and the revocation both write the link's connection guard first
  (a connection's disabling or deletion every guard of the connection), so at PostgreSQL's REPEATABLE READ or
  SERIALIZABLE, where no read sees a session a sign-in committed after the transaction's snapshot, the later of the two
  fails to serialise (40001) instead, and the adapter retries its whole transaction.

### Audit (`laravel-audit-log`)

- With `laravel-iam` installed, it maps every package event into the audit log, and there is nothing to wire. Without
  it, register an `EventMapper` for `Contracts\AuthenticationEvent` with `AuditLog::map()`, giving each event an
  explicit, dotted code (see [Events](events.md#events) for an example).
- Every package event carries one `Events\EventContext`, so one mapper records them all from its plain values: when, the
  guard, the client, the identity, principal and tenant by type and identifier (`identityType`/`identityId`,
  `principalType`/`principalId`, `tenantType`/`tenantId`), the session's identifier (`sessionId`), the method, the
  credential and its scopes (`credentialId`, `scopes`), and for a redeemed external result the connection and the
  request reference, never a model and never a secret. A failure's `challengeId` names the challenge it answered.
- Events that report a write are dispatched once it commits on the written row's connection, and never for a rolled-back
  one, so a mapped event is recorded at once and only for what happened.
- `laravel-audit-log` also records Laravel's own `Login`, `Failed` and `Logout`. This package's guards dispatch those
  beside their own `SignedIn`, `AuthenticationFailed` and `SessionRevoked`, so list every guard whose driver is `jwt`
  or `api_key` in `audit-log.capture.laravel.except_guards`, or each sign-in is recorded twice.
