<?php

declare(strict_types = 1);

namespace Tests\Unit\Contracts;

use Illuminate\Contracts\Auth\Authenticatable as LaravelAuthenticatable;
use Illuminate\Contracts\Auth\Guard as LaravelGuard;
use Illuminate\Contracts\Auth\UserProvider as LaravelUserProvider;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\EloquentSessionOrigin;
use SineMacula\Laravel\Authentication\Contracts\EloquentSessionStanding;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormalizer;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;

/**
 * Reflection-based structural tests for the package contracts.
 *
 * Pins the documented method surface of every contract and the inheritance
 * chains that let framework typehints resolve against package implementations.
 * Marked `#[CoversNothing]` because PHPUnit cannot attribute coverage to a bare
 * interface; the assertions run against interface metadata only.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[CoversNothing]
final class ContractDeclarationTest extends TestCase
{
    /**
     * `IdentityProvider` extends Laravel's framework `UserProvider` contract so
     * the package provider drops into Laravel's `Auth::createUserProvider()`
     * factory unchanged.
     *
     * @return void
     */
    public function testIdentityProviderExtendsLaravelUserProvider(): void
    {
        $reflection = new \ReflectionClass(IdentityProvider::class);

        self::assertTrue($reflection->isInterface());
        self::assertContains(LaravelUserProvider::class, $reflection->getInterfaceNames());
    }

    /**
     * `Identity` extends `Illuminate\Contracts\Auth\Authenticatable` so every
     * identity satisfies Laravel's framework typehints.
     *
     * @return void
     */
    public function testIdentityExtendsLaravelAuthenticatable(): void
    {
        $reflection = new \ReflectionClass(Identity::class);

        self::assertTrue($reflection->isInterface());
        self::assertContains(LaravelAuthenticatable::class, $reflection->getInterfaceNames());
    }

    /**
     * `Session` declares exactly the read surface the guards, the refresh
     * exchange, the session service, and the package events depend on: the
     * identifier, last use, both refresh digests and the rotation time, both
     * deadlines, the revocation, the guard and sign-in method that started the
     * session, its status and requirements, the pending credential's digest,
     * the active tenant and policy version, and the floor its context changes
     * set.
     *
     * @return void
     */
    public function testSessionContractDeclaresExactlyItsReadSurface(): void
    {
        self::assertSame([
            'getAbsoluteExpiresAt',
            'getGuard',
            'getIdleExpiresAt',
            'getLastUsedAt',
            'getPendingKey',
            'getPreviousRefreshKey',
            'getRefreshKey',
            'getRefreshRotatedAt',
            'getRequires',
            'getRevokedAt',
            'getRevokedReason',
            'getSessionIdentifier',
            'getSignInIdentifierType',
            'getSignInMethod',
            'getSignedInAt',
            'getStatus',
            'getSwitchedAt',
            'getTenantId',
            'getTenantPolicyVersion',
        ], self::declaredMethods(Session::class));
    }

    /**
     * `EloquentSession` extends the generic `Session` contract with the
     * relation and column-name accessors required by refresh persistence paths.
     *
     * @return void
     */
    public function testEloquentSessionExtendsSession(): void
    {
        self::assertContains(
            Session::class,
            (new \ReflectionClass(EloquentSession::class))->getInterfaceNames(),
        );
        self::assertContains(
            EloquentSessionOrigin::class,
            (new \ReflectionClass(EloquentSession::class))->getInterfaceNames(),
        );
        self::assertContains(
            EloquentSessionStanding::class,
            (new \ReflectionClass(EloquentSession::class))->getInterfaceNames(),
        );
    }

    /**
     * `EloquentSession` adds exactly the owner and principal relations and the
     * column names the session creation, activation, refresh, revocation, and
     * last-use writes need, and the generation's and the issuance guard's,
     * besides those of the session's origin and standing. The identifier has no
     * column name: it is always the primary key.
     *
     * @return void
     */
    public function testEloquentSessionContractDeclaresExactlyItsPersistenceHooks(): void
    {
        self::assertSame([
            'authenticatable',
            'getAbsoluteExpiresAtName',
            'getGenerationName',
            'getIdleExpiresAtName',
            'getIssuanceSequenceName',
            'getLastUsedAtName',
            'getLastUsedIpName',
            'getLastUsedUserAgentName',
            'getPreviousRefreshKeyName',
            'getRefreshKeyName',
            'getRefreshRotatedAtName',
            'getRevokedAtName',
            'getRevokedReasonName',
            'getSignedInAtName',
            'getSwitchedAtName',
            'principal',
        ], self::declaredMethods(EloquentSession::class));
    }

    /**
     * `EloquentSessionOrigin` declares exactly the column names of what a
     * session started with, which the session service writes.
     *
     * @return void
     */
    public function testEloquentSessionOriginDeclaresExactlyTheOriginColumns(): void
    {
        self::assertSame([
            'getClientNameName',
            'getCreatedIpName',
            'getCreatedUserAgentName',
            'getGuardName',
            'getPlatformName',
            'getSignInIdentifierTypeName',
            'getSignInMethodName',
        ], self::declaredMethods(EloquentSessionOrigin::class));
    }

    /**
     * `EloquentSessionStanding` declares exactly the column names of where a
     * session stands: its status, what it waits on, its pending credential, the
     * session it supersedes, the slots it keeps, and its active tenant.
     *
     * @return void
     */
    public function testEloquentSessionStandingDeclaresExactlyTheStandingColumns(): void
    {
        self::assertSame([
            'getAttemptWindowsName',
            'getPendingKeyName',
            'getRequiresName',
            'getStatusName',
            'getSupersedesRefreshKeyName',
            'getSupersedesSessionIdName',
            'getTenantIdName',
            'getTenantPolicyVersionName',
        ], self::declaredMethods(EloquentSessionStanding::class));
    }

    /**
     * `EloquentSession::authenticatable()` and `principal()` must return
     * MorphTo relations, and the persistence column-name accessors, its
     * origin's and standing's included, must return strings.
     *
     * @return void
     */
    public function testEloquentSessionDeclaresExpectedReturnTypes(): void
    {
        foreach (['authenticatable', 'principal'] as $relation) {
            $relationReturn = (new \ReflectionMethod(EloquentSession::class, $relation))->getReturnType();
            self::assertInstanceOf(\ReflectionNamedType::class, $relationReturn);
            self::assertSame(MorphTo::class, $relationReturn->getName());
        }

        $persistence         = array_diff(self::declaredMethods(EloquentSession::class), ['authenticatable', 'principal']);
        $columnNameAccessors = [...$persistence, ...self::declaredMethods(EloquentSessionOrigin::class), ...self::declaredMethods(EloquentSessionStanding::class)];

        foreach ($columnNameAccessors as $method) {
            $returnType = (new \ReflectionMethod(EloquentSession::class, $method))->getReturnType();
            self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
            self::assertSame('string', $returnType->getName());
        }
    }

    /**
     * Data provider listing the methods `Principal` must declare.
     *
     * @return \Generator<string, array{0: string}>
     */
    public static function providePrincipalContractMethods(): iterable
    {
        yield from [
            'getPrincipalIdentifier' => ['getPrincipalIdentifier'],
            'getIdentity'            => ['getIdentity'],
            'getTenant'              => ['getTenant'],
        ];
    }

    /**
     * `Principal` declares every method the contextual guards and default
     * resolver depend on.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('providePrincipalContractMethods')]
    public function testPrincipalContractDeclaresMethod(string $method): void
    {
        self::assertTrue(
            (new \ReflectionClass(Principal::class))->hasMethod($method),
            "Principal contract must declare {$method}().",
        );
    }

    /**
     * Activation is opt-in: `Principal` does not declare `isActive()`, the
     * `CanBeActive` capability does.
     *
     * @return void
     */
    public function testActivationIsDeclaredOnlyByTheCanBeActiveCapability(): void
    {
        self::assertFalse((new \ReflectionClass(Principal::class))->hasMethod('isActive'));
        self::assertTrue((new \ReflectionClass(CanBeActive::class))->hasMethod('isActive'));
    }

    /**
     * `Tenant` declares the identifier accessor used by the contextual
     * accessors.
     *
     * @return void
     */
    public function testTenantContractDeclaresGetTenantIdentifier(): void
    {
        self::assertTrue(
            (new \ReflectionClass(Tenant::class))->hasMethod('getTenantIdentifier'),
            'Tenant contract must declare getTenantIdentifier().',
        );
    }

    /**
     * `ApplicationPolicy` declares exactly the four questions the package asks
     * an application's settings: may this method start a session (or this
     * machine credential be accepted), may a client credentials exchange read
     * the client from the body, may this identity sign in with this identifier,
     * and for how long; the second and the last depend on the guard alone.
     * Which principals may hold a session is not among them.
     *
     * @return void
     */
    public function testApplicationPolicyDeclaresExactlyItsChecks(): void
    {
        $lifetimes = (new \ReflectionMethod(ApplicationPolicy::class, 'lifetimes'))->getParameters();
        $post      = new \ReflectionMethod(ApplicationPolicy::class, 'allowsClientSecretPost');

        self::assertSame(['admitIdentifier', 'allowsClientSecretPost', 'allowsMethod', 'lifetimes'], self::declaredMethods(ApplicationPolicy::class));
        self::assertCount(1, $lifetimes);
        self::assertSame('guard', $lifetimes[0]->getName());
        self::assertSame('string', (string) $lifetimes[0]->getType());
        self::assertSame(['guard'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $post->getParameters()));
        self::assertSame('bool', (string) $post->getReturnType());
    }

    /**
     * The access contracts each declare one yes-or-no question, and the
     * resolver one lookup by an opaque identifier: may this principal use this
     * application, may it act in this tenant (or in none), and which tenant an
     * identifier names.
     *
     * @return void
     */
    public function testTheAccessContractsDeclareOneQuestionEach(): void
    {
        $mayActIn = (new \ReflectionMethod(TenantAccess::class, 'mayActIn'))->getParameters();
        $resolve  = (new \ReflectionMethod(TenantResolver::class, 'resolve'))->getParameters();

        self::assertSame(['mayUse'], self::declaredMethods(ApplicationAccess::class));
        self::assertSame(['mayActIn'], self::declaredMethods(TenantAccess::class));
        self::assertSame(['resolve'], self::declaredMethods(TenantResolver::class));
        self::assertSame('?' . Tenant::class, (string) $mayActIn[1]->getType());
        self::assertSame('string', (string) $resolve[0]->getType());
        self::assertSame('?' . Tenant::class, (string) (new \ReflectionMethod(TenantResolver::class, 'resolve'))->getReturnType());
    }

    /**
     * `AttemptLimiter` declares the reserve-and-release pair for flows that
     * guess a secret and the read-and-count pair for flows that count only
     * failures.
     *
     * @return void
     */
    public function testAttemptLimiterDeclaresExactlyItsTwoCountingModes(): void
    {
        self::assertSame(['acquire', 'blocked', 'recordFailure', 'release'], self::declaredMethods(AttemptLimiter::class));
    }

    /**
     * Verifiable identifiers are a capability an identity opts into:
     * `HasVerifiableIdentifiers` declares reading the identifier, reading its
     * verification, and recording it, and `Identity` declares none of them.
     *
     * @return void
     */
    public function testVerifiableIdentifiersAreACapabilityOfTheIdentity(): void
    {
        self::assertSame(
            ['getIdentifierForVerification', 'hasVerifiedIdentifier', 'markIdentifierAsVerified'],
            self::declaredMethods(HasVerifiableIdentifiers::class),
        );
        self::assertFalse((new \ReflectionClass(Identity::class))->hasMethod('hasVerifiedIdentifier'));
    }

    /**
     * `IdentifierNormalizer` declares only `normalize()`, which may refuse a
     * value by returning `null`.
     *
     * @return void
     */
    public function testIdentifierNormalizerDeclaresOnlyNormalize(): void
    {
        $method = new \ReflectionMethod(IdentifierNormalizer::class, 'normalize');

        self::assertSame(['normalize'], self::declaredMethods(IdentifierNormalizer::class));
        self::assertSame('?string', (string) $method->getReturnType());
    }

    /**
     * `HasSessions::sessions()` must return an
     * `Illuminate\Contracts\Database\Eloquent\Builder` so the guards'
     * `resolveSessionFromHint()` path can query through a uniform surface.
     *
     * @return void
     */
    public function testHasSessionsDeclaresSessionsReturnType(): void
    {
        $reflection = new \ReflectionMethod(HasSessions::class, 'sessions');

        $returnType = $reflection->getReturnType();

        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertSame(
            Builder::class,
            $returnType->getName(),
        );
    }

    /**
     * `HasPrincipals::principals()` must return an
     * `Illuminate\Contracts\Database\Eloquent\Builder` and
     * `resolveDefaultPrincipal()` must return a nullable `Principal`.
     *
     * @return void
     */
    public function testHasPrincipalsDeclaresReturnTypes(): void
    {
        $principalsReturn = (new \ReflectionMethod(HasPrincipals::class, 'principals'))->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $principalsReturn);
        self::assertSame(
            Builder::class,
            $principalsReturn->getName(),
        );

        $resolveReturn = (new \ReflectionMethod(HasPrincipals::class, 'resolveDefaultPrincipal'))->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $resolveReturn);
        self::assertTrue($resolveReturn->allowsNull());
        self::assertSame(Principal::class, $resolveReturn->getName());
    }

    /**
     * `ResolvesHintedPrincipal::resolveHintedPrincipal()` must return a
     * nullable `Principal`.
     *
     * @return void
     */
    public function testResolvesHintedPrincipalDeclaresReturnType(): void
    {
        $returnType = (new \ReflectionMethod(ResolvesHintedPrincipal::class, 'resolveHintedPrincipal'))->getReturnType();

        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertTrue($returnType->allowsNull());
        self::assertSame(Principal::class, $returnType->getName());
    }

    /**
     * `JwtGuard` implements the package `ContextualGuard` interface so
     * typehints on the package facade and service locator resolve correctly.
     *
     * @return void
     */
    public function testJwtGuardImplementsContextualGuard(): void
    {
        self::assertTrue(
            (new \ReflectionClass(JwtGuard::class))->implementsInterface(ContextualGuard::class),
            'JwtGuard must implement ContextualGuard.',
        );
    }

    /**
     * `JwtGuard` implements Laravel's framework `Guard` contract so first-party
     * `Auth::guard()->user()` calls return a framework- compatible guard.
     *
     * @return void
     */
    public function testJwtGuardImplementsLaravelGuard(): void
    {
        self::assertTrue(
            (new \ReflectionClass(JwtGuard::class))->implementsInterface(LaravelGuard::class),
            'JwtGuard must implement Illuminate\Contracts\Auth\Guard.',
        );
    }

    /**
     * Data provider listing every method on Laravel's `Guard` contract.
     *
     * @return \Generator<string, array{0: string}>
     */
    public static function provideLaravelGuardMethods(): iterable
    {
        yield from [
            'check'    => ['check'],
            'guest'    => ['guest'],
            'user'     => ['user'],
            'id'       => ['id'],
            'validate' => ['validate'],
            'hasUser'  => ['hasUser'],
            'setUser'  => ['setUser'],
        ];
    }

    /**
     * The shipped guard declares every method on Laravel's `Guard` contract.
     * Pins the full conformance surface in one reflection scan so a renamed
     * contract method fails the suite cleanly.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideLaravelGuardMethods')]
    public function testShippedGuardDeclaresLaravelGuardMethod(string $method): void
    {
        self::assertTrue(
            (new \ReflectionClass(JwtGuard::class))->hasMethod($method),
            "JwtGuard must declare {$method}().",
        );
    }

    /**
     * `SignInMethod` declares exactly what the session service asks of a
     * method: the identifier type, the identifier the input names, the
     * challenge it answers, and the verification itself.
     *
     * @return void
     */
    public function testSignInMethodDeclaresExactlyItsVerificationSurface(): void
    {
        self::assertSame(['authenticate', 'challenge', 'identifier', 'identifierType'], self::declaredMethods(SignInMethod::class));
    }

    /**
     * `AdditionalFactorPolicy` declares the one decision it makes.
     *
     * @return void
     */
    public function testAdditionalFactorPolicyDeclaresOneDecision(): void
    {
        self::assertSame(['requirementFor'], self::declaredMethods(AdditionalFactorPolicy::class));
    }

    /**
     * The passkey factor gate is asked before a registration and a removal, and
     * about nothing else.
     *
     * @return void
     */
    public function testPasskeyFactorGateDeclaresItsTwoChanges(): void
    {
        self::assertSame(['registering', 'removing'], self::declaredMethods(PasskeyFactorGate::class));
    }

    /**
     * The external identity link contract declares one lookup, by connection,
     * issuer and subject, and nothing that finds a link by anything else.
     *
     * @return void
     */
    public function testExternalIdentityLinksDeclaresOneLookup(): void
    {
        self::assertSame(['find'], self::declaredMethods(ExternalIdentityLinks::class));
        $parameters = (new \ReflectionMethod(ExternalIdentityLinks::class, 'find'))->getParameters();

        self::assertSame(['connectionId', 'issuer', 'subject'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $parameters));
    }

    /**
     * `AuthenticationEvent` declares only the context every package event
     * carries.
     *
     * @return void
     */
    public function testAuthenticationEventDeclaresOnlyItsContext(): void
    {
        self::assertSame(['context'], self::declaredMethods(AuthenticationEvent::class));
    }

    /**
     * Every event the package ships implements `AuthenticationEvent`, so one
     * listener on the contract receives them all.
     *
     * @return void
     */
    public function testEveryPackageEventImplementsAuthenticationEvent(): void
    {
        $events = [];

        foreach (glob(__DIR__ . '/../../../src/Events/*.php') ?: [] as $file) {

            $class = 'SineMacula\Laravel\Authentication\Events\\' . basename($file, '.php');

            if ($class === EventContext::class) {
                continue;
            }

            $events[$class] = (new \ReflectionClass($class))->implementsInterface(AuthenticationEvent::class);
        }

        self::assertNotEmpty($events);
        self::assertSame(array_fill_keys(array_keys($events), true), $events);
    }

    /**
     * "Tokens valid after" is a capability an identity or principal declares on
     * its own: reading the time and moving it forward.
     *
     * @return void
     */
    public function testTokensValidAfterIsACapabilityOfItsOwn(): void
    {
        self::assertSame(['getTokensValidAfter', 'invalidateTokensIssuedBefore'], self::declaredMethods(HasTokensValidAfter::class));
        self::assertNotContains(HasTokensValidAfter::class, (new \ReflectionClass(Identity::class))->getInterfaceNames());
        self::assertNotContains(HasTokensValidAfter::class, (new \ReflectionClass(Principal::class))->getInterfaceNames());
    }

    /**
     * The freshness contract carries its read mode: `freshProof()` and
     * `freshUntil()` each take, last, whether the session is judged as
     * committed (`$current`), plain unless asked.
     *
     * @return void
     */
    public function testTheFreshnessContractCarriesItsReadMode(): void
    {
        foreach (['freshProof', 'freshUntil'] as $method) {
            $parameters = (new \ReflectionMethod(FreshnessPolicy::class, $method))->getParameters();
            $names      = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $parameters);
            $current    = $parameters[4];

            self::assertSame(['session', 'operation', 'requirement', 'excludingFactor', 'current'], $names, $method);
            self::assertSame('bool', (string) $current->getType(), $method);
            self::assertFalse($current->getDefaultValue(), $method);
        }
    }

    /**
     * No package contract names a method after a device: the record is a
     * session everywhere.
     *
     * @return void
     */
    public function testNoContractNamesAMethodAfterADevice(): void
    {
        $contracts = glob(dirname(__DIR__, 3) . '/src/Contracts/*.php') ?: [];

        self::assertNotEmpty($contracts);

        foreach ($contracts as $file) {
            $interface = 'SineMacula\Laravel\Authentication\Contracts\\' . basename($file, '.php');

            foreach (self::declaredMethods($interface) as $method) {
                self::assertStringNotContainsStringIgnoringCase('device', $method, $interface . '::' . $method);
            }
        }
    }

    /**
     * The sorted names of the methods an interface declares itself, without the
     * ones it inherits.
     *
     * @param  class-string  $interface
     * @return list<string>
     */
    private static function declaredMethods(string $interface): array
    {
        $reflection = new \ReflectionClass($interface);

        $names = array_map(
            static fn (\ReflectionMethod $method): string => $method->getName(),
            array_filter(
                $reflection->getMethods(),
                static fn (\ReflectionMethod $method): bool => $method->getDeclaringClass()->getName() === $interface,
            ),
        );

        sort($names);

        return $names;
    }
}
