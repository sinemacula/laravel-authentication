<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Proofs\ProofHistory;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\MorphClass;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Builds the authentication context of what a guard bound, then adds each
 * registered contributor's keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContextBuilder
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Build the context of the state the guard bound.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Context\Enums\CredentialKind  $credential
     * @param  ?list<string>  $scopes
     * @return \SineMacula\Laravel\Authentication\Context\AuthenticationContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function build(
        GuardContext $guard,
        Identity $identity,
        Principal $principal,
        ?Tenant $tenant,
        ?Session $session,
        ?CredentialKind $credential,
        ?array $scopes,
    ): AuthenticationContext {
        $now         = CarbonImmutable::now();
        $history     = $session instanceof EloquentSession && $session instanceof Model ? SessionProofs::history($session) : new ProofHistory([]);
        $steppedUpAt = $history->steppedUpAt();

        $keys = [
            'subjectType'        => $identity instanceof MachineIdentity ? SubjectType::MACHINE : SubjectType::PERSON,
            'identityType'       => MorphClass::of($identity),
            'identityId'         => IdentifierCoercion::stringify($identity->getAuthIdentifier()),
            'principalType'      => MorphClass::of($principal),
            'principalId'        => PrincipalReference::id($principal),
            'tenantType'         => $tenant === null ? null : MorphClass::of($tenant),
            'tenantId'           => $tenant === null ? null : IdentifierCoercion::stringify($tenant->getTenantIdentifier()),
            'application'        => $guard->name(),
            'sessionId'          => $session === null ? null : IdentifierCoercion::stringify($session->getSessionIdentifier()),
            'amr'                => $history->methods(),
            'authTime'           => $history->authenticatedAt(),
            'mfa'                => $history->hasAdditionalVerification(),
            'recoveryCode'       => $history->hasRecoveryCode(),
            'multifactor'        => $history->isMultifactor(),
            'secondsSinceStepUp' => $steppedUpAt === null ? null : max(0, $now->getTimestamp() - $steppedUpAt->getTimestamp()),
            'credential'         => $credential,
            'scopes'             => $scopes,
            'ip'                 => $guard->client()->ip,
        ];

        $subject = new ContributionSubject(new AuthenticationContext(...$keys), $identity, $principal, $tenant, $session);

        return new AuthenticationContext(...$keys, contributed: self::contributions($subject));
    }

    /**
     * Every registered contributor's keys, by namespace, in the order
     * registered.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, array<string, mixed>>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private static function contributions(ContributionSubject $subject): array
    {
        $container   = Container::getInstance();
        $contributed = [];

        foreach ($container->make(ContextContributors::class)->registered() as $namespace => $abstract) {
            $contributed[$namespace] = self::keysOf($namespace, $container->make($abstract), $subject);
        }

        return $contributed;
    }

    /**
     * The keys the contributor adds under its namespace, once checked.
     *
     * @param  string  $namespace
     * @param  mixed  $contributor
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    private static function keysOf(string $namespace, mixed $contributor, ContributionSubject $subject): array
    {
        if (!$contributor instanceof AuthenticationContextContributor) {
            throw new \LogicException(sprintf('The context contributor registered under [%s] does not implement %s.', $namespace, AuthenticationContextContributor::class));
        }

        $keys = ContextKeys::checked($namespace, $contributor->contribute($subject));

        if (is_string($keys)) {
            throw new \LogicException($keys);
        }

        return $keys;
    }
}
