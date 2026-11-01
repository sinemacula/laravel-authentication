<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

/**
 * How a session established through an external identity provider began: the
 * connection and its tenant, when the provider authenticated the identity, the
 * provider's own deadline for its session (SAML `SessionNotOnOrAfter`), and the
 * version of the enforcement or policy the caller checked.
 *
 * Given by a trusted server-side caller, never built from what a client sent.
 * The session records it once, beside its proofs, and nothing rewrites it: a
 * later reauthentication at the provider is a proof of its own. The evidence
 * the provider asserted is not part of it: only the evidence contract, when it
 * accepts that evidence, records it. Times are kept to the whole second.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Provenance
{
    /** @var int Longest connection or tenant id, in characters: the columns' length. */
    public const int ID_MAX_LENGTH = 255;

    /** @var int Longest policy version, in characters: the column's length. */
    public const int VERSION_MAX_LENGTH = 64;

    /** @var ?\Carbon\CarbonImmutable When the provider authenticated the identity, to the whole second. */
    public ?CarbonImmutable $providerAuthenticatedAt;

    /** @var ?\Carbon\CarbonImmutable The provider's deadline for its session, to the whole second. */
    public ?CarbonImmutable $sessionNotAfter;

    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  ?string  $tenantId
     * @param  ?\Carbon\CarbonInterface  $providerAuthenticatedAt
     * @param  ?\Carbon\CarbonInterface  $sessionNotAfter
     * @param  ?string  $policyVersion
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The connection (the configured external provider) the session was established through. */
        public string $connectionId,

        /** The tenant the connection belongs to, if any. */
        public ?string $tenantId = null,

        // When the provider authenticated the identity, if it said.
        ?CarbonInterface $providerAuthenticatedAt = null,

        // The provider's deadline for its session, if it gave one.
        ?CarbonInterface $sessionNotAfter = null,

        /** The version of the enforcement or policy the caller checked, if any. */
        public ?string $policyVersion = null,
    ) {
        self::assertText($connectionId, self::ID_MAX_LENGTH, 'connection id');
        self::assertText($tenantId, self::ID_MAX_LENGTH, 'tenant id');
        self::assertText($policyVersion, self::VERSION_MAX_LENGTH, 'policy version');

        $this->providerAuthenticatedAt = $providerAuthenticatedAt === null ? null : CarbonImmutable::instance($providerAuthenticatedAt)->startOfSecond();
        $this->sessionNotAfter         = $sessionNotAfter         === null ? null : CarbonImmutable::instance($sessionNotAfter)->startOfSecond();
    }

    /**
     * Refuse a value that is empty or longer than its column.
     *
     * @param  ?string  $value
     * @param  int  $max
     * @param  string  $name
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertText(?string $value, int $max, string $name): void
    {
        if ($value !== null && ($value === '' || mb_strlen($value) > $max)) {
            throw new \InvalidArgumentException(sprintf('A provenance\'s %s, when given, must be from 1 to %d characters.', $name, $max));
        }
    }
}
