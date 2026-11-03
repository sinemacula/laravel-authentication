<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

/**
 * How a session established through an external identity provider began: the
 * connection and its tenant, when the provider authenticated the identity, the
 * provider's own deadline for its session (SAML `SessionNotOnOrAfter`), the
 * version of the enforcement or policy the caller checked, and the id of the
 * link the result was mapped to its identity through.
 *
 * Built by the session service from a trusted server-side adapter's result and
 * the link the link contract found, never from what a client sent. The session
 * records it once, beside its proofs, and nothing rewrites it: a later
 * reauthentication at the provider is a proof of its own, and must come through
 * the very link recorded here. The evidence the provider asserted is not part
 * of it, and no evidence is recorded with it: nothing decides yet whether a
 * provider's evidence is accepted. Times are kept to the whole second.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Provenance
{
    /** @var int Longest connection, tenant or link id, in characters: the columns' length. */
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
     * @param  ?string  $linkId
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

        /** The id of the link the result was mapped to its identity through, opaque and compared exactly; `null` for none. */
        public ?string $linkId = null,
    ) {
        self::assertText($connectionId, self::ID_MAX_LENGTH, 'connection id');
        self::assertText($tenantId, self::ID_MAX_LENGTH, 'tenant id');
        self::assertText($policyVersion, self::VERSION_MAX_LENGTH, 'policy version');
        self::assertText($linkId, self::ID_MAX_LENGTH, 'link id');

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
