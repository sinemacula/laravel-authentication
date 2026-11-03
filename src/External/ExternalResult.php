<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

/**
 * A result an external identity provider verified: the connection (the
 * configured provider) it came through, the issuer and the subject the provider
 * asserted, the connection's tenant, when the provider authenticated the
 * identity, the provider's own deadline for its session (SAML
 * `SessionNotOnOrAfter`), the version of the enforcement or policy the adapter
 * checked, and the evidence the provider asserted of how it authenticated the
 * identity, which counts only once the evidence contract accepts it.
 *
 * Only a trusted server-side adapter builds one, from a result it verified
 * itself (a redeemed handoff, say), never from what a client sent: the session
 * service takes it as proof the provider authenticated whoever the link
 * contract maps the connection, issuer and subject to. The connection, issuer
 * and subject are kept exactly as given, and times to the whole second.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExternalResult
{
    /** @var int Longest connection or tenant id, in characters. */
    public const int ID_MAX_LENGTH = 255;

    /** @var int Longest issuer, in characters. */
    public const int ISSUER_MAX_LENGTH = 2048;

    /** @var int Longest subject, in characters. */
    public const int SUBJECT_MAX_LENGTH = 1024;

    /** @var int Longest policy version, in characters. */
    public const int VERSION_MAX_LENGTH = 64;

    /** @var ?\Carbon\CarbonImmutable When the provider authenticated the identity, to the whole second. */
    public ?CarbonImmutable $authenticatedAt;

    /** @var ?\Carbon\CarbonImmutable The provider's deadline for its session, to the whole second. */
    public ?CarbonImmutable $sessionNotAfter;

    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $tenantId
     * @param  ?\Carbon\CarbonInterface  $authenticatedAt
     * @param  ?\Carbon\CarbonInterface  $sessionNotAfter
     * @param  ?string  $policyVersion
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The connection (the configured external provider) the result came through. */
        public string $connectionId,

        /** The issuer the provider asserted. */
        public string $issuer,

        /** The subject the provider asserted, unique within its issuer. */
        public string $subject,

        /** The tenant the connection belongs to, if any. */
        public ?string $tenantId = null,

        // When the provider authenticated the identity, if it said.
        ?CarbonInterface $authenticatedAt = null,

        // The provider's deadline for its session, if it gave one.
        ?CarbonInterface $sessionNotAfter = null,

        /** The version of the enforcement or policy the adapter checked, if any. */
        public ?string $policyVersion = null,

        /** The evidence the provider asserted of how it authenticated the identity, if any. */
        public ?ExternalEvidence $evidence = null,
    ) {
        self::assertText($connectionId, self::ID_MAX_LENGTH, 'connection id');
        self::assertText($issuer, self::ISSUER_MAX_LENGTH, 'issuer');
        self::assertText($subject, self::SUBJECT_MAX_LENGTH, 'subject');
        self::assertText($tenantId, self::ID_MAX_LENGTH, 'tenant id');
        self::assertText($policyVersion, self::VERSION_MAX_LENGTH, 'policy version');

        $this->authenticatedAt = $authenticatedAt === null ? null : CarbonImmutable::instance($authenticatedAt)->startOfSecond();
        $this->sessionNotAfter = $sessionNotAfter === null ? null : CarbonImmutable::instance($sessionNotAfter)->startOfSecond();
    }

    /**
     * Refuse a value that is empty or longer than it may be.
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
            throw new \InvalidArgumentException(sprintf('An external result\'s %s, when given, must be from 1 to %d characters.', $name, $max));
        }
    }
}
