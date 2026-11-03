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
 * checked, the evidence the provider asserted of how it authenticated the
 * identity, which counts only once the evidence contract accepts it, and the id
 * of the link the adapter redeemed the result through, when it names one.
 *
 * Only a trusted server-side adapter builds one, from a result it verified
 * itself (a redeemed handoff, say), never from what a client sent: the session
 * service takes it as proof the provider authenticated whoever the link
 * contract maps the connection, issuer and subject to. The connection, issuer
 * and subject are kept exactly as given, and times to the whole second. The
 * provider's time is when the result says it authenticated the identity, and
 * times the proof; the evidence's own time is what its acceptance and any
 * requirement judged on it age. Evidence is never for a later authentication
 * than the result's: evidence dated after the provider's time, when the result
 * gives one, is refused. The link the session is recorded under is always the
 * one the link contract answers; a result that names a link id is refused as
 * `link_mismatch` unless that answer is exactly that link, so a link removed
 * and made again for the same subject since the adapter redeemed the result
 * never takes its place.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExternalResult
{
    /** @var int Longest connection, tenant or link id, in characters. */
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
     * @param  ?string  $linkId
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

        /** The id of the link the adapter redeemed the result through, if it names one, compared exactly. */
        public ?string $linkId = null,
    ) {
        self::assertText($connectionId, self::ID_MAX_LENGTH, 'connection id');
        self::assertText($issuer, self::ISSUER_MAX_LENGTH, 'issuer');
        self::assertText($subject, self::SUBJECT_MAX_LENGTH, 'subject');
        self::assertText($tenantId, self::ID_MAX_LENGTH, 'tenant id');
        self::assertText($policyVersion, self::VERSION_MAX_LENGTH, 'policy version');
        self::assertText($linkId, self::ID_MAX_LENGTH, 'link id');

        $this->authenticatedAt = $authenticatedAt === null ? null : CarbonImmutable::instance($authenticatedAt)->startOfSecond();
        $this->sessionNotAfter = $sessionNotAfter === null ? null : CarbonImmutable::instance($sessionNotAfter)->startOfSecond();

        if ($evidence !== null && $this->authenticatedAt !== null && $evidence->authenticatedAt->greaterThan($this->authenticatedAt)) {
            throw new \InvalidArgumentException('An external result\'s evidence may not be dated after the provider authenticated the identity.');
        }
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
