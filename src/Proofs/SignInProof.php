<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;

/**
 * What a sign-in proved before its session exists, carried through
 * establishment to the session's first proofs: the sign-in method, the first
 * factor's channel, observed properties, `amr` values and time, the provenance
 * of a session established through an external provider, and the further factor
 * a pending sign-in was completed with, if any.
 *
 * A pending sign-in keeps the first factor and the provenance (`toArray()`,
 * `provenanceToArray()`), so the session it becomes records the time the
 * credentials were verified, not the time it completed. The further factor is
 * never kept: it is given when the pending sign-in completes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInProof
{
    /** @var array<string, string> The observed flags, by their name on `ObservedProperties`, with the key a pending sign-in keeps each under. */
    private const array OBSERVED = [
        'userPresence'      => 'user_presence',
        'userVerification'  => 'user_verification',
        'backupEligible'    => 'backup_eligible',
        'backupState'       => 'backup_state',
        'phishingResistant' => 'phishing_resistant',
    ];

    /**
     * Constructor.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  list<string>  $methods
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\NewProof  $additional
     */
    private function __construct(

        /** The sign-in method that verified the first factor. */
        public string $method,

        /** The channel the first factor was proved over. */
        public Channel $channel,

        /** What was observed about the first factor's authenticator. */
        public ObservedProperties $observed,

        /** The first factor's authentication method reference values. */
        public array $methods,

        /** When the first factor was verified, to the whole second. */
        public CarbonImmutable $authenticatedAt,

        /** How a session established through an external provider began, if it was. */
        public ?Provenance $provenance = null,

        /** The further factor a pending sign-in was completed with, if any. */
        public ?NewProof $additional = null,
    ) {}

    /**
     * The proof of a first factor the named sign-in method verified at the
     * given time.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\FirstFactor  $factor
     * @param  \Carbon\CarbonImmutable  $at
     * @return self
     */
    public static function verified(string $method, FirstFactor $factor, CarbonImmutable $at): self
    {
        return new self($method, $factor->channel, $factor->observed, $factor->methods, $at->startOfSecond());
    }

    /**
     * The proof of a sign-in an external provider verified, under the named
     * method: the connection as its channel, the private external-provider
     * `amr` value, and the provider's authentication time, or now when it gave
     * none or one after now (the clocks disagree), with the provenance.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @param  \Carbon\CarbonImmutable  $now
     * @return self
     */
    public static function external(string $method, Provenance $provenance, CarbonImmutable $now): self
    {
        $now = $now->startOfSecond();
        $at  = $provenance->providerAuthenticatedAt;

        return new self(
            $method,
            new Channel(ChannelKind::EXTERNAL_PROVIDER, $provenance->connectionId),
            new ObservedProperties,
            [FirstFactor::EXTERNAL_PROVIDER_METHOD],
            $at === null || $at->greaterThan($now) ? $now : $at,
            $provenance,
        );
    }

    /**
     * The proof of a sign-in something outside the guard verified under the
     * named method and did not describe: an unknown channel, no `amr` values,
     * verified now.
     *
     * @param  string  $method
     * @param  \Carbon\CarbonImmutable  $now
     * @return self
     */
    public static function unattested(string $method, CarbonImmutable $now): self
    {
        return new self($method, new Channel(ChannelKind::UNKNOWN), new ObservedProperties, [], $now->startOfSecond());
    }

    /**
     * The first factor the pending sign-in kept, with the provenance it kept,
     * if any, under the method it records. A pending sign-in the package wrote
     * always keeps a readable one, so anything else is a `LogicException`.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @return self
     *
     * @throws \LogicException
     */
    public static function kept(PendingSignIn $pending): self
    {
        $factor     = $pending->first_factor;
        $provenance = $pending->provenance;

        try {
            return new self(
                $pending->sign_in_method,
                new Channel(ChannelKind::from(self::text($factor, 'channel_kind')), self::optionalText($factor, 'channel_reference')),
                self::observedFrom(self::field($factor, 'observed')),
                AuthenticationMethods::assertValid(self::listOf($factor, 'methods')),
                self::requiredTime($factor, 'authenticated_at'),
                $provenance === null ? null : self::provenanceFrom($provenance),
            );
        } catch (\InvalidArgumentException|\UnexpectedValueException|\ValueError $exception) {
            throw new \LogicException('A pending sign-in keeps a first factor or provenance the package cannot read.', 0, $exception);
        }
    }

    /**
     * The same proof, completed with the further factor given.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\NewProof  $additional
     * @return self
     */
    public function withAdditional(NewProof $additional): self
    {
        return new self($this->method, $this->channel, $this->observed, $this->methods, $this->authenticatedAt, $this->provenance, $additional);
    }

    /**
     * The first factor as the session records it.
     *
     * @return \SineMacula\Laravel\Authentication\Proofs\NewProof
     */
    public function firstFactor(): NewProof
    {
        return new NewProof(ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, $this->method, $this->channel, null, $this->observed, null, $this->methods, $this->authenticatedAt);
    }

    /**
     * The first factor as a pending sign-in keeps it.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $observed = $this->observed;

        return [
            'channel_kind'      => $this->channel->kind->value,
            'channel_reference' => $this->channel->reference,
            'observed'          => [
                'user_presence'      => $observed->userPresence,
                'user_verification'  => $observed->userVerification,
                'backup_eligible'    => $observed->backupEligible,
                'backup_state'       => $observed->backupState,
                'phishing_resistant' => $observed->phishingResistant,
                'key_protection'     => $observed->keyProtection?->value,
            ],
            'methods'          => $this->methods,
            'authenticated_at' => $this->authenticatedAt->getTimestamp(),
        ];
    }

    /**
     * The provenance as a pending sign-in keeps it, or `null` for none.
     *
     * @return ?array<string, mixed>
     */
    public function provenanceToArray(): ?array
    {
        $provenance = $this->provenance;

        return $provenance === null ? null : [
            'connection_id'             => $provenance->connectionId,
            'tenant_id'                 => $provenance->tenantId,
            'provider_authenticated_at' => $provenance->providerAuthenticatedAt?->getTimestamp(),
            'session_not_after'         => $provenance->sessionNotAfter?->getTimestamp(),
            'policy_version'            => $provenance->policyVersion,
        ];
    }

    /**
     * The observed properties a pending sign-in kept.
     *
     * @param  mixed  $observed
     * @return \SineMacula\Laravel\Authentication\Proofs\ObservedProperties
     *
     * @throws \UnexpectedValueException
     */
    private static function observedFrom(mixed $observed): ObservedProperties
    {
        $flags = [];

        foreach (self::OBSERVED as $name => $key) {

            $flag = self::field($observed, $key);

            $flags[$name] = is_bool($flag) || $flag === null ? $flag : throw new \UnexpectedValueException("{$key} is not a flag");
        }

        $protection = self::optionalText($observed, 'key_protection');

        return new ObservedProperties(...$flags, keyProtection: $protection === null ? null : KeyProtection::from($protection));
    }

    /**
     * The provenance a pending sign-in kept.
     *
     * @param  mixed  $provenance
     * @return \SineMacula\Laravel\Authentication\Proofs\Provenance
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function provenanceFrom(mixed $provenance): Provenance
    {
        return new Provenance(
            self::text($provenance, 'connection_id'),
            self::optionalText($provenance, 'tenant_id'),
            self::time($provenance, 'provider_authenticated_at'),
            self::time($provenance, 'session_not_after'),
            self::optionalText($provenance, 'policy_version'),
        );
    }

    /**
     * A field of a kept array, `null` when it has none.
     *
     * @param  mixed  $data
     * @param  string  $key
     * @return mixed
     *
     * @throws \UnexpectedValueException
     */
    private static function field(mixed $data, string $key): mixed
    {
        return is_array($data) ? $data[$key] ?? null : throw new \UnexpectedValueException('not an array');
    }

    /**
     * A string field of a kept array.
     *
     * @param  mixed  $data
     * @param  string  $key
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function text(mixed $data, string $key): string
    {
        return self::optionalText($data, $key) ?? throw new \UnexpectedValueException("{$key} is missing");
    }

    /**
     * A string field of a kept array that may be `null`.
     *
     * @param  mixed  $data
     * @param  string  $key
     * @return ?string
     *
     * @throws \UnexpectedValueException
     */
    private static function optionalText(mixed $data, string $key): ?string
    {
        $value = self::field($data, $key);

        return is_string($value) || $value === null ? $value : throw new \UnexpectedValueException("{$key} is not a string");
    }

    /**
     * A list field of a kept array.
     *
     * @param  mixed  $data
     * @param  string  $key
     * @return array<array-key, mixed>
     *
     * @throws \UnexpectedValueException
     */
    private static function listOf(mixed $data, string $key): array
    {
        $value = self::field($data, $key);

        return is_array($value) ? $value : throw new \UnexpectedValueException("{$key} is not a list");
    }

    /**
     * A time field of a kept array that must be there.
     *
     * @param  mixed  $data
     * @param  string  $key
     * @return \Carbon\CarbonImmutable
     *
     * @throws \UnexpectedValueException
     */
    private static function requiredTime(mixed $data, string $key): CarbonImmutable
    {
        return self::time($data, $key) ?? throw new \UnexpectedValueException("{$key} is missing");
    }

    /**
     * A time field of a kept array, kept as a Unix timestamp, or `null`.
     *
     * @param  mixed  $data
     * @param  string  $key
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \UnexpectedValueException
     */
    private static function time(mixed $data, string $key): ?CarbonImmutable
    {
        $value = self::field($data, $key);

        return match (true) {
            $value === null => null,
            is_int($value)  => CarbonImmutable::createFromTimestamp($value, date_default_timezone_get()),
            default         => throw new \UnexpectedValueException("{$key} is not a time"),
        };
    }
}
