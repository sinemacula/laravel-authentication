<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * A proof an adapter verified and hands to the session service to satisfy a
 * pending session or step a session up.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProofResult
{
    /** @var int Longest method name or factor reference, in characters: the columns' length. */
    public const int NAME_MAX_LENGTH = 255;

    /** @var list<string> The authentication method reference values the proof stands for. */
    public array $methods;

    /** @var \Carbon\CarbonImmutable When the proof was made, to the whole second. */
    public CarbonImmutable $authenticatedAt;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Proofs\Channel  $channel
     * @param  ?string  $factor
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @param  \SineMacula\Laravel\Authentication\Proofs\Evaluation  $evaluation
     * @param  array<array-key, mixed>  $methods
     * @param  \Carbon\CarbonInterface  $authenticatedAt
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** What kind of proof it is. */
        public ProofKind $kind,

        /** The method the adapter verified it with (for example `totp`). */
        public string $method,

        /** The channel it was made over. */
        public Channel $channel,

        /** The adapter's reference to the factor used, if any. */
        public ?string $factor,

        /** What was observed about the authenticator. */
        public ObservedProperties $observed,

        /** What the adapter reported about it. */
        public Evaluation $evaluation,

        // The authentication method reference values, `mfa` excluded.
        array $methods,

        // When the proof was made.
        CarbonInterface $authenticatedAt,

        /** What the proof was made for. */
        public ProofBinding $binding,
    ) {
        if ($method === '' || mb_strlen($method) > self::NAME_MAX_LENGTH || ($factor !== null && ($factor === '' || mb_strlen($factor) > self::NAME_MAX_LENGTH))) {
            throw new \InvalidArgumentException(sprintf('A proof\'s method, and its factor reference when it has one, must be from 1 to %d characters.', self::NAME_MAX_LENGTH));
        }

        $this->methods         = AuthenticationMethods::assertValid($methods);
        $this->authenticatedAt = CarbonImmutable::instance($authenticatedAt)->startOfSecond();
    }
}
