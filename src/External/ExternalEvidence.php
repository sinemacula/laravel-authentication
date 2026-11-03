<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

/**
 * The evidence an external identity provider asserted about how it
 * authenticated the identity: its authentication method references (`amr`), its
 * authentication context (an `acr` value or a SAML authentication context class
 * reference) and the time the evidence is for.
 *
 * Given by a trusted server-side caller with the provider's result, never built
 * from what a client sent. It counts for nothing on its own: only once the
 * bound `Contracts\ExternalEvidencePolicy` says it meets a requirement is it
 * accepted, and only accepted evidence is recorded. The time is kept to the
 * whole second.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExternalEvidence
{
    /** @var int Most method references the evidence carries. */
    public const int MAX_METHODS = 32;

    /** @var int Longest method reference, in characters. */
    public const int METHOD_MAX_LENGTH = 255;

    /** @var int Longest authentication context, in characters. */
    public const int CONTEXT_MAX_LENGTH = 1024;

    /** @var \Carbon\CarbonImmutable The time the evidence is for, to the whole second. */
    public CarbonImmutable $authenticatedAt;

    /**
     * Constructor.
     *
     * @param  list<string>  $methods
     * @param  ?string  $context
     * @param  \Carbon\CarbonInterface  $authenticatedAt
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The provider's authentication method references (`amr`), in the order it gave them. */
        public array $methods,

        /** The provider's authentication context (`acr`, or a SAML authentication context class reference), if it gave one. */
        public ?string $context,

        // When the provider authenticated the identity.
        CarbonInterface $authenticatedAt,
    ) {
        self::assertMethods($methods);

        if ($context !== null && ($context === '' || mb_strlen($context) > self::CONTEXT_MAX_LENGTH)) {
            throw new \InvalidArgumentException(sprintf('An external provider\'s authentication context, when given, must be from 1 to %d characters.', self::CONTEXT_MAX_LENGTH));
        }

        $this->authenticatedAt = CarbonImmutable::instance($authenticatedAt)->startOfSecond();
    }

    /**
     * The evidence as it is stored: its method references, its context, and its
     * time in UTC as ISO 8601.
     *
     * @return array{methods: list<string>, context: ?string, authenticated_at: string}
     */
    public function toArray(): array
    {
        return [
            'methods'          => $this->methods,
            'context'          => $this->context,
            'authenticated_at' => $this->authenticatedAt->utc()->toIso8601String(),
        ];
    }

    /**
     * The evidence a stored value holds, or `null` when it holds none or is
     * malformed, which is never read as evidence.
     *
     * @internal
     *
     * @param  mixed  $value
     * @return ?self
     */
    public static function fromStored(mixed $value): ?self
    {
        $methods = is_array($value) ? $value['methods']          ?? null : null;
        $context = is_array($value) ? $value['context']          ?? null : null;
        $time    = is_array($value) ? $value['authenticated_at'] ?? null : null;

        if (!is_array($methods) || !is_string($time) || ($context !== null && !is_string($context))) {
            return null;
        }

        try {
            return new self($methods, $context, CarbonImmutable::parse($time));
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Refuse method references that are not a list of at most `MAX_METHODS`
     * strings of 1 to `METHOD_MAX_LENGTH` characters.
     *
     * @param  array<array-key, mixed>  $methods
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertMethods(array $methods): void
    {
        if (!array_is_list($methods) || count($methods) > self::MAX_METHODS) {
            throw new \InvalidArgumentException(sprintf('An external provider\'s method references must be a list of at most %d.', self::MAX_METHODS));
        }

        foreach ($methods as $method) {
            if (!is_string($method) || $method === '' || mb_strlen($method) > self::METHOD_MAX_LENGTH) {
                throw new \InvalidArgumentException(sprintf('An external provider\'s method reference must be from 1 to %d characters.', self::METHOD_MAX_LENGTH));
            }
        }
    }
}
