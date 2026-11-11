<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Secrets;

use SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException;

/**
 * A secret the package hands out, whose plaintext leaves only through
 * `reveal()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Secret implements \JsonSerializable, \Stringable
{
    /** @var string What a dump of a secret shows in place of the plaintext. */
    public const string REDACTED = '[redacted]';

    /** @var \SensitiveParameterValue<string> The plaintext. */
    private \SensitiveParameterValue $value;

    /**
     * Constructor.
     *
     * @param  string  $value
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(#[\SensitiveParameter] string $value)
    {
        if ($value === '') {
            throw new \InvalidArgumentException('A secret cannot be empty.');
        }

        $this->value = new \SensitiveParameterValue($value);
    }

    /**
     * Refuse to give the plaintext up as a string.
     *
     * @return string
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException
     */
    #[\Override]
    public function __toString(): string
    {
        throw SecretNotRevealedException::for('cast to a string');
    }

    /**
     * Refuse to be serialised.
     *
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException
     */
    public function __serialize(): array
    {
        throw SecretNotRevealedException::for('serialised');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<array-key, mixed>  $data
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException
     */
    public function __unserialize(array $data): void
    {
        throw SecretNotRevealedException::for('unserialised');
    }

    /**
     * What a dump shows: the placeholder, never the plaintext.
     *
     * @return array{secret: string}
     */
    public function __debugInfo(): array
    {
        return ['secret' => self::REDACTED];
    }

    /**
     * The plaintext, to send where it belongs. Never log it.
     *
     * @return string
     */
    public function reveal(): string
    {
        return $this->value->getValue();
    }

    /**
     * Refuse to be encoded as JSON.
     *
     * @return mixed
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException
     */
    #[\Override]
    public function jsonSerialize(): mixed
    {
        throw SecretNotRevealedException::for('encoded as JSON');
    }
}
