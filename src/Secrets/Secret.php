<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Secrets;

use SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException;

/**
 * A secret the package hands out: an access or refresh token, a pending
 * credential, an API key, a one-time code, a reset token or a signed link.
 *
 * The plaintext is held in a private `\SensitiveParameterValue` and leaves only
 * through `reveal()`, called where the secret is to be sent. Nothing else gives
 * it up: casting the secret to a string, encoding it as JSON, serialising it
 * (into a queued job, a cache or a session, say) and unserialising one each
 * throw `SecretNotRevealedException`, so a secret is never sent, stored or
 * logged by accident, nor replaced by a placeholder a client would take for the
 * real value. PHP's `var_dump` and `print_r` and Symfony's VarDumper (behind
 * Laravel's `dump` and `dd` helpers) show `[redacted]`, and `var_export` an
 * empty `\SensitiveParameterValue`, so neither a dump nor an exception report
 * that records a frame's arguments shows the plaintext.
 *
 * `SecretResponse::json()` reveals every secret in a response body and marks
 * the response not to be stored.
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
     * The plaintext, to send where it belongs: a response body, a cookie, a
     * message to its recipient. Never log it.
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
