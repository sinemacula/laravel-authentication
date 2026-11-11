<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Illuminate\Contracts\Config\Repository;

/**
 * The keyed digests behind one-time codes, each an HMAC-SHA256 under its own
 * key derived from `authentication.codes.key` or `app.key`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeKeys
{
    /** @var int Fewest bytes a configured key may have. */
    public const int MIN_KEY_BYTES = 32;

    /** @var string What the binding key is derived for, so it is used for nothing else. */
    private const string BINDING_PURPOSE = 'sinemacula/laravel-authentication one-time code bindings';

    /** @var string What the transaction key is derived for, so it is used for nothing else. */
    private const string CONTEXT_PURPOSE = 'sinemacula/laravel-authentication one-time code contexts';

    /** @var string What the code key is derived for, so it is used for nothing else. */
    private const string CODE_PURPOSE = 'sinemacula/laravel-authentication one-time code hashes';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the key is read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The digest of the binding, as 64 hexadecimal characters: the key of the
     * binding's one live code.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function binding(CodeBinding $binding): string
    {
        $parts = ['binding', $binding->purpose->value, $binding->guard, $binding->type, $binding->identifier, $binding->identity];

        return hash_hmac('sha256', implode("\0", $parts), $this->derive(self::BINDING_PURPOSE));
    }

    /**
     * The digest of the transaction the binding names besides its key, as 64
     * hexadecimal characters, or `null` for a binding that names none.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function context(CodeBinding $binding): ?string
    {
        if ($binding->transaction === '') {
            return null;
        }

        return hash_hmac('sha256', implode("\0", ['context', $binding->purpose->value, $binding->transaction]), $this->derive(self::CONTEXT_PURPOSE));
    }

    /**
     * The hash of a code issued for the binding digest in the issuance, as 64
     * hexadecimal characters.
     *
     * @param  string  $binding
     * @param  string  $issueId
     * @param  string  $code
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function code(string $binding, string $issueId, #[\SensitiveParameter] string $code): string
    {
        return hash_hmac('sha256', implode("\0", ['code', $binding, $issueId, $code]), $this->derive(self::CODE_PURPOSE));
    }

    /**
     * Read the key, failing closed when it is malformed; `authentication:check`
     * runs it.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->secret();
    }

    /**
     * The key derived from the secret for the purpose.
     *
     * @param  string  $purpose
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function derive(string $purpose): string
    {
        return hash_hmac('sha256', $purpose, $this->secret(), true);
    }

    /**
     * The secret the keys are derived from: `authentication.codes.key` when it
     * is set (at least 32 bytes), otherwise the application key.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function secret(): string
    {
        $key = $this->config->get('authentication.codes.key');

        if ($key === null || $key === '') {
            return $this->applicationKey();
        }

        if (!is_string($key) || strlen($key) < self::MIN_KEY_BYTES) {
            $message = sprintf('authentication.codes.key must be a string of at least %d bytes, or null to derive the key from `app.key`.', self::MIN_KEY_BYTES);

            throw new \InvalidArgumentException($message);
        }

        return $key;
    }

    /**
     * The application key, which must be set when no codes key is.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function applicationKey(): string
    {
        $key = $this->config->get('app.key');

        if (!is_string($key) || $key === '') {
            throw new \InvalidArgumentException('One-time codes are keyed with `authentication.codes.key`, or the application key when it is not set; set either.');
        }

        return $key;
    }
}
