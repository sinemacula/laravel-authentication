<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Firebase\JWT\Key;

/**
 * JWT key configuration value object.
 *
 * Two construction modes:
 *
 * - **Single-secret mode** (`fromSecret()`): one secret signs and verifies
 *   every token, no `kid` header.
 * - **Kid mode** (`fromKeyMap()`): a `kid -> secret` map plus an active kid.
 *   Tokens carry the active kid in the header; verification accepts any kid
 *   present in the map. This is the production rotation pattern.
 *
 * Fails closed: empty secrets and unknown active kids raise
 * `InvalidJwtConfigurationException` at construction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtKeyring
{
    /** @var string Sentinel kid for single-secret mode (never in headers). */
    private const string LEGACY_KID = '__legacy__';

    /** @var array<int, string> Allow-listed JWT signing algorithms. */
    private const array SUPPORTED_ALGORITHMS = [
        'HS256',
        'HS384',
        'HS512',
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
    ];

    /**
     * Constructor.
     *
     * @param  array<string, \Firebase\JWT\Key>  $keys
     * @param  string  $activeKid
     * @param  bool  $kidMode
     */
    private function __construct(

        /** Map of `kid -> Firebase\JWT\Key` used for verification. */
        private readonly array $keys,

        /** Kid stamped into every issued token; empty string when kid mode is off. */
        private readonly string $activeKid,

        /** Whether the keyring operates in kid mode (true) or legacy single-secret mode (false). */
        private readonly bool $kidMode,

    ) {}

    /**
     * Construct a single-secret keyring (no kid header).
     *
     * @param  string  $secret
     * @param  string  $algorithm
     * @return self
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    public static function fromSecret(#[\SensitiveParameter] string $secret, string $algorithm): self
    {
        self::assertAlgorithmSupported($algorithm);

        if ($secret === '') {

            $message = 'JWT secret is empty. Set `authentication.jwt.secret`'
                . ' (env `AUTHENTICATION_JWT_SECRET`) to a strong random value -'
                . ' an empty secret would silently accept forged tokens.';

            throw new InvalidJwtConfigurationException($message);
        }

        return new self(
            [self::LEGACY_KID => new Key($secret, $algorithm)],
            self::LEGACY_KID,
            false,
        );
    }

    /**
     * Construct a kid-aware keyring with an active signing key and a
     * verification map for graceful rotation.
     *
     * Typed `array<array-key, mixed>` because this factory is the fail-closed
     * boundary at which null secrets, integer-indexed arrays, and non-string
     * values are rejected with typed exceptions.
     *
     * @param  array<array-key, mixed>  $keys
     * @param  string  $activeKid
     * @param  string  $algorithm
     * @return self
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    public static function fromKeyMap(#[\SensitiveParameter] array $keys, string $activeKid, string $algorithm): self
    {
        self::assertAlgorithmSupported($algorithm);

        if ($keys === []) {

            $message = 'JWT key map is empty. Set `authentication.jwt.keys`'
                . ' to a kid -> secret map of at least one entry, or remove the keys'
                . ' block entirely to fall back to single-secret mode.';

            throw new InvalidJwtConfigurationException($message);
        }

        if ($activeKid === '' || !array_key_exists($activeKid, $keys)) {

            $message = "JWT active kid '{$activeKid}' is not present in the configured key map."
                . ' Set `authentication.jwt.active_kid` to a kid that exists'
                . ' in `authentication.jwt.keys`.';

            throw new InvalidJwtConfigurationException($message);
        }

        return new self(
            self::buildKeyMap($keys, $algorithm),
            $activeKid,
            true,
        );
    }

    /**
     * Return the active signing key.
     *
     * @return \Firebase\JWT\Key
     */
    public function activeKey(): Key
    {
        return $this->keys[$this->activeKid];
    }

    /**
     * Return the kid embedded in newly issued tokens, or `null` in
     * single-secret mode.
     *
     * @return ?string
     */
    public function activeKid(): ?string
    {
        return $this->kidMode ? $this->activeKid : null;
    }

    /**
     * Return the verification key set in the form `firebase/php-jwt` expects:
     * a single `Key` in single-secret mode, or a `kid -> Key` map in kid mode.
     *
     * @return array<string, \Firebase\JWT\Key>|\Firebase\JWT\Key
     */
    public function verificationKeys(): array|Key
    {
        return $this->kidMode ? $this->keys : $this->keys[self::LEGACY_KID];
    }

    /**
     * Reject any signing algorithm not on the allow-list. Run first in both
     * factories so weak or typo'd settings fail fast at boot.
     *
     * @param  string  $algorithm
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private static function assertAlgorithmSupported(string $algorithm): void
    {
        if (in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
            return;
        }

        $message = "JWT algorithm '{$algorithm}' is not supported."
            . ' Set `authentication.jwt.algorithm` to one of: '
            . implode(', ', self::SUPPORTED_ALGORITHMS) . '.';

        throw new InvalidJwtConfigurationException($message);
    }

    /**
     * Validate the supplied kid -> secret map and convert it into a kid -> Key
     * map. Both kid and secret must be non-empty strings; fail-closed
     * regardless of the caller's static type hint.
     *
     * @param  array<string, mixed>  $keys
     * @param  string  $algorithm
     * @return array<string, \Firebase\JWT\Key>
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private static function buildKeyMap(#[\SensitiveParameter] array $keys, string $algorithm): array
    {
        $built = [];

        foreach ($keys as $kid => $material) {

            if ($kid === '') {

                $message = 'JWT key map contains an empty kid. Every entry under'
                    . ' `authentication.jwt.keys` must be keyed by a'
                    . ' non-empty string.';

                throw new InvalidJwtConfigurationException($message);
            }

            if (!is_string($material) || $material === '') {

                $message = "JWT key '{$kid}' has empty material. Every kid in"
                    . ' `authentication.jwt.keys` must map to a non-empty secret.';

                throw new InvalidJwtConfigurationException($message);
            }

            $built[$kid] = new Key($material, $algorithm);
        }

        return $built;
    }
}
