<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Firebase\JWT\Key;

/**
 * JWT key configuration value object.
 *
 * Built from a `kid -> secret` map plus an active kid (`fromKeyMap()`). Every
 * issued token carries the active kid in its header; verification accepts any
 * kid present in the map, which is what makes graceful key rotation possible. A
 * map with a single entry is the minimal configuration.
 *
 * Fails closed: empty maps, empty secrets, and unknown active kids raise
 * `InvalidJwtConfigurationException` at construction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class JwtKeyring
{
    /** @var array<int, string> Allow-listed JWT signing algorithms (HMAC only). */
    private const array SUPPORTED_ALGORITHMS = [
        'HS256',
        'HS384',
        'HS512',
    ];

    /**
     * Constructor.
     *
     * @param  array<string, \Firebase\JWT\Key>  $keys
     * @param  string  $activeKid
     */
    private function __construct(

        /** Map of `kid -> Firebase\JWT\Key` used for verification. */
        private array $keys,

        /** Kid stamped into every issued token. */
        private string $activeKid,
    ) {}

    /**
     * Construct a keyring with an active signing key and a verification map for
     * graceful rotation.
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
                . ' to a kid -> secret map of at least one entry.';

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
     * Return the kid embedded in newly issued tokens.
     *
     * @return string
     */
    public function activeKid(): string
    {
        return $this->activeKid;
    }

    /**
     * Return the `kid -> Key` verification map in the form `firebase/php-jwt`
     * expects.
     *
     * @return array<string, \Firebase\JWT\Key>
     */
    public function verificationKeys(): array
    {
        return $this->keys;
    }

    /**
     * Reject any signing algorithm not on the allow-list. Run first so weak or
     * typo'd settings fail fast at boot.
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
