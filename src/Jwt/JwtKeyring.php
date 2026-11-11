<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Firebase\JWT\Key;

/**
 * The JWT signing keys: the active kid signs, and any kid in the map verifies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class JwtKeyring
{
    /** @var array<string, int> Allow-listed JWT signing algorithms (HMAC only), mapped to their minimum key length in bytes. */
    private const array SUPPORTED_ALGORITHMS = [
        'HS256' => 32,
        'HS384' => 48,
        'HS512' => 64,
    ];

    /**
     * Constructor.
     *
     * @param  array<array-key, \Firebase\JWT\Key>  $keys
     * @param  string  $activeKid
     */
    private function __construct(

        /** Map of `kid -> Firebase\JWT\Key` used for verification. */
        private array $keys,

        /** Kid stamped into every issued token. */
        private string $activeKid,
    ) {}

    /**
     * Build a keyring from a `kid -> secret` map and its active kid.
     *
     * A numeric kid such as `'2026'` arrives as an integer key (PHP casts
     * numeric string keys) and is matched by its string form.
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
     * @return array<array-key, \Firebase\JWT\Key>
     */
    public function verificationKeys(): array
    {
        return $this->keys;
    }

    /**
     * Reject any signing algorithm not on the allow-list.
     *
     * @param  string  $algorithm
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private static function assertAlgorithmSupported(string $algorithm): void
    {
        if (array_key_exists($algorithm, self::SUPPORTED_ALGORITHMS)) {
            return;
        }

        $message = "JWT algorithm '{$algorithm}' is not supported."
            . ' Set `authentication.jwt.algorithm` to one of: '
            . implode(', ', array_keys(self::SUPPORTED_ALGORITHMS)) . '.';

        throw new InvalidJwtConfigurationException($message);
    }

    /**
     * Validate the `kid -> secret` map and convert it into a `kid -> Key` map.
     *
     * @param  array<array-key, mixed>  $keys
     * @param  string  $algorithm
     * @return array<array-key, \Firebase\JWT\Key>
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

            self::assertKeyLength($kid, $material, $algorithm);

            $built[$kid] = new Key($material, $algorithm);
        }

        return $built;
    }

    /**
     * Reject secret material shorter than the algorithm's digest size.
     *
     * @param  int|string  $kid
     * @param  string  $material
     * @param  string  $algorithm
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private static function assertKeyLength(int|string $kid, #[\SensitiveParameter] string $material, string $algorithm): void
    {
        $minimumBytes = self::SUPPORTED_ALGORITHMS[$algorithm];

        if (strlen($material) >= $minimumBytes) {
            return;
        }

        $message = "JWT key '{$kid}' is too short for {$algorithm}: it must be at"
            . " least {$minimumBytes} bytes. Set every kid in"
            . " `authentication.jwt.keys` to a random value of at least {$minimumBytes} bytes.";

        throw new InvalidJwtConfigurationException($message);
    }
}
