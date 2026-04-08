<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Firebase\JWT\Key;

/**
 * JWT key configuration value object.
 *
 * Encapsulates the signing material the `JwtTokenService` uses to
 * issue and verify tokens. Two construction modes are supported:
 *
 * - **Single-secret mode** (`fromSecret()`): one shared secret signs
 *   and verifies every token. Tokens are issued without a `kid`
 *   header. This is the legacy / development default.
 * - **Kid mode** (`fromKeyMap()`): a map of `kid → secret` is
 *   supplied along with an active kid. Tokens are signed with the
 *   active key and carry its kid in the JWT header. Verification
 *   accepts any token whose kid is present in the map. This is the
 *   production rotation pattern — the operator adds a new key under
 *   a new kid, points `active_kid` at it, and only retires the old
 *   kid once every live token signed under it has expired.
 *
 * The keyring fails closed: empty secrets and unknown active kids
 * raise `InvalidJwtConfigurationException` at construction time so
 * the package never silently issues or accepts forged tokens.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class JwtKeyring
{
    /** @var string Sentinel kid used by single-secret mode (never embedded in headers). */
    private const string LEGACY_KID = '__legacy__';

    /** @var array<int, string> Allow-listed JWT signing algorithms; anything outside is rejected at boot. */
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

        /**
         * Verification map keyed by kid. In legacy mode the only
         * entry uses the sentinel kid.
         */
        private readonly array $keys,

        /** Kid of the key currently used to sign new tokens. */
        private readonly string $activeKid,

        /**
         * Whether tokens should embed and require a `kid` header
         * (true) or remain headerless (false).
         */
        private readonly bool $kidMode,

    ) {}

    /**
     * Construct a single-secret keyring (legacy mode — no kid header).
     *
     * Tokens issued via this keyring carry no `kid` header and are
     * verified against the same single secret. Suitable for
     * development and small deployments where graceful key rotation
     * is not yet required.
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
                . ' (env `AUTHENTICATION_JWT_SECRET`) to a strong random value —'
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
     * verification map covering current and previous keys for
     * graceful rotation.
     *
     * Operators add a new key under a new kid, point `$activeKid` at
     * it, and retire the old kid once every live token signed under
     * it has expired.
     *
     * The `$keys` parameter is declared as `array<array-key, mixed>`
     * (rather than the narrower `array<string, string>` the runtime
     * guard ultimately enforces) because this factory is the
     * fail-closed boundary at which null secrets, integer-indexed
     * arrays, and non-string values are rejected with typed
     * exceptions. Narrowing the signature would push the validation
     * into the PHPStan-only realm and let misconfigurations reach
     * `firebase/php-jwt` as opaque runtime errors.
     *
     * @param  array<array-key, mixed>  $keys
     * @param  string  $activeKid
     * @param  string  $algorithm
     * @return self
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    public static function fromKeyMap(
        #[\SensitiveParameter] array $keys,
        string $activeKid,
        string $algorithm,
    ): self {
        self::assertAlgorithmSupported($algorithm);

        if ($keys === []) {

            $message = 'JWT key map is empty. Set `authentication.jwt.keys`'
                . ' to a kid → secret map of at least one entry, or remove the keys'
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
     * Return the active signing key — the `Key` instance used to
     * encode newly issued tokens.
     *
     * @return \Firebase\JWT\Key
     */
    public function activeKey(): Key
    {
        return $this->keys[$this->activeKid];
    }

    /**
     * Return the kid embedded in newly issued tokens, or `null` when
     * the keyring is in single-secret mode and tokens carry no `kid`
     * header.
     *
     * @return ?string
     */
    public function activeKid(): ?string
    {
        return $this->kidMode ? $this->activeKid : null;
    }

    /**
     * Return the verification key set in the form `firebase/php-jwt`
     * expects: a single `Key` in legacy single-secret mode (so a
     * tokeen with no `kid` header decodes cleanly), or a `kid → Key`
     * map in kid mode (so php-jwt picks the right key from the
     * token's `kid` header).
     *
     * @return array<string, \Firebase\JWT\Key>|\Firebase\JWT\Key
     */
    public function verificationKeys(): array|Key
    {
        return $this->kidMode ? $this->keys : $this->keys[self::LEGACY_KID];
    }

    /**
     * Validate every entry in the supplied kid → secret map and
     * convert it into a kid → Key map suitable for storage on the
     * keyring. Each kid must be a non-empty string and each secret
     * must be a non-empty string — both conditions are enforced
     * fail-closed at runtime regardless of the static-analysis hint
     * supplied by the caller (e.g. an `env()` lookup that returned
     * `null` because the variable was unset).
     *
     * @param  array<string, mixed>  $keys
     * @param  string  $algorithm
     * @return array<string, \Firebase\JWT\Key>
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    private static function buildKeyMap(
        #[\SensitiveParameter] array $keys,
        string $algorithm,
    ): array {
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

    /**
     * Reject any signing algorithm that is not in the allow-list. Run
     * before any other validation in both factories so a typo or a
     * deliberately weak setting fails fast at boot rather than at the
     * first encode/decode call deep inside `firebase/php-jwt`.
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
}
