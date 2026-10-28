<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Illuminate\Contracts\Config\Repository;

/**
 * The WebAuthn relying party a guard's passkeys belong to: its id, which every
 * credential registered through the guard is scoped to, the name a browser
 * shows, and the exact origins its ceremonies may run on.
 *
 * Read from the guard's `passkeys` block on its `config/auth.php` entry over
 * the package's `authentication.passkeys.relying_party`, where a key present in
 * the guard's block wins. The id must be a lower-case host name, not an IP
 * address; the name a non-empty string (by default `app.name`); and each origin
 * `https://host[:port]`, or `http://localhost[:port]` for development, in lower
 * case, whose host is the id or a subdomain of it, as WebAuthn requires of an
 * origin its relying party id is scoped to. Whether the id is a public suffix
 * is not checked: the package does not carry the public suffix list, so an
 * application must not name one. Anything else, or an unknown key, fails closed
 * with an `InvalidArgumentException` naming the guard and the key. Nothing is
 * cached, so a change to the configuration applies at once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RelyingParty
{
    /** @var list<string> Keys a relying party block may hold. */
    private const array KEYS = ['id', 'name', 'origins'];

    /** @var string Pattern of a lower-case host name: dot-separated labels of letters, digits and inner hyphens. */
    private const string HOST_PATTERN = '/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/D';

    /** @var string Pattern of an origin: a scheme, a host and an optional port, nothing else. */
    private const string ORIGIN_PATTERN = '/^(https?):\/\/([^:\/?#]+)(?::([1-9][0-9]{0,4}))?$/D';

    /** @var string Host name a plain `http` origin may name, for development. */
    private const string LOCALHOST = 'localhost';

    /** @var int Highest port number. */
    private const int MAX_PORT = 65535;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  string  $id
     * @param  string  $name
     * @param  non-empty-list<string>  $origins
     */
    private function __construct(

        /** Guard whose relying party it is. */
        public string $guard,

        /** The relying party id, a lower-case host name. */
        public string $id,

        /** The name a browser shows for the relying party. */
        public string $name,

        /** The exact origins the ceremonies may run on. */
        public array $origins,
    ) {}

    /**
     * The guard's relying party, read and validated from the configuration.
     *
     * @param  string  $guard
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function forGuard(string $guard, Repository $config): self
    {
        $guardConfig = $config->get("auth.guards.{$guard}");

        if (!is_array($guardConfig)) {
            throw new \InvalidArgumentException("Auth guard [{$guard}] is not configured.");
        }

        $settings = self::block($guard, $guardConfig['passkeys'] ?? [], 'the guard\'s `passkeys` overrides')
            + self::block($guard, $config->get('authentication.passkeys.relying_party'), '`authentication.passkeys.relying_party`');

        $id = $settings['id'] ?? null;

        if (!is_string($id) || preg_match(self::HOST_PATTERN, $id) !== 1 || filter_var($id, FILTER_VALIDATE_IP) !== false) {
            throw new \InvalidArgumentException(self::message($guard, 'id', 'a lower-case host name, not an IP address'));
        }

        $name = $settings['name'] ?? $config->get('app.name');

        if (!is_string($name) || trim($name) === '') {
            throw new \InvalidArgumentException(self::message($guard, 'name', 'a non-empty string (or `app.name` set)'));
        }

        return new self($guard, $id, $name, self::origins($guard, $id, $settings['origins'] ?? null));
    }

    /**
     * Validate the origins: a non-empty list of exact origins on the relying
     * party id or its subdomains.
     *
     * @param  string  $guard
     * @param  string  $id
     * @param  mixed  $origins
     * @return non-empty-list<string>
     *
     * @throws \InvalidArgumentException
     */
    private static function origins(string $guard, string $id, mixed $origins): array
    {
        $expected = 'a non-empty list of exact lower-case origins, each `https://host[:port]` (or `http://localhost[:port]`) on the relying party id or a subdomain of it';

        if (!is_array($origins) || $origins === [] || !array_is_list($origins)) {
            throw new \InvalidArgumentException(self::message($guard, 'origins', $expected));
        }

        foreach ($origins as $origin) {
            if (!is_string($origin) || !self::isOrigin($origin, $id)) {
                throw new \InvalidArgumentException(self::message($guard, 'origins', $expected));
            }
        }

        return $origins;
    }

    /**
     * Whether the value is an exact lower-case origin whose host is the relying
     * party id or a subdomain of it, served over `https`, or over `http` on
     * `localhost`.
     *
     * @param  string  $origin
     * @param  string  $id
     * @return bool
     */
    private static function isOrigin(string $origin, string $id): bool
    {
        if (preg_match(self::ORIGIN_PATTERN, $origin, $parts) !== 1 || preg_match(self::HOST_PATTERN, $parts[2]) !== 1) {
            return false;
        }

        [, $scheme, $host] = $parts;

        $secure = $scheme === 'https' || $host === self::LOCALHOST;

        return $secure && self::isScopedTo($host, $id) && (int) ($parts[3] ?? self::MAX_PORT) <= self::MAX_PORT;
    }

    /**
     * Whether the host is the relying party id or a subdomain of it.
     *
     * @param  string  $host
     * @param  string  $id
     * @return bool
     */
    private static function isScopedTo(string $host, string $id): bool
    {
        return $host === $id || str_ends_with($host, '.' . $id);
    }

    /**
     * Validate a relying party block: an array whose keys are known.
     *
     * @param  string  $guard
     * @param  mixed  $block
     * @param  string  $name
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function block(string $guard, mixed $block, string $name): array
    {
        if (!is_array($block)) {
            throw new \InvalidArgumentException("Passkey configuration for guard [{$guard}]: {$name} must be an array.");
        }

        foreach (array_keys($block) as $key) {
            if (!in_array($key, self::KEYS, true)) {
                throw new \InvalidArgumentException("Passkey configuration for guard [{$guard}]: {$name} has an unknown key `{$key}`.");
            }
        }

        return $block;
    }

    /**
     * Build the message for a relying party key that is missing or malformed.
     *
     * @param  string  $guard
     * @param  string  $key
     * @param  string  $expected
     * @return string
     */
    private static function message(string $guard, string $key, string $expected): string
    {
        return "Passkey relying party `{$key}` for guard [{$guard}] must be {$expected}:"
            . " set `authentication.passkeys.relying_party.{$key}` or the guard's `passkeys.{$key}` override.";
    }
}
