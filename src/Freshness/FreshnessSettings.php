<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Freshness;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * The freshness each operation requires, from `authentication.freshness` and a
 * guard's own `freshness` block on its `config/auth.php` entry, read on every
 * call.
 *
 * Each block maps operation names to an entry: `max_age_seconds` (an integer,
 * or the digit string `env()` returns for one, from 1 to 86400), `proofs` (a
 * list of proof kinds by value) and, optionally, `multifactor` and
 * `phishing_resistant` (booleans, `false` by default). A guard's block replaces
 * the package's entry for every operation it names, and `null` there removes
 * the operation, so it is never fresh without a caller's own requirement.
 * Operation names are the blocks' keys, read whole, never through a dotted
 * path, so `mfa.add_factor` is one name. A block that is not a map, a name that
 * is not an operation's, and a malformed entry fail closed with an
 * `InvalidArgumentException` naming the block and the operation;
 * `authentication:check` reports them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FreshnessSettings
{
    /** @var string Configuration key of the package's freshness block. */
    private const string PACKAGE_KEY = 'authentication.freshness';

    /** @var string What an operation's name is: dot-separated lower-case segments, each starting with a letter. */
    private const string OPERATION_PATTERN = '/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/';

    /** @var list<string> The keys an entry may set. */
    private const array ENTRY_KEYS = ['max_age_seconds', 'proofs', 'multifactor', 'phishing_resistant'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the blocks are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * Whether the name is an operation's.
     *
     * @param  string  $operation
     * @return bool
     */
    public static function isOperation(string $operation): bool
    {
        return preg_match(self::OPERATION_PATTERN, $operation) === 1;
    }

    /**
     * The freshness the operation requires on the guard: the guard's own entry
     * when its block names the operation (`null` when that removes it), else
     * the package's, else `null`; `null` for a name that is not an operation's.
     *
     * @param  string  $guard
     * @param  string  $operation
     * @return ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     *
     * @throws \InvalidArgumentException
     */
    public function requirement(string $guard, string $operation): ?FreshnessRequirement
    {
        if (!self::isOperation($operation)) {
            return null;
        }

        $own = $this->guardBlock($guard);

        if ($own !== null && array_key_exists($operation, $own)) {
            return self::entry($own[$operation], self::guardKey($guard), $operation);
        }

        $package = $this->block($this->config->get(self::PACKAGE_KEY, []), self::PACKAGE_KEY);

        return array_key_exists($operation, $package) ? self::entry($package[$operation], self::PACKAGE_KEY, $operation) : null;
    }

    /**
     * Read the package's block, or the guard's when one is named, failing
     * closed on the first malformed name or entry; `authentication:check` runs
     * it.
     *
     * @param  ?string  $guard
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(?string $guard = null): void
    {
        $key   = $guard === null ? self::PACKAGE_KEY : self::guardKey($guard);
        $block = $guard === null ? $this->block($this->config->get(self::PACKAGE_KEY, []), self::PACKAGE_KEY) : ($this->guardBlock($guard) ?? []);

        foreach ($block as $operation => $entry) {
            self::entry($entry, $key, $operation);
        }
    }

    /**
     * The guard's own block, or `null` when it sets none.
     *
     * @param  string  $guard
     * @return ?array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function guardBlock(string $guard): ?array
    {
        $config = $this->config->get("auth.guards.{$guard}");
        $block  = is_array($config) ? $config['freshness'] ?? null : null;

        return $block === null ? null : $this->block($block, self::guardKey($guard));
    }

    /**
     * The block, once it is known to be a map whose every key is an operation's
     * name.
     *
     * @param  mixed  $block
     * @param  string  $key
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function block(mixed $block, string $key): array
    {
        if (!is_array($block)) {
            throw new \InvalidArgumentException(sprintf('%s must map operation names to their freshness.', $key));
        }

        foreach (array_keys($block) as $operation) {
            if (!is_string($operation) || !self::isOperation($operation)) {
                throw new \InvalidArgumentException(sprintf('%s names [%s], which is not an operation (dot-separated lower-case segments).', $key, $operation));
            }
        }

        /** @var array<string, mixed> $block */
        return $block;
    }

    /**
     * The requirement an entry describes, or `null` for an entry that removes
     * the operation.
     *
     * @param  mixed  $entry
     * @param  string  $key
     * @param  string  $operation
     * @return ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     *
     * @throws \InvalidArgumentException
     */
    private static function entry(mixed $entry, string $key, string $operation): ?FreshnessRequirement
    {
        if ($entry === null) {
            return null;
        }

        $setting = "{$key}.{$operation}";

        if (!is_array($entry) || array_diff(array_keys($entry), self::ENTRY_KEYS) !== [] || !array_key_exists('proofs', $entry)) {
            throw new \InvalidArgumentException(sprintf('%s must set `max_age_seconds` and `proofs`, and may set `multifactor` and `phishing_resistant`, or be null.', $setting));
        }

        return new FreshnessRequirement(
            IntegerSetting::from($setting . '.max_age_seconds', $entry['max_age_seconds'] ?? null, 1, FreshnessRequirement::MAX_AGE_SECONDS),
            self::kinds($entry['proofs'], $setting),
            self::isRequired($entry, 'multifactor', $setting),
            self::isRequired($entry, 'phishing_resistant', $setting),
        );
    }

    /**
     * The proof kinds an entry lists, once each names a kind and none twice.
     *
     * @param  mixed  $proofs
     * @param  string  $setting
     * @return list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>
     *
     * @throws \InvalidArgumentException
     */
    private static function kinds(mixed $proofs, string $setting): array
    {
        $listed = is_array($proofs) && array_is_list($proofs) ? $proofs : [];
        $kinds  = array_map(self::kind(...), $listed);

        if ($kinds === [] || in_array(null, $kinds, true) || count(array_unique(array_column($kinds, 'value'))) !== count($kinds)) {
            $names = implode('`, `', array_column(ProofKind::cases(), 'value'));

            throw new \InvalidArgumentException(sprintf('%s.proofs must list distinct proof kinds, at least one, from `%s`.', $setting, $names));
        }

        /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind> $kinds */
        return $kinds;
    }

    /**
     * The proof kind a listed value names, or `null` for one that names none.
     *
     * @param  mixed  $kind
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind
     */
    private static function kind(mixed $kind): ?ProofKind
    {
        return is_string($kind) ? ProofKind::tryFrom($kind) : null;
    }

    /**
     * Whether the entry requires the flag: `false` when it does not set it.
     *
     * @param  array<array-key, mixed>  $entry
     * @param  string  $flag
     * @param  string  $setting
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function isRequired(array $entry, string $flag, string $setting): bool
    {
        $value = $entry[$flag] ?? false;

        return is_bool($value) ? $value : throw new \InvalidArgumentException(sprintf('%s.%s must be true or false.', $setting, $flag));
    }

    /**
     * The key a guard's block is reported under.
     *
     * @param  string  $guard
     * @return string
     */
    private static function guardKey(string $guard): string
    {
        return "auth.guards.{$guard}.freshness";
    }
}
