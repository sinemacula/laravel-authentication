<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;

/**
 * The one-time code engine: issues the live code of a binding and checks codes
 * against it, on the code table's connection and always on its write PDO.
 *
 * A code is `length` digits drawn uniformly with `random_int()`, stored only as
 * a keyed hash (see `CodeKeys`) under the digest of its binding, so one binding
 * has one live code. Issuing again replaces it at once, with a fresh issuance,
 * once the resend cooldown since the last has passed. A check counts an attempt
 * against the issuance it read before it compares anything, so concurrent
 * checks never exceed `max_attempts`, and uses the code up only with a second
 * conditional statement, so of two correct submissions exactly one is accepted.
 * A password reset link's token is a binding's live secret in the same way, 256
 * random bits under the same cooldown, checked without counting attempts. Every
 * change is one statement the database applies atomically, and a database error
 * propagates.
 *
 * The engine keeps no state between calls: the settings and the key are read
 * from the configuration each time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OneTimeCodes
{
    /** @var int Random bytes in a token, 256 bits. */
    private const int TOKEN_BYTES = 32;

    /** @var \SineMacula\Laravel\Authentication\Codes\CodeSettings The code settings. */
    private CodeSettings $settings;

    /** @var \SineMacula\Laravel\Authentication\Codes\CodeKeys The keyed digests of bindings and codes. */
    private CodeKeys $keys;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  (\Closure(int): string)|null  $generator
     */
    public function __construct(

        // Configuration the settings and the key are read from on every call.
        Repository $config,

        /** Draws a code of the given number of digits instead of `random_int()`; for tests that need a known code. */
        private ?\Closure $generator = null,
    ) {
        $this->settings = new CodeSettings($config);
        $this->keys     = new CodeKeys($config);
    }

    /**
     * Issue a new live code for the binding, replacing any code it had, unless
     * one was issued within the resend cooldown: then the seconds, at least 1,
     * until another may be.
     *
     * A code issued more than the cooldown ago is replaced in one conditional
     * update; a binding with no row gets one from an insert that a concurrent
     * issue cannot duplicate. When neither wrote, a code for the binding was
     * issued within the cooldown, by this client or a concurrent one.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return int|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-impure
     */
    public function issue(CodeBinding $binding, CarbonImmutable $now): int|IssuedCode
    {
        return $this->store($binding, $now, $this->draw($this->settings->length()), $this->settings->ttlSeconds());
    }

    /**
     * Issue a code for a binding that names a request of its own (an identifier
     * change's), so none can have been issued for it yet, as `issue()` issues
     * one, trying the insert before the replacement: inside the request's
     * transaction, MySQL's `UPDATE` of a missing key would lock the gap it
     * searched until the commit, and two requests that each insert into the
     * same gap would then deadlock.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return int|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-impure
     */
    public function issueFirst(CodeBinding $binding, CarbonImmutable $now): int|IssuedCode
    {
        return $this->store($binding, $now, $this->draw($this->settings->length()), $this->settings->ttlSeconds(), true);
    }

    /**
     * Issue a new live token for the binding (a password reset link's), as
     * `issue()` issues a code, under the same resend cooldown, that works for
     * the seconds given: 32 random bytes, base64url-encoded without padding (43
     * characters), stored only as its keyed hash.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $ttlSeconds
     * @return int|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-impure
     */
    public function issueToken(CodeBinding $binding, CarbonImmutable $now, int $ttlSeconds): int|IssuedCode
    {
        return $this->store($binding, $now, rtrim(strtr(base64_encode(random_bytes(self::TOKEN_BYTES)), '+/', '-_'), '='), $ttlSeconds);
    }

    /**
     * Check the code against the binding's live code, and use it up when it
     * matches.
     *
     * A binding with no code, or whose code was used, is `invalid`; one whose
     * code has expired or used up its attempts says so, without counting. A
     * check that can count an attempt against the issuance it read compares the
     * code, and accepts it only when it also uses that issuance up; one that
     * cannot (a concurrent resend, check or expiry got there first) never
     * compares, and answers from a fresh read.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function check(CodeBinding $binding, #[\SensitiveParameter] string $code, CarbonImmutable $now): CodeCheck
    {
        $digest = $this->keys->binding($binding);
        $max    = $this->settings->maxAttempts();
        $live   = self::live($this->find($digest), $max, $now);

        if ($live instanceof CodeCheck) {
            return $live;
        }

        return $this->countAttempt($live, $max, $now)
            ? $this->compare($live, $digest, $code, $now)
            : $this->recheck($digest, $live->issue_id, $max, $now);
    }

    /**
     * Check a token against the binding's live token, and use it up when it
     * matches. No attempt is counted: a token has 256 bits, so none can be
     * guessed. A binding with no token, or a used one, or a token that does
     * not match, is `invalid`; a matching one that has expired is `expired`;
     * a matching live one is `accepted` only when this check also uses it up,
     * so of two concurrent checks exactly one is.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $token
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function checkToken(CodeBinding $binding, #[\SensitiveParameter] string $token, CarbonImmutable $now): CodeCheck
    {
        $digest = $this->keys->binding($binding);
        $row    = $this->find($digest);

        return match (true) {
            $row === null,
            $row->consumed_at !== null,
            !hash_equals($row->code_hash, $this->keys->code($digest, $row->issue_id, $token)) => CodeCheck::INVALID,
            $row->expires_at->getTimestamp() <= $now->getTimestamp()                          => CodeCheck::EXPIRED,
            default                                                                           => $this->useUp($row, $now) ? CodeCheck::ACCEPTED : CodeCheck::INVALID,
        };
    }

    /**
     * Whether the issuance is still the binding's live code: not replaced, not
     * used, and not expired.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $issueId
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function isCurrent(CodeBinding $binding, string $issueId, CarbonImmutable $now): bool
    {
        $row = $this->find($this->keys->binding($binding));

        return $row !== null
            && hash_equals($row->issue_id, $issueId)
            && $row->consumed_at === null
            && $row->expires_at->getTimestamp() > $now->getTimestamp();
    }

    /**
     * Delete the live code of each binding, whatever its state, in one
     * statement, so none of them can be checked again. Returns how many rows it
     * deleted.
     *
     * @param  iterable<\SineMacula\Laravel\Authentication\Codes\CodeBinding>  $bindings
     * @return int
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function invalidate(iterable $bindings): int
    {
        $digests = [];

        foreach ($bindings as $binding) {
            $digests[] = $this->keys->binding($binding);
        }

        return $digests === [] ? 0 : $this->table()->whereIn('id', $digests)->delete();
    }

    /**
     * Whether the code is exactly `length` ASCII digits.
     *
     * @param  string  $code
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isWellFormed(#[\SensitiveParameter] string $code): bool
    {
        return preg_match(sprintf('/^\d{%d}$/D', $this->settings->length()), $code) === 1;
    }

    /**
     * Whether the value is a token `issueToken()` could have drawn: exactly 43
     * base64url characters.
     *
     * @param  string  $token
     * @return bool
     */
    public function isWellFormedToken(#[\SensitiveParameter] string $token): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{43}$/D', $token) === 1;
    }

    /**
     * Store the secret as the binding's live issuance, replacing one issued
     * more than the resend cooldown ago, or answer the seconds until another
     * may be.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @param  string  $secret
     * @param  int  $ttlSeconds
     * @param  bool  $insertFirst
     * @return int|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-impure
     */
    private function store(CodeBinding $binding, CarbonImmutable $now, #[\SensitiveParameter] string $secret, int $ttlSeconds, bool $insertFirst = false): int|IssuedCode
    {
        $cooldown = $this->settings->cooldownSeconds();
        $issued   = new IssuedCode($secret, Str::uuid()->toString(), $now->addSeconds($ttlSeconds));
        $digest   = $this->keys->binding($binding);
        $model    = new OneTimeCode;
        $issuance = [
            'issue_id'    => $issued->issueId,
            'code_hash'   => $this->keys->code($digest, $issued->issueId, $secret),
            'attempts'    => 0,
            'issued_at'   => $model->fromDateTime($now),
            'expires_at'  => $model->fromDateTime($issued->expiresAt),
            'consumed_at' => null,
        ];

        $row     = ['id' => $digest, 'purpose' => $binding->purpose->value, 'guard' => $binding->guard, ...$issuance];
        $replace = $this->table()->where('id', $digest)->where('issued_at', '<=', $model->fromDateTime($now->subSeconds($cooldown)));

        if (($insertFirst && $this->table()->insertOrIgnore($row) === 1) || $replace->update($issuance) === 1 || (!$insertFirst && $this->table()->insertOrIgnore($row) === 1)) {
            return $issued;
        }

        $current = $this->find($digest);

        return $current === null ? 1 : max(1, $current->issued_at->getTimestamp() + $cooldown - $now->getTimestamp());
    }

    /**
     * The binding's code as stored, read from the write PDO, or `null`.
     *
     * @param  string  $digest
     * @return ?\SineMacula\Laravel\Authentication\Models\OneTimeCode
     *
     * @throws \InvalidArgumentException
     */
    private function find(string $digest): ?OneTimeCode
    {
        $code = WriteConnection::query((new OneTimeCode)->newQuery())->find($digest);

        return $code instanceof OneTimeCode ? $code : null;
    }

    /**
     * The binding's code when it can still be checked, or why not: there is
     * none, or it was used (`invalid`), it has expired, or it has used up its
     * attempts.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  int  $max
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck|\SineMacula\Laravel\Authentication\Models\OneTimeCode
     */
    private static function live(?OneTimeCode $row, int $max, CarbonImmutable $now): CodeCheck|OneTimeCode
    {
        return match (true) {
            $row === null, $row->consumed_at !== null                => CodeCheck::INVALID,
            $row->expires_at->getTimestamp() <= $now->getTimestamp() => CodeCheck::EXPIRED,
            $row->attempts >= $max                                   => CodeCheck::EXHAUSTED,
            default                                                  => $row,
        };
    }

    /**
     * The answer for a check that could not count its attempt against the
     * issuance it read: why that issuance refuses checks when it is still the
     * binding's code and does; otherwise `invalid`.
     *
     * @param  string  $digest
     * @param  string  $issueId
     * @param  int  $max
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     */
    private function recheck(string $digest, string $issueId, int $max, CarbonImmutable $now): CodeCheck
    {
        $fresh = $this->find($digest);
        $live  = self::live($fresh?->issue_id === $issueId ? $fresh : null, $max, $now);

        return $live instanceof CodeCheck ? $live : CodeCheck::INVALID;
    }

    /**
     * Compare the code with the issuance's, after its attempt was counted, and
     * accept it only when this check also uses the issuance up.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  string  $digest
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     */
    private function compare(OneTimeCode $row, string $digest, #[\SensitiveParameter] string $code, CarbonImmutable $now): CodeCheck
    {
        return hash_equals($row->code_hash, $this->keys->code($digest, $row->issue_id, $code)) && $this->useUp($row, $now)
            ? CodeCheck::ACCEPTED
            : CodeCheck::INVALID;
    }

    /**
     * Count one attempt against the issuance, in one statement, while it is
     * still the live code, unused, unexpired and under its maximum. Returns
     * whether it did.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  int  $max
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     *
     * @imperative
     */
    private function countAttempt(OneTimeCode $row, int $max, CarbonImmutable $now): bool
    {
        return $this->table()
            ->where('id', $row->id)
            ->where('issue_id', $row->issue_id)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', $row->fromDateTime($now))
            ->where('attempts', '<', $max)
            ->increment('attempts') === 1;
    }

    /**
     * Use the issuance up, in one statement, while it is still the live code
     * and unused. Returns whether this call used it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     *
     * @imperative
     */
    private function useUp(OneTimeCode $row, CarbonImmutable $now): bool
    {
        return $this->table()
            ->where('id', $row->id)
            ->where('issue_id', $row->issue_id)
            ->whereNull('consumed_at')
            ->update(['consumed_at' => $row->fromDateTime($now)]) === 1;
    }

    /**
     * Draw a code of the given number of digits, uniformly, zero-padded.
     *
     * @param  int  $length
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function draw(int $length): string
    {
        if ($this->generator !== null) {
            return ($this->generator)($length);
        }

        return str_pad((string) random_int(0, (int) str_repeat('9', $length)), $length, '0', STR_PAD_LEFT);
    }

    /**
     * A query on the codes' table, on its own connection, for the writes.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function table(): Builder
    {
        $model = new OneTimeCode;

        return $model->getConnection()->table($model->getTable());
    }
}
