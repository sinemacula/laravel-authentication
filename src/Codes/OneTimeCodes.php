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
 * Every change is one statement the database applies atomically, and a database
 * error propagates.
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
        $code     = $this->draw($this->settings->length());
        $cooldown = $this->settings->cooldownSeconds();
        $issued   = new IssuedCode($code, Str::uuid()->toString(), $now->addSeconds($this->settings->ttlSeconds()));
        $digest   = $this->keys->binding($binding);
        $model    = new OneTimeCode;
        $issuance = [
            'issue_id'    => $issued->issueId,
            'code_hash'   => $this->keys->code($digest, $issued->issueId, $code),
            'attempts'    => 0,
            'issued_at'   => $model->fromDateTime($now),
            'expires_at'  => $model->fromDateTime($issued->expiresAt),
            'consumed_at' => null,
        ];

        $replaced = $this->table()
            ->where('id', $digest)
            ->where('issued_at', '<=', $model->fromDateTime($now->subSeconds($cooldown)))
            ->update($issuance) === 1;

        if ($replaced || $this->table()->insertOrIgnore(['id' => $digest, 'purpose' => $binding->purpose->value, 'guard' => $binding->guard, ...$issuance]) === 1) {
            return $issued;
        }

        $current = $this->find($digest);

        return $current === null ? 1 : max(1, $current->issued_at->getTimestamp() + $cooldown - $now->getTimestamp());
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
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
     * Whether the issuance is still the binding's live code: not replaced, not
     * used, and not expired.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $issueId
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
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
     * The binding's code as stored, read from the write PDO, or `null`.
     *
     * @param  string  $digest
     * @return ?\SineMacula\Laravel\Authentication\Models\OneTimeCode
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function table(): Builder
    {
        $model = new OneTimeCode;

        return $model->getConnection()->table($model->getTable());
    }
}
