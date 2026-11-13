<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;

/**
 * The one-time code engine: issues the live challenge of a delivery key and
 * checks codes against it, always on the write PDO.
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

    /** @var string A challenge id as issued: a lower-case UUID. */
    private const string CHALLENGE_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D';

    /** @var \SineMacula\Laravel\Authentication\Codes\CodeSettings The code settings. */
    private CodeSettings $settings;

    /** @var \SineMacula\Laravel\Authentication\Codes\CodeKeys The keyed digests of bindings and codes. */
    private CodeKeys $keys;

    /** @var \SineMacula\Laravel\Authentication\Codes\ChallengeDeliveries Writes each delivery to its key's row. */
    private ChallengeDeliveries $deliveries;

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
        $this->settings   = new CodeSettings($config);
        $this->keys       = new CodeKeys($config);
        $this->deliveries = new ChallengeDeliveries($this->settings, $this->keys);
    }

    /**
     * Deliver a new code for the binding, of its live challenge or a new one,
     * or answer why not.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     *
     * @phpstan-impure
     */
    public function issue(CodeBinding $binding, CarbonImmutable $now): DeliveryRefusal|IssuedCode
    {
        return $this->deliveries->deliver($binding, $now, $this->draw($this->settings->length()), $this->settings->ttlSeconds(), true);
    }

    /**
     * Issue a code as `issue()` does, trying the insert first, for a binding
     * that names a request of its own.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     *
     * @phpstan-impure
     */
    public function issueFirst(CodeBinding $binding, CarbonImmutable $now): DeliveryRefusal|IssuedCode
    {
        return $this->deliveries->deliver($binding, $now, $this->draw($this->settings->length()), $this->settings->ttlSeconds(), true, true);
    }

    /**
     * Issue a new live token for the binding (a password reset link's), as
     * `issue()` issues a code, that works for the seconds given.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $ttlSeconds
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     *
     * @phpstan-impure
     */
    public function issueToken(CodeBinding $binding, CarbonImmutable $now, int $ttlSeconds): DeliveryRefusal|IssuedCode
    {
        return $this->deliveries->deliver($binding, $now, rtrim(strtr(base64_encode(random_bytes(self::TOKEN_BYTES)), '+/', '-_'), '='), $ttlSeconds, false);
    }

    /**
     * Check the code against the live challenge of the binding's key, and use
     * it up when it matches.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $lock
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function check(CodeBinding $binding, string $challengeId, #[\SensitiveParameter] string $code, CarbonImmutable $now, bool $lock = false): CodeCheck
    {
        $digest = $this->keys->binding($binding);
        $max    = $this->settings->maxAttempts();
        $row    = CodeRows::find($digest, $lock);
        $same   = $row !== null && hash_equals($row->challenge_id, $challengeId) && CodeRows::isSameContext($row->context, $this->keys->context($binding));
        $live   = CodeRows::live($same ? $row : null, $max, $now);

        if ($live instanceof CodeCheck) {
            return $live;
        }

        return $this->countAttempt($live, $max, $now)
            ? $this->compare($live, $digest, $code, $now)
            : $this->recheck($digest, $live->issue_id, $max, $now);
    }

    /**
     * Check a token against the binding's live token, and use it up when it
     * matches; a 256-bit token counts no attempts.
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
        $row    = CodeRows::find($digest);

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
        $row = CodeRows::find($this->keys->binding($binding));

        return $row !== null
            && hash_equals($row->issue_id, $issueId)
            && $row->consumed_at === null
            && $row->expires_at->getTimestamp() > $now->getTimestamp();
    }

    /**
     * Whether the code is the one that used the binding's challenge up; ending
     * a challenge replaces its issuance, so no code matches one ended unused.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    public function isUsedBy(CodeBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): bool
    {
        $digest = $this->keys->binding($binding);
        $row    = CodeRows::find($digest);

        return $row !== null
            && hash_equals($row->challenge_id, $challengeId)
            && $row->consumed_at !== null
            && CodeRows::isSameContext($row->context, $this->keys->context($binding))
            && hash_equals($row->code_hash, $this->keys->code($digest, $row->issue_id, $code));
    }

    /**
     * End the challenge of each binding that is not used yet, keeping its row
     * so the delivery cap and cooldown still hold, and answer how many ended.
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

        if ($digests === []) {
            return 0;
        }

        return CodeRows::table()
            ->whereIn('id', $digests)
            ->whereNull('consumed_at')
            ->update([
                'issue_id'    => Str::uuid()->toString(),
                'consumed_at' => (new OneTimeCode)->fromDateTime(CarbonImmutable::now()->startOfSecond()),
            ]);
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
     * Whether the value is a challenge id the engine could have issued: a
     * lower-case UUID.
     *
     * @param  string  $challengeId
     * @return bool
     */
    public function isWellFormedChallenge(string $challengeId): bool
    {
        return preg_match(self::CHALLENGE_PATTERN, $challengeId) === 1;
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
     * The answer for a check that could not count its attempt against the
     * issuance it read.
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
        $fresh = CodeRows::find($digest);

        if ($fresh?->issue_id !== $issueId) {
            return CodeCheck::INVALID;
        }

        $live = CodeRows::live($fresh, $max, $now);

        return $live instanceof CodeCheck ? $live : CodeCheck::INVALID;
    }

    /**
     * Compare the code with the issuance's, and accept it only when this check
     * also uses the issuance up.
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
            : CodeCheck::WRONG;
    }

    /**
     * Count one attempt against the issuance while it is still live and under
     * its maximum, and answer whether it did.
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
        return CodeRows::table()
            ->where('id', $row->id)
            ->where('issue_id', $row->issue_id)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', $row->fromDateTime($now))
            ->where('attempts', '<', $max)
            ->increment('attempts') === 1;
    }

    /**
     * Use the issuance up while it is still the live code and unused, and
     * answer whether this call used it.
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
        return CodeRows::table()
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
}
