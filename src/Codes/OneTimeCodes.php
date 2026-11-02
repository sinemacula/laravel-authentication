<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;

/**
 * The one-time code engine: issues the live challenge of a delivery key and
 * checks codes against it, on the code table's connection and always on its
 * write PDO.
 *
 * A code is `length` digits drawn uniformly with `random_int()`, stored only as
 * a keyed hash (see `CodeKeys`) under the digest of its binding's key, so one
 * key has one live challenge. A challenge has a public id, and, for a further
 * factor's code, a transaction the key leaves out; both are compared before
 * anything is counted. Issuing again, once the resend cooldown since the last
 * delivery has passed, is a new delivery: of the same challenge (its id and its
 * attempts kept) while it is live and its transaction is the one given, or of a
 * new challenge otherwise; either way with a new code and issuance that
 * invalidate the previous code. The deliveries belong to the key's delivery
 * window, which lasts `max_lifetime_seconds` from its first delivery and allows
 * `max_deliveries`, across every challenge it holds; no code outlives it, so a
 * resend never extends a challenge past it. A check counts an attempt against
 * the issuance it read before it compares anything, so concurrent checks never
 * exceed `max_attempts`, and uses the code up only with a second conditional
 * statement, so of two correct submissions exactly one is accepted. A password
 * reset link's token is a key's live secret in the same way, 256 random bits
 * under the same cooldown and delivery cap, checked without counting attempts,
 * with the lifetime its caller gives. Every change is one statement the
 * database applies atomically, conditional on the issuance it read, and a
 * database error propagates.
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
     * unless one was delivered for its key within the resend cooldown or its
     * delivery window has had all its deliveries: then why not, and the seconds
     * until another may be.
     *
     * A key with no row gets one from an insert that a concurrent issue cannot
     * duplicate; otherwise the row is replaced in one update conditional on the
     * issuance it read. When neither wrote, a code for the key was issued
     * meanwhile, by this client or a concurrent one, within the cooldown.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpstan-impure
     */
    public function issue(CodeBinding $binding, CarbonImmutable $now): DeliveryRefusal|IssuedCode
    {
        return $this->deliveries->deliver($binding, $now, $this->draw($this->settings->length()), $this->settings->ttlSeconds(), true);
    }

    /**
     * Issue a code for a binding that names a request of its own (an identifier
     * change's), so none can have been issued for it yet, as `issue()` issues
     * one, trying the insert before reading the row: inside the request's
     * transaction, a locking read of a missing key on MySQL would lock the gap
     * it searched until the commit, and two requests that each insert into the
     * same gap would then deadlock.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpstan-impure
     */
    public function issueFirst(CodeBinding $binding, CarbonImmutable $now): DeliveryRefusal|IssuedCode
    {
        return $this->deliveries->deliver($binding, $now, $this->draw($this->settings->length()), $this->settings->ttlSeconds(), true, true);
    }

    /**
     * Issue a new live token for the binding (a password reset link's), as
     * `issue()` issues a code, under the same resend cooldown and delivery cap,
     * that works for the seconds given, whatever is left of the delivery
     * window: 32 random bytes, base64url-encoded without padding (43
     * characters), stored only as its keyed hash.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $ttlSeconds
     * @return \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
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
     * A key with no challenge, one whose code was used, or whose challenge id
     * or transaction is not the one given, is `invalid`; one whose code has
     * expired or used up its attempts says so; none of these counts an attempt.
     * A check that can count an attempt against the issuance it read compares
     * the code, and accepts it only when it also uses that issuance up, and is
     * otherwise `wrong`; one that cannot (a concurrent resend, check or expiry
     * got there first) never compares, and answers from a fresh read. With
     * `$lock`, the row is read with a lock held until the caller's transaction
     * ends, so the check, and whatever the caller does in that transaction, is
     * the only one made on the challenge meanwhile.
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
     * matches. No attempt is counted: a token has 256 bits, so none can be
     * guessed, and it is its own transaction. A binding with no token, or a
     * used one, or a token that does not match, is `invalid`; a matching one
     * that has expired is `expired`; a matching live one is `accepted` only
     * when this check also uses it up, so of two concurrent checks exactly one
     * is.
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

        return $digests === [] ? 0 : CodeRows::table()->whereIn('id', $digests)->delete();
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
        $fresh = CodeRows::find($digest);
        $live  = CodeRows::live($fresh?->issue_id === $issueId ? $fresh : null, $max, $now);

        return $live instanceof CodeCheck ? $live : CodeCheck::INVALID;
    }

    /**
     * Compare the code with the issuance's, after its attempt was counted, and
     * accept it only when this check also uses the issuance up; otherwise it is
     * `wrong`.
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
        return CodeRows::table()
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
