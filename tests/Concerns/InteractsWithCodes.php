<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\DeliveryRefusal;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;

/**
 * Finds one-time codes the way their keys are documented, an HMAC-SHA256 of the
 * parts joined by NUL bytes under a key derived from the application key for
 * each purpose, so tests compute a row's key and a code's hash themselves
 * rather than asking the engine; reads the challenge id a check names; and
 * builds an engine that issues known codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithCodes
{
    /** @var string A well-formed challenge id no challenge is issued with. */
    protected const string NO_CHALLENGE = '00000000-0000-4000-8000-000000000000';

    /** @var string What a challenge id the engine issues looks like: a lower-case UUID. */
    protected const string CHALLENGE_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D';

    /**
     * The key of the binding's code row.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @return string
     */
    protected static function bindingDigest(CodeBinding $binding): string
    {
        $parts = ['binding', $binding->purpose->value, $binding->guard, $binding->type, $binding->identifier, $binding->identity];

        return hash_hmac('sha256', implode("\0", $parts), self::derivedCodeKey('bindings'));
    }

    /**
     * The hash a code issued for the binding in the issuance is stored as.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $issueId
     * @param  string  $code
     * @return string
     */
    protected static function codeHash(CodeBinding $binding, string $issueId, string $code): string
    {
        return hash_hmac('sha256', implode("\0", ['code', self::bindingDigest($binding), $issueId, $code]), self::derivedCodeKey('hashes'));
    }

    /**
     * The id of the live challenge stored for the binding, or of the only one
     * stored when no binding is given; a well-formed id no challenge has when
     * there is none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @return string
     */
    protected static function challenge(?CodeBinding $binding = null): string
    {
        $query = self::codeRows();
        $id    = ($binding === null ? $query : $query->where('id', self::bindingDigest($binding)))->value('challenge_id');

        return is_string($id) ? $id : self::NO_CHALLENGE;
    }

    /**
     * The seconds of cooldown an issue answered with, or `null` when it issued
     * a code or answered the delivery cap.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\DeliveryRefusal|\SineMacula\Laravel\Authentication\Codes\IssuedCode  $issued
     * @return ?int
     */
    protected static function cooldownOf(DeliveryRefusal|IssuedCode $issued): ?int
    {
        return $issued instanceof DeliveryRefusal && !$issued->exhausted ? $issued->retryAfter : null;
    }

    /**
     * An engine that issues the given codes in turn, as the container would
     * build it otherwise.
     *
     * @param  list<string>  $codes
     * @return \SineMacula\Laravel\Authentication\Codes\OneTimeCodes
     */
    protected static function sequence(array $codes): OneTimeCodes
    {
        return new OneTimeCodes(app(Repository::class), static function () use (&$codes): string {
            $code = array_shift($codes);

            self::assertIsString($code, 'The engine issued more codes than the test gave it.');

            return $code;
        });
    }

    /**
     * Bind an engine that issues the given codes in turn, for the sign-in
     * methods and the code service the container builds from now on.
     *
     * @param  list<string>  $codes
     * @return void
     */
    protected static function issueCodes(array $codes): void
    {
        app()->instance(OneTimeCodes::class, self::sequence($codes));
    }

    /**
     * The challenge id of the code sent for the identity's pending change of
     * the type, read on the write connection, or a well-formed id no challenge
     * has when it has none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return string
     */
    protected static function changeChallenge(Identity $identity, string $type = 'email'): string
    {
        $change = PendingChanges::find($identity, $type);
        $id     = $change === null ? null : self::codeRows()->where('id', self::bindingDigest(PendingChanges::binding($change, $identity)))->value('challenge_id');

        return is_string($id) ? $id : self::NO_CHALLENGE;
    }

    /**
     * A query on the codes' table, on the connection the codes live on, for the
     * write PDO.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function codeRows(): Builder
    {
        $model = new OneTimeCode;

        return $model->getConnection()->table($model->getTable())->useWritePdo();
    }

    /**
     * The key derived from the application key for one of the code key's
     * purposes (`bindings` or `hashes`).
     *
     * @param  string  $purpose
     * @return string
     */
    private static function derivedCodeKey(string $purpose): string
    {
        return hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code ' . $purpose, Config::string('app.key'), true);
    }
}
