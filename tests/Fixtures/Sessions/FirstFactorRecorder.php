<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;

/**
 * Gives a session row a test inserts itself the first-factor proof a real
 * sign-in would record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FirstFactorRecorder
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Record the first-factor proof on every session row created from now on
     * outside the session writer, while the given check allows it.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \Closure(): bool  $enabled
     * @return void
     */
    public static function listen(Dispatcher $events, \Closure $enabled): void
    {
        $events->listen('eloquent.created: *', static function (string $event, array $payload) use ($enabled): void {

            $session = $payload[0] ?? null;

            if (!$enabled() || !$session instanceof EloquentSession || !$session instanceof Model) {
                return;
            }

            self::record($session);
        });
    }

    /**
     * Record the first-factor proof the row's sign-in would have recorded, when
     * the row records enough to build one.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \Throwable
     */
    public static function record(EloquentSession&Model $session): void
    {
        $proof = self::firstFactorOf($session);
        $guard = $session->getAttribute($session->getGuardName());

        if ($proof === null || !is_string($guard) || self::isWrittenBySessionWriter()) {
            return;
        }

        try {
            ProofWriter::record($session, $guard, $proof);
        } catch (\Throwable $exception) {
            // A test that migrates its own tables may have no proofs table; on
            // PostgreSQL the failed insert aborts any open transaction.
            if (!$exception instanceof QueryException) {
                throw $exception;
            }
        }
    }

    /**
     * Whether the session writer is inserting the session being created: it
     * records the sign-in's own proofs.
     *
     * @return bool
     */
    public static function isWrittenBySessionWriter(): bool
    {
        foreach ((new \LogicException)->getTrace() as $frame) {
            if (($frame['class'] ?? null) === SessionWriter::class) {
                return true;
            }
        }

        return false;
    }

    /**
     * The first factor the row's sign-in would have recorded, or `null` when
     * the row records too little.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?\SineMacula\Laravel\Authentication\Proofs\NewProof
     *
     * @throws \LogicException
     */
    private static function firstFactorOf(EloquentSession&Model $session): ?NewProof
    {
        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $blank */
        $blank    = $session->newInstance();
        $owner    = $blank->authenticatable();
        $type     = $session->getAttribute($owner->getMorphType());
        $signedIn = array_key_exists($session->getSignedInAtName(), $session->getAttributes()) ? $session->getSignedInAt() : null;
        $method   = $session->getAttribute($session->getSignInMethodName());

        $recordable = $signedIn !== null
            && is_string($type)
            && class_exists(Relation::getMorphedModel($type) ?? $type)
            && $session->getAttribute($owner->getForeignKeyName()) !== null;

        if (!$recordable) {
            return null;
        }

        $name = is_string($method) ? $method : 'password';

        [$kind, $values] = match ($name) {
            'password'   => [ChannelKind::PASSWORD, ['pwd']],
            'email_code' => [ChannelKind::EMAIL, ['otp']],
            'phone_code' => [ChannelKind::SMS, ['sms']],
            'passkey'    => [ChannelKind::PASSKEY, ['pop']],
            default      => [ChannelKind::UNKNOWN, []],
        };

        $at = CarbonImmutable::instance($signedIn);

        return new NewProof(ProofKind::FIRST_FACTOR, Purpose::SIGN_IN, $name, new Channel($kind), null, new ObservedProperties, null, $values, $at);
    }
}
