<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\ExactMatch;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\KeyShape;

/**
 * An identity's sessions as the package reads them, through its `sessions()`
 * relation on the write connection, held to rows that record it byte for byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentitySessions
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A write-connection query of the identity's sessions, with the session
     * model it queries; a non-Eloquent identity owns none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasSessions&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return array{0: \Illuminate\Contracts\Database\Eloquent\Builder, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession}
     *
     * @throws \LogicException
     */
    public static function query(HasSessions&Identity $identity): array
    {
        $query = WriteConnection::during($identity, static fn (): Builder => WriteConnection::query($identity->sessions()));
        $model = $query->getModel();

        if (!$model instanceof EloquentSession) {
            throw new \LogicException(sprintf('The sessions() relation of %s must query a model that implements %s.', $identity::class, EloquentSession::class));
        }

        $owner = $model->authenticatable();

        ExactMatch::where($query, $model, $identity instanceof Model ? [
            $owner->getMorphType()      => $identity->getMorphClass(),
            $owner->getForeignKeyName() => IdentifierCoercion::stringify($identity->getKey()),
        ] : [$owner->getForeignKeyName() => null]);

        return [$query, $model];
    }

    /**
     * The identity's session with the identifier, or `null` when it has no such
     * session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $id
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \LogicException
     */
    public static function find(Identity $identity, mixed $id): (EloquentSession&Model)|null
    {
        if ($id === null || !$identity instanceof HasSessions) {
            return null;
        }

        [$query, $model] = self::query($identity);

        if (!KeyShape::matches($model, $id)) {
            return null;
        }

        $session = WriteConnection::during($identity, static fn (): mixed => $query->find($id));

        return $session instanceof $model ? $session : null;
    }
}
