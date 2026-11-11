<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;

/**
 * An identity's sessions as the package reads them, through its `sessions()`
 * relation on the write connection.
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
     * model it queries.
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

        if (!SessionKeyShape::matches($model, $id)) {
            return null;
        }

        $session = WriteConnection::during($identity, static fn (): mixed => $query->find($id));

        return $session instanceof $model ? $session : null;
    }
}
