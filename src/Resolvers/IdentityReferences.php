<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Resolvers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\KeyShape;
use SineMacula\Laravel\Authentication\Support\MorphClass;

/**
 * Resolves the identity a stored reference names by its morph type and key, as
 * a session row records its owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class IdentityReferences
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The Eloquent identity whose morph class is the type and whose key is the
     * id byte for byte, read on the write connection with the model's global
     * scopes; `null` when none is, without a query for an id that cannot be a
     * key of the model.
     *
     * @param  string  $type
     * @param  string  $id
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null
     */
    public static function resolve(string $type, string $id): (Identity&Model)|null
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        if (!is_subclass_of($class, Model::class) || !is_subclass_of($class, Identity::class)) {
            return null;
        }

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity $model */
        $model = new $class;

        if (!KeyShape::matches($model, $id)) {
            return null;
        }

        $found = WriteConnection::during($model, static fn (): ?Model => WriteConnection::query($model->newQuery())->find($id));

        // A collation can match another spelling of the key
        if (!$found instanceof Identity || MorphClass::of($found) !== $type || IdentifierCoercion::stringify($found->getKey()) !== $id) {
            return null;
        }

        return $found;
    }
}
