<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

use Illuminate\Database\ClassMorphViolationException;
use Illuminate\Database\Eloquent\Model;

/**
 * The type an identity, principal or tenant is named by wherever the package
 * reports one as a plain value (an event's context, the authentication
 * context): an Eloquent model's morph class, any other object's class name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MorphClass
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The morph class the subject is named by.
     *
     * A model the morph map leaves out under `Relation::enforceMorphMap()` is
     * named by its class name: a tenant reached through a plain relation never
     * needed an alias, and naming it must not fail the flow that reports it.
     *
     * @param  object  $subject
     * @return string
     */
    public static function of(object $subject): string
    {
        try {
            return $subject instanceof Model ? $subject->getMorphClass() : $subject::class;
        } catch (ClassMorphViolationException) {
            return $subject::class;
        }
    }
}
