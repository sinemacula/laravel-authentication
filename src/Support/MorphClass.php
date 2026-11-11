<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

use Illuminate\Database\ClassMorphViolationException;
use Illuminate\Database\Eloquent\Model;

/**
 * Names a subject by its morph class, or its class name when it is no model.
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
