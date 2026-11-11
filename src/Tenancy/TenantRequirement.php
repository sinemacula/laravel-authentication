<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy;

use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * A tenant authentication policy's answer: the further factor, the connections
 * and the version.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TenantRequirement
{
    /** @var int The longest version a session records. */
    public const int VERSION_MAX_LENGTH = 64;

    /** @var ?list<non-empty-string> The connections a session must have been established through; `null` for no such requirement, `[]` for none that satisfies. */
    public ?array $connections;

    /**
     * Constructor.
     *
     * @param  ?string  $version
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $factor
     * @param  ?array<array-key, mixed>  $connections
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The version of the answer, 1 to 64 characters, or `null`. */
        public ?string $version = null,

        /** The further factor required; an empty requirement asks for none. */
        public Requirement $factor = new Requirement,

        // The connection ids, a list of non-empty strings, or `null`.
        ?array $connections = null,
    ) {
        if ($version !== null && ($version === '' || mb_strlen($version) > self::VERSION_MAX_LENGTH)) {
            throw new \InvalidArgumentException(sprintf('A tenant policy version must be between 1 and %d characters.', self::VERSION_MAX_LENGTH));
        }

        $this->connections = $connections === null ? null : self::connections($connections);
    }

    /**
     * Whether a session established through the connection meets the connection
     * requirement.
     *
     * @param  ?string  $connectionId
     * @return bool
     */
    public function admitsConnection(?string $connectionId): bool
    {
        return $this->connections === null || ($connectionId !== null && in_array($connectionId, $this->connections, true));
    }

    /**
     * The connection ids given, when they are a list of non-empty strings.
     *
     * @param  array<array-key, mixed>  $connections
     * @return list<non-empty-string>
     *
     * @throws \InvalidArgumentException
     */
    private static function connections(array $connections): array
    {
        $ids = array_filter($connections, static fn (mixed $id): bool => is_string($id) && $id !== '');

        if (!array_is_list($connections) || count($ids) !== count($connections)) {
            throw new \InvalidArgumentException('A tenant policy\'s connections must be a list of non-empty connection ids.');
        }

        return array_values($ids);
    }
}
