<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;

/**
 * An authentication context contributor that answers as scripted and keeps
 * every subject it was given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedContributor implements AuthenticationContextContributor
{
    /** @var list<\SineMacula\Laravel\Authentication\Context\ContributionSubject> The subjects it was given, in order. */
    public array $asked = [];

    /**
     * Constructor.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Context\ContributionSubject): array<array-key, mixed>  $script
     */
    public function __construct(

        /** Answers the keys for a subject. */
        private readonly \Closure $script,
    ) {}

    /**
     * Keep the subject and answer what the script does.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, mixed>
     */
    #[\Override]
    public function contribute(ContributionSubject $subject): array
    {
        $this->asked[] = $subject;

        /** @var array<string, mixed> */
        return ($this->script)($subject);
    }
}
