<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Factor code counters that answer as scripted and record every call, the way
 * the factor package's counters run: each call requires a transaction open on
 * the storage connection, as the factor package's own writes and locks would,
 * and throws a `LogicException` without one; a report can be made to throw, as
 * one that fails would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingFactorCodeCounters implements FactorCodeCounters
{
    /** @var list<\SineMacula\Laravel\Authentication\Codes\FactorCodeBinding> The bindings admission was asked for, in order. */
    public array $admitted = [];

    /** @var list<array{0: \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding, 1: string, 2: bool, 3: int}> Each report: the binding, the challenge, whether it passed, and the open transaction level. */
    public array $reports = [];

    /** @var ?\Closure(string): void Told `admit` or `report` as each call is made, when set. */
    public ?\Closure $observer = null;

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission  $admission
     * @param  ?\SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission  $report
     * @param  ?\Throwable  $failure
     */
    public function __construct(

        /** What admission answers; admitted when `null`. */
        public ?FactorCodeAdmission $admission = null,

        /** What a report answers; admitted when `null`. */
        public ?FactorCodeAdmission $report = null,

        /** Thrown by a report, when given. */
        public ?\Throwable $failure = null,
    ) {}

    /**
     * Record the binding and answer the scripted admission.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     *
     * @throws \LogicException
     */
    #[\Override]
    public function admit(FactorCodeBinding $binding): FactorCodeAdmission
    {
        self::requireTransaction();

        $this->admitted[] = $binding;

        $this->observe('admit');

        return $this->admission ?? FactorCodeAdmission::admitted();
    }

    /**
     * Record the attempt and answer the scripted report, or throw.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  bool  $passed
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     *
     * @throws \Throwable
     */
    #[\Override]
    public function report(FactorCodeBinding $binding, string $challengeId, bool $passed): FactorCodeAdmission
    {
        $this->reports[] = [$binding, $challengeId, $passed, self::requireTransaction()];

        $this->observe('report');

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->report ?? FactorCodeAdmission::admitted();
    }

    /**
     * Tell the observer of the call, when there is one.
     *
     * @param  string  $call
     * @return void
     */
    private function observe(string $call): void
    {
        if ($this->observer === null) {
            return;
        }

        ($this->observer)($call);
    }

    /**
     * The transaction level open on the storage connection, which must be one.
     *
     * @return int
     *
     * @throws \LogicException
     */
    private static function requireTransaction(): int
    {
        $level = DB::connection(StorageConnection::name())->transactionLevel();

        if ($level === 0) {
            throw new \LogicException('The factor code counters run only inside a transaction on the storage connection.');
        }

        return $level;
    }
}
