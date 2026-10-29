<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\CodeSettings;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use SineMacula\Laravel\Authentication\Delivery\QueuedDelivery;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Sends password reset links and codes for a guard, doing the same work for
 * every identifier: no identity is looked up.
 *
 * In order: the settings (codes, their key, the delivery queue and, for a link,
 * its lifetime) fail closed, and the provider's configured model must live on
 * the device model's connection, as a reset needs (see `SharedConnection`); the
 * guard must allow the password method; the identifier must be one its type's
 * normaliser accepts (as given, for a link whose type has none); the identifier
 * and the IP address must have reset requests left (`password_reset_request`,
 * counted on every request and never given back); and no link or code may have
 * been issued for the identifier within the codes' resend cooldown. Then the
 * link's token or the code is issued, for any identifier, and its delivery
 * queued once it is committed; the job alone decides, later, whether anyone
 * receives it (see `SendPasswordReset`). Refusals are reported by
 * `AuthenticationFailed` (`password_reset`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResetRequests
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The guard the resets are requested through. */
        private JwtGuard $guard,

        /** Container the settings, policies, limiter, engine and queue are resolved from. */
        private Container $container,
    ) {}

    /**
     * Send a reset link to the identifier the input names under the guard's
     * password identifier. While the default sender, Laravel's notification, is
     * bound, that identifier must be `email`.
     *
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function link(#[\SensitiveParameter] array $input, ?ClientContext $client): CodeRequest
    {
        $type = $this->container->make(PasswordSignIn::class)->identifierType($this->guard->getName());

        $this->assertSenderReaches($type);

        return $this->send(CodePurpose::PASSWORD_RESET_LINK, $type, $input, $client);
    }

    /**
     * Send a reset code to the identifier the input names under the type, which
     * must have a registered normaliser.
     *
     * @param  string  $type
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function code(string $type, #[\SensitiveParameter] array $input, ?ClientContext $client): CodeRequest
    {
        ResetInput::assertCodeType($this->container->make(IdentifierNormalisers::class), $type);

        return $this->send(CodePurpose::PASSWORD_RESET, $type, $input, $client);
    }

    /**
     * Take a request from the identifier's and the IP address's limits, issue
     * the token or code, and queue its delivery; malformed settings fail closed
     * before anything is counted.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function send(CodePurpose $purpose, string $type, #[\SensitiveParameter] array $input, ?ClientContext $client): CodeRequest
    {
        $delivery   = new QueuedDelivery($this->container);
        $ttl        = $this->validated($delivery);
        $guard      = $this->guard->getName();
        $context    = new EventContext($guard, $client ?? ClientContext::fromRequest($this->guard->getRequest()));
        $given      = ResetInput::identifier($input, $type);
        $identifier = $this->admit($type, $given, $context);

        if (is_array($identifier)) {
            return $this->refuse($identifier, $context, $given);
        }

        $codes   = $this->container->make(OneTimeCodes::class);
        $now     = CarbonImmutable::now()->startOfSecond();
        $link    = $purpose === CodePurpose::PASSWORD_RESET_LINK;
        $binding = $link ? CodeBinding::passwordResetLink($guard, $type, $identifier) : CodeBinding::passwordReset($guard, $type, $identifier);
        $issued  = $link ? $codes->issueToken($binding, $now, $ttl) : $codes->issue($binding, $now);

        if (is_int($issued)) {
            return $this->refuse([CodeRequest::rateLimited($issued), FailureReason::RATE_LIMITED, $issued], $context, $given);
        }

        $delivery->dispatch(new SendPasswordReset($binding, $issued), new OneTimeCode);

        return CodeRequest::sent($issued->expiresAt);
    }

    /**
     * The identifier given, in canonical form, when the request may go on;
     * otherwise why not, with the answer: the guard does not allow passwords,
     * the identifier is not one, or the identifier or the IP address has no
     * reset requests left (a request that gets this far is counted).
     *
     * @param  string  $type
     * @param  ?string  $given
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return array{0: \SineMacula\Laravel\Authentication\Codes\CodeRequest, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 2: ?int}|string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function admit(string $type, ?string $given, EventContext $context): array|string
    {
        $guard      = $this->guard->getName();
        $identifier = $given === null ? null : $this->container->make(IdentifierVerifier::class)->canonical($type, $given);

        if (!$this->container->make(AudiencePolicy::class)->allowsMethod($guard, PasswordSignIn::NAME)) {
            return [CodeRequest::methodNotAllowed(), FailureReason::METHOD_NOT_ALLOWED, null];
        }

        if ($identifier === null || $identifier === '') {
            return [CodeRequest::identifierInvalid(), FailureReason::INVALID_CREDENTIALS, null];
        }

        $wait = $this->container->make(AttemptLimiter::class)->acquire(
            new AttemptSubject($guard, AttemptFlow::PASSWORD_RESET_REQUEST, $identifier, $type, $context->client->ip),
        )->retryAfter;

        return $wait === null ? $identifier : [CodeRequest::rateLimited($wait), FailureReason::RATE_LIMITED, $wait];
    }

    /**
     * Refuse a link the bound sender cannot deliver: while Laravel's
     * notification is the sender, the password identifier must be `email`.
     *
     * @param  string  $type
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertSenderReaches(string $type): void
    {
        if ($type === NotifyingResetLinkSender::IDENTIFIER_TYPE || !$this->container->make(PasswordResetLinkSender::class) instanceof NotifyingResetLinkSender) {
            return;
        }

        $message = sprintf(
            'Guard [%s] identifies passwords by [%s], but the bound %s, Laravel\'s notification, can only link an email address: bind a %s of your own.',
            $this->guard->getName(),
            $type,
            NotifyingResetLinkSender::class,
            PasswordResetLinkSender::class,
        );

        throw new \InvalidArgumentException($message);
    }

    /**
     * Validate every setting a request reads, the delivery queue included, and
     * refuse a guard whose provider's model is on another connection than the
     * devices, whose resets could never run, before anything is counted; then
     * answer the link lifetime.
     *
     * @param  \SineMacula\Laravel\Authentication\Delivery\QueuedDelivery  $delivery
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function validated(QueuedDelivery $delivery): int
    {
        $config = $this->container->make(Repository::class);

        (new CodeSettings($config))->validate();
        (new CodeKeys($config))->validate();
        $delivery->settings();

        SharedConnection::assertForGuard($this->guard->getName(), ResetSubmissions::FLOW, $config);

        return (new PasswordSettings($config))->linkTtlSeconds();
    }

    /**
     * Report a refused request with `AuthenticationFailed` and answer it.
     *
     * @param  array{0: \SineMacula\Laravel\Authentication\Codes\CodeRequest, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 2: ?int}  $refusal
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?string  $given
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     */
    private function refuse(array $refusal, EventContext $context, ?string $given): CodeRequest
    {
        [$request, $reason, $retryAfter] = $refusal;

        $this->guard->getDispatcher()->dispatch(new AuthenticationFailed($context, AuthenticationFlow::PASSWORD_RESET, $reason, $given, $retryAfter));

        return $request;
    }
}
