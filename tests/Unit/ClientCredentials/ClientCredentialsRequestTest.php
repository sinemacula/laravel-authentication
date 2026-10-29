<?php

declare(strict_types = 1);

namespace Tests\Unit\ClientCredentials;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsRequest;
use SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient;
use Symfony\Component\Process\Process;

/**
 * Unit tests for reading a client credentials token request as RFC 6749 defines
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientCredentialsRequest::class)]
#[CoversClass(PresentedClient::class)]
final class ClientCredentialsRequestTest extends TestCase
{
    /** @var string Reads the request a body and its parameters make, in a PHP process of its own, and prints the result. */
    private const string READER = <<<'PHP'
        require $argv[1];

        $request = Illuminate\Http\Request::create('/oauth/token', 'POST', json_decode($argv[3], true), [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], $argv[2]);
        $read    = SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsRequest::read($request);

        echo is_string($read) ? $read : json_encode([$read->clientId, $read->scope]);
        PHP;

    /**
     * Body credentials and a scope are read; the client did not use Basic.
     *
     * @return void
     */
    public function testReadsBodyCredentialsAndAScope(): void
    {
        $presented = ClientCredentialsRequest::read(self::request('grant_type=client_credentials&client_id=id&client_secret=secret&scope=a+b'));

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertSame('id', $presented->clientId);
        self::assertSame('secret', $presented->clientSecret());
        self::assertSame('a b', $presented->scope);
        self::assertFalse($presented->basic);
    }

    /**
     * Basic credentials are read, each part form-url-decoded, whatever the
     * scheme's case, with a charset on the media type; a secret may hold a
     * colon.
     *
     * @return void
     */
    public function testReadsBasicCredentials(): void
    {
        $basic     = ['HTTP_AUTHORIZATION' => 'basic ' . base64_encode('my%20id:se%3Acr+et:x')];
        $request   = self::request('grant_type=client_credentials', $basic, 'application/x-www-form-urlencoded; charset=UTF-8');
        $presented = ClientCredentialsRequest::read($request);

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertSame('my id', $presented->clientId);
        self::assertSame('se:cr et:x', $presented->clientSecret());
        self::assertNull($presented->scope);
        self::assertTrue($presented->basic);
        self::assertTrue(ClientCredentialsRequest::usesBasic($request));
    }

    /**
     * Rows of
     * `[body, server, content type, query, client id, secret, scope, basic]`:
     * requests in form.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>, 2: string, 3: array<string, string>, 4: string, 5: string, 6: ?string, 7: bool}>
     */
    public static function provideClients(): iterable
    {
        $form  = 'application/x-www-form-urlencoded';
        $mixed = ' Application/X-WWW-Form-Urlencoded ;charset=utf-8';
        $body  = 'grant_type=client_credentials&client_id=id&client_secret=secret';
        $basic = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('id:secret')];
        $colon = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('id:se:cret')];

        yield from [
            'body credentials'           => ["{$body}&scope=a", [], $form, [], 'id', 'secret', 'a', false],
            'basic credentials'          => ['grant_type=client_credentials&scope=a+b', $basic, $form, [], 'id', 'secret', 'a b', true],
            'a colon in a basic secret'  => ['grant_type=client_credentials', $colon, $form, [], 'id', 'se:cret', null, true],
            'a media type in any case'   => [$body, [], $mixed, [], 'id', 'secret', null, false],
            'another query parameter'    => [$body, [], $form, ['page' => '2'], 'id', 'secret', null, false],
            'another parameter repeated' => ["{$body}&x=1&x=2", [], $form, [], 'id', 'secret', null, false],
        ];
    }

    /**
     * A request in form presents its client, scope and how it authenticated;
     * the media type is matched without regard to case or spaces, and anything
     * outside the four parameters is ignored.
     *
     * @param  string  $body
     * @param  array<string, string>  $server
     * @param  string  $type
     * @param  array<string, string>  $query
     * @param  string  $id
     * @param  string  $secret
     * @param  ?string  $scope
     * @param  bool  $basic
     * @return void
     */
    #[DataProvider('provideClients')]
    public function testReadsAClientInForm(
        string $body,
        array $server,
        string $type,
        array $query,
        string $id,
        #[\SensitiveParameter]
        string $secret,
        ?string $scope,
        bool $basic,
    ): void {
        $request = self::request($body, $server, $type);

        $request->query->add($query);

        $presented = ClientCredentialsRequest::read($request);

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertSame([$id, $secret, $scope, $basic], [$presented->clientId, $presented->clientSecret(), $presented->scope, $presented->basic]);
    }

    /**
     * Rows of `[body, server, content type, method, error]`.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>, 2: string, 3: string, 4: string}>
     */
    public static function provideRefusedRequests(): iterable
    {
        $form  = 'application/x-www-form-urlencoded';
        $body  = 'grant_type=client_credentials&client_id=id&client_secret=secret';
        $basic = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('id:secret')];

        yield from [
            'a GET'                 => [$body, [], $form, 'GET', 'invalid_request'],
            'a JSON body'           => [$body, [], 'application/json', 'POST', 'invalid_request'],
            'a multipart body'      => [$body, [], 'multipart/form-data', 'POST', 'invalid_request'],
            'no content type'       => [$body, [], '', 'POST', 'invalid_request'],
            'an empty body'         => ['', [], $form, 'POST', 'invalid_request'],
            'a parameter twice'     => ["{$body}&scope=a&scope=b", [], $form, 'POST', 'invalid_request'],
            'an encoded repeat'     => ["{$body}&client%5Fid=id", [], $form, 'POST', 'invalid_request'],
            'a dotted repeat'       => ["client.id=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'a spaced repeat'       => ["client+id=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'a padded repeat'       => ["+client_id=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'a list then a value'   => ["client_id[]=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'an unclosed bracket'   => ["client[id=a&{$body}", [], $form, 'POST', 'invalid_request'],
            'a list'                => ["{$body}&scope[]=a", [], $form, 'POST', 'invalid_request'],
            'no grant'              => ['client_id=id&client_secret=secret', [], $form, 'POST', 'invalid_request'],
            'another grant'         => ['grant_type=password&client_id=id&client_secret=secret', [], $form, 'POST', 'unsupported_grant_type'],
            'basic and a body id'   => ['grant_type=client_credentials&client_id=id', $basic, $form, 'POST', 'invalid_request'],
            'basic and a secret'    => ['grant_type=client_credentials&client_secret=s', $basic, $form, 'POST', 'invalid_request'],
            'no client'             => ['grant_type=client_credentials', [], $form, 'POST', 'invalid_client'],
            'only a secret'         => ['grant_type=client_credentials&client_secret=s', [], $form, 'POST', 'invalid_client'],
            'basic not base64'      => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic %%%'], $form, 'POST', 'invalid_client'],
            'basic without a colon' => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('idsecret')], $form, 'POST', 'invalid_client'],
            'basic alone'           => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Basic'], $form, 'POST', 'invalid_client'],
            'a bearer instead'      => ['grant_type=client_credentials', ['HTTP_AUTHORIZATION' => 'Bearer token'], $form, 'POST', 'invalid_client'],
        ];
    }

    /**
     * A request not in form is refused with its RFC 6749 error.
     *
     * @param  string  $body
     * @param  array<string, string>  $server
     * @param  string  $type
     * @param  string  $method
     * @param  string  $error
     * @return void
     */
    #[DataProvider('provideRefusedRequests')]
    public function testRefusesARequestNotInForm(string $body, array $server, string $type, string $method, string $error): void
    {
        self::assertSame($error, ClientCredentialsRequest::read(self::request($body, $server, $type, $method)));
    }

    /**
     * Any parameter in the query string is refused, the body's included.
     *
     * @return void
     */
    public function testRefusesAParameterInTheQueryString(): void
    {
        foreach (['grant_type', 'scope', 'client_id', 'client_secret'] as $name) {
            $request = self::request('grant_type=client_credentials&client_id=id&client_secret=secret');

            $request->query->set($name, 'x');

            self::assertSame('invalid_request', ClientCredentialsRequest::read($request), $name);
        }
    }

    /**
     * Each parameter given again under a name PHP cuts at a NUL byte is a
     * repeat, refused like any other, even with the same value.
     *
     * @return void
     */
    public function testRefusesARepeatUnderANameCutAtANulByte(): void
    {
        $body = 'grant_type=client_credentials&client_id=id&client_secret=secret&scope=a';

        foreach (['grant_type' => 'client_credentials', 'scope' => 'a', 'client_id' => 'id', 'client_secret' => 'secret'] as $name => $value) {
            self::assertSame('invalid_request', ClientCredentialsRequest::read(self::request("{$body}&{$name}%00x={$value}")), $name);
        }

        self::assertInstanceOf(PresentedClient::class, ClientCredentialsRequest::read(self::request("{$body}&extra%00x=1")));
    }

    /**
     * Rows of `[body, parameters, result]`: bodies read where
     * `arg_separator.input` is `&;`, with the parameters PHP's form parser,
     * which splits only on `&`, reads from them.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>, 2: string}>
     */
    public static function provideBodiesUnderAnotherSeparator(): iterable
    {
        $body       = 'grant_type=client_credentials&client_id=id&client_secret=secret';
        $parameters = ['grant_type' => 'client_credentials', 'client_id' => 'id', 'client_secret' => 'secret'];

        yield from [
            'a separator in a value' => ["{$body}&scope=read;client_id=x", $parameters + ['scope' => 'read;client_id=x'], '["id","read;client_id=x"]'],
            'a repeat'               => ["{$body}&scope=a&scope=b", $parameters + ['scope' => 'b'], 'invalid_request'],
            'a repeat cut at NUL'    => ["{$body}&client_id%00x=id", $parameters, 'invalid_request'],
        ];
    }

    /**
     * Repeats are found among the pairs a form body is split into on `&` alone,
     * whatever else `arg_separator.input` splits a query string on.
     *
     * @param  string  $body
     * @param  array<string, string>  $parameters
     * @param  string  $result
     * @return void
     */
    #[DataProvider('provideBodiesUnderAnotherSeparator')]
    public function testFindsRepeatsAsAFormBodyIsSplit(string $body, array $parameters, string $result): void
    {
        $autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
        $process  = new Process([PHP_BINARY, '-d', 'arg_separator.input=&;', '-r', self::READER, '--', $autoload, $body, json_encode($parameters, JSON_THROW_ON_ERROR)]);

        $process->mustRun();

        self::assertSame($result, $process->getOutput());
    }

    /**
     * A parameter whose value is `null` (an empty one after Laravel's
     * middleware) is absent, and anything outside the four parameters is
     * ignored.
     *
     * @return void
     */
    public function testANullParameterIsAbsentAndOthersAreIgnored(): void
    {
        $request = self::request('grant_type=client_credentials&client_id=id&client_secret=secret&scope=&extra[]=1');

        $request->request->set('scope', null);

        $presented = ClientCredentialsRequest::read($request);

        self::assertInstanceOf(PresentedClient::class, $presented);
        self::assertNull($presented->scope);
    }

    /**
     * Only an Authorization header with the Basic scheme counts as Basic.
     *
     * @return void
     */
    public function testRecognisesTheBasicScheme(): void
    {
        self::assertTrue(ClientCredentialsRequest::usesBasic(self::request('', ['HTTP_AUTHORIZATION' => 'Basic abc'])));
        self::assertTrue(ClientCredentialsRequest::usesBasic(self::request('', ['HTTP_AUTHORIZATION' => 'BASIC'])));
        self::assertFalse(ClientCredentialsRequest::usesBasic(self::request('', ['HTTP_AUTHORIZATION' => 'Basically abc'])));
        self::assertFalse(ClientCredentialsRequest::usesBasic(self::request('', ['HTTP_AUTHORIZATION' => 'Bearer abc'])));
        self::assertFalse(ClientCredentialsRequest::usesBasic(self::request('', ['HTTP_AUTHORIZATION' => 'Bearer Basic abc'])));
        self::assertFalse(ClientCredentialsRequest::usesBasic(self::request('')));
    }

    /**
     * The reader holds no state and cannot be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ClientCredentialsRequest::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ClientCredentialsRequest::class, $instance);
    }

    /**
     * A request with the body, parsed as PHP parses a form, and kept raw.
     *
     * @param  string  $body
     * @param  array<string, string>  $server
     * @param  string  $type
     * @param  string  $method
     * @return \Illuminate\Http\Request
     */
    private static function request(string $body, array $server = [], string $type = 'application/x-www-form-urlencoded', string $method = 'POST'): Request
    {
        parse_str($body, $parameters);

        return Request::create('/oauth/token', $method, $method === 'POST' ? $parameters : [], [], [], ['CONTENT_TYPE' => $type, ...$server], $body);
    }
}
