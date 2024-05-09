<?php

/**
 * This file is part of the JwtSessionBundle package.
 *
 * (c) Valérian Dorcy <valerian.dorcy@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 */

namespace Dorcyv\JwtSessionBundle\Session;

use Dorcyv\JwtSessionBundle\Cookie\CookieManager;
use Dorcyv\JwtSessionBundle\Jwt\JwtWrapper;
use Lcobucci\JWT\Token;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Session\Storage\Handler\AbstractSessionHandler;

/**
 * Class JwtSessionHandler
 */
class JwtSessionHandler extends AbstractSessionHandler
{
    /**
     * @var CookieManager
     */
    private $cookieManager;

    /**
     * @var JwtWrapper
     */
    private $jwtWrapper;

    /**
     * @var string
     */
    private $cookieName;

    /**
     * JwtSessionHandler constructor.
     *
     * @param CookieManager $cookieManager
     * @param JwtWrapper    $jwtWrapper
     */
    public function __construct(CookieManager $cookieManager, JwtWrapper $jwtWrapper)
    {
        $this->cookieManager = $cookieManager;
        $this->jwtWrapper = $jwtWrapper;
        $this->cookieName = 'jwt_session';
    }

    /**
     * {@inheritDoc}
     */
    public function close(): bool
    {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function gc($maxLifetime): bool
    {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * @throws \OutOfBoundsException
     * @throws \InvalidArgumentException
     * @throws \BadMethodCallException
     */
    public function updateTimestamp($sessionId, $session_data): bool
    {
        $token = $this->getToken();
        $this->jwtWrapper->updateExpiration($token, (int)ini_get('session.gc_maxlifetime'));

        $expiry = $token->getClaim('exp', 0);

        $parts = str_split((string)$token, 4000);

        foreach ($parts as $key => $part) {
            $this->cookieManager->addCookie(new Cookie($this->cookieName . $key, $part, $expiry, null, null, true, true));
        }
        $this->cookieManager->addCookie(new Cookie($this->cookieName . ($key + 1), '', $expiry, null, null, true, true));

        return true;
    }

    /**
     * @return Token
     *
     * @throws \BadMethodCallException
     */
    private function getToken(): Token
    {
        $tokenString = '';

        foreach (range(0, 100) as $i) {
            $cookie = $this->cookieManager->getCookie($this->cookieName . $i);

            if ($cookie && strlen($cookie->getValue()) > 0) {
                $tokenString .= $cookie->getValue();
            } else {
                break;
            }
        }

        if (!$tokenString) {
            return $this->jwtWrapper->createToken();
        }

        $token = $this->jwtWrapper->parse($tokenString);
        if ($token === null || !$this->jwtWrapper->isValid($token)) {

            return $this->jwtWrapper->createToken();
        }

        return $token;
    }

    /**
     * {@inheritDoc}
     * @throws \OutOfBoundsException
     * @throws \BadMethodCallException
     */
    protected function doRead($sessionId): string
    {
        $token = $this->getToken();

        return $token->getClaim('session', '');
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Exception
     */
    protected function doWrite($sessionId, $data): bool
    {
        $token = $this->getToken();
        $token = $this->jwtWrapper->updateClaim($token, 'session', $data);

        $expiry = $token->getClaim('exp', 0);

        $parts = str_split((string)$token, 4000);

        foreach ($parts as $key => $part) {
            $this->cookieManager->addCookie(new Cookie($this->cookieName . $key, $part, $expiry));
        }
        $this->cookieManager->addCookie(new Cookie($this->cookieName . ($key + 1), '', $expiry));

        return true;
    }

    /**
     * {@inheritDoc}
     *
     * @throws \InvalidArgumentException
     */
    protected function doDestroy($sessionId): bool
    {
        foreach (range(0, 100) as $i) {
            $this->cookieManager->addCookie(new Cookie($this->cookieName . $i));
        }

        return true;
    }
}
