<?php

declare(strict_types=1);

namespace Mautic\UserBundle\Tests\Functional\Mpass;

use Mautic\ConfigBundle\Model\SysinfoModel;

/**
 * Round-2 review, attack finding: the edge secret must not be readable through the app.
 */
final class MpassEdgeSecretTest extends AbstractMpassTestCase
{
    public function testSysinfoRendersNoPhpinfoUnderSso(): void
    {
        $phpInfo = (string) static::getContainer()->get(SysinfoModel::class)->getPhpInfo();

        self::assertStringContainsString(PHP_VERSION, $phpInfo, 'the version line only');
        self::assertStringNotContainsString('<table', $phpInfo, 'no phpinfo() tables');
        self::assertStringNotContainsString(self::EDGE_SECRET, $phpInfo);
    }

    public function testSysinfoPageDoesNotContainTheEdgeSecret(): void
    {
        $this->createUser('alice@example.com'); // admin role
        $response = $this->get('/s/sysinfo', 'alice@example.com');

        self::assertSame(200, $response->getStatusCode());
        self::assertStringNotContainsString(self::EDGE_SECRET, (string) $response->getContent());
    }

    public function testEdgeSecretIsReadFromTheFileTheImageWrites(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'mpass-edge-');
        file_put_contents($file, self::EDGE_SECRET."\n");
        self::setEnv('MPASS_EDGE_SECRET', null);
        $this->restartWithEnv('MPASS_EDGE_SECRET_FILE', $file);

        try {
            $this->createUser('alice@example.com');
            $this->assertServedAs('alice@example.com', $this->get('/s/account', 'alice@example.com'));

            $this->client->getCookieJar()->clear();
            self::assertSame(403, $this->get('/s/account', 'alice@example.com', ['HTTP_X_MPASS_EDGE_SECRET' => 'wrong'])->getStatusCode());
        } finally {
            unlink($file);
        }
    }
}
