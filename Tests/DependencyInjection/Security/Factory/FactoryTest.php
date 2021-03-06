<?php

namespace Escape\WSSEAuthenticationBundle\Tests\DependencyInjection\Security\Factory;

use Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function getPosition()
    {
        $factory = new Factory();
        $result = $factory->getPosition();
        $this->assertEquals('pre_auth', $result);
    }

    /**
     * @test
     */
    public function getKey()
    {
        $factory = new Factory();
        $result = $factory->getKey();
        $this->assertEquals('wsse', $result);
        $this->assertEquals('wsse', $this->getFactory()->getKey());
    }

    protected function getFactory()
    {
        return $this->getMockForAbstractClass('Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory\Factory', array());
    }

    public function testCreate()
    {
        $factory = $this->getFactory();

        $container = new ContainerBuilder();
        $container->register('escape_wsse_authentication.provider');

        $nonce_dir = 'nonce';
        $lifetime = 300;
        $realm = 'TheRealm';
        $profile = 'TheProfile';

        list($authProviderId,
             $listenerId,
             $entryPointId
        ) = $factory->create(
            $container,
            'foo',
            array(
                'nonce_dir' => $nonce_dir,
                'lifetime' => $lifetime,
                'realm' => $realm,
                'profile' => $profile
            ),
            'user_provider',
            'entry_point'
        );

        //auth provider
        $this->assertEquals('escape_wsse_authentication.provider.foo', $authProviderId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.provider.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.provider.foo');
        $this->assertEquals(
            array(
                'index_0' => new Reference('user_provider'),
                'index_1' => $nonce_dir,
                'index_2' => $lifetime
            ),
            $definition->getArguments()
        );

        //listener
        $this->assertEquals('escape_wsse_authentication.listener.foo', $listenerId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.listener.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.listener.foo');
        $this->assertEquals(
            array(
                0 => new Reference($entryPointId)
            ),
            $definition->getArguments()
        );

        //entry point
        $this->assertEquals('escape_wsse_authentication.entry_point.foo', $entryPointId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.entry_point.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.entry_point.foo');
        $this->assertEquals(
            array(
                'index_1' => $realm,
                'index_2' => $profile
            ),
            $definition->getArguments()
        );
    }
}
