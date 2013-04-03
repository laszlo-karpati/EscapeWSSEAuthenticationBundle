[![Build Status](https://secure.travis-ci.org/escapestudios/EscapeWSSEAuthenticationBundle.png)](http://travis-ci.org/escapestudios/EscapeWSSEAuthenticationBundle)

## Introduction

The EscapeWSSEAuthentication bundle is a simple and easy way to implement WSSE authentication in Symfony2 applications.

I have taken this great bundle and made it usable with FOSUserBundle - At least you can use it in combination with FOSUserbundle, without compromising by having passwords in plaintext inyour db. It makes use of the standard symfony Encoder in exactly the same way that FOSUB does.

This can be achieved by using this ( still needs work..) security Controller in your own bundle.

 

## Installation

composer.json

```
"require": {
    ...
    "escapestudios/wsse-authentication-bundle": "2.2.x-dev",
    ...
}
```

app/AppKernel.php

```
public function registerBundles()
{
    return array(
        //...
        new Escape\WSSEAuthenticationBundle\EscapeWSSEAuthenticationBundle(),
        //...
    );
    ...
```

## Configuration

app/config/config.yml

```
# Escape WSSE authentication configuration
escape_wsse_authentication:
    authentication_provider_class: Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider
    authentication_listener_class: Escape\WSSEAuthenticationBundle\Security\Http\Firewall\Listener
    authentication_entry_point_class: Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint\EntryPoint
```

## Usage example

app/config/security.yml

nonce_dir: location where nonces will be saved (use null to skip nonce-validation)
lifetime: lifetime of nonce
realm: identifies the set of resources to which the authentication information will apply (WWW-Authenticate)
profile: WSSE profile (WWW-Authenticate)

```
firewalls:
    wsse_secured:
        pattern:   ^/api/.*
        wsse:      { nonce_dir: null, lifetime: 300, realm: "Secured API", profile: "UsernameToken" } 
```

##  bundle security controller


```
<?php
/**
 * Created by JetBrains PhpStorm.
 * User: hintt
 * Date: 01-04-13
 * File: ${File_NAME}
 */

namespace S2M\ProfileBundle\Controller;

use S2M\ProfileBundle\Entity\User;
use Nelmio\ApiDocBundle\Annotation\ApiDoc;
use FOS\RestBundle\Controller\Annotations\Prefix;
use FOS\RestBundle\Controller\Annotations\NamePrefix;
use FOS\RestBundle\View\RouteRedirectView;
use FOS\RestBundle\View\View AS FOSView;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;

/**
 * Controller that provides Restfuls security functions.
 *
 * @Prefix("/security")
 * @NamePrefix("mybundle_securityrest_")
 */
class WsseSecurityController extends Controller
{

    /**
     * POST WSSE Token generation
     *
     * returns token in this format:
     * UsernameToken Username=\"{$username}\", PasswordDigest=\"{$passwordDigest}\", Nonce=\"{$nonceHigh}\", Created=\"{$created}\"
     *
     * needs HTTP-HEADERs :
     *
     *  > Accept : application/json
     *
     *  > Content-Type : application/x-www-form-urlencoded
     *
     * ALSO NEEDS URL params:
     *
     * _username : myusername
     *
     * _password : mypassword
     *
     *  ie. something like this:
     *
     * http://mysite/app_dev.php/security/token/create?_username=myusername&_password=mypassword
     *
     * !
     * NOTE!: Part of this token will need to be passed in subsequent calls to the API, the part is in the X-WSSE http-header ie.
     *
     *  >  X-WSSE : UsernameToken Username=\"myname\", PasswordDigest=\"AAA=\", Nonce=\"AA==\", Created=\"2013-04-01T22:19:11+02:00\"
     *
     *
     * @return FOSView
     * @throws AccessDeniedException

     * @ApiDoc(
     *
     *  statusCodes={
     *         200="Returned when successful",
     *         403="Bad Credentials: User or Password"
     *      }
     * )
     */
    public function postTokenCreateAction()
    {

        $view = FOSView::create();
        $request = $this->getRequest();

        $username = $request->get('_username');
        $password = $request->get('_password');

        $um = $this->get('fos_user.user_manager');
        $user = $um->findUserByUsernameOrEmail($username);

        if (!$user instanceof User) {
            $view->setStatusCode(403)
            ->setData('Unknown User with {$username}');
            return $view;
        }

        $created = date('c');
        $nonce = substr(md5(uniqid('nonce_', true)), 0, 16);
        $nonceHigh = base64_encode($nonce);

        //slightly improved for use with FosUserBundle
        if (0 !== strlen($password)) {
            $encoder = $this->getEncoder($user);
            $passwordEncoded = $encoder->encodePassword($password, $user->getSalt());
        }

        $passwordDigest = base64_encode(sha1($nonce . $created . $passwordEncoded , true));

        $header = "UsernameToken Username=\"{$username}\", PasswordDigest=\"{$passwordDigest}\", Nonce=\"{$nonceHigh}\", Created=\"{$created}\"";
        $view->setHeader("Authorization", 'WSSE profile="UsernameToken"');
        $view->setHeader("X-WSSE", "UsernameToken Username=\"{$username}\", PasswordDigest=\"{$passwordDigest}\", Nonce=\"{$nonceHigh}\", Created=\"{$created}\"");
        $data = array('WSSE' => $header);

        $view->setStatusCode(200)->setData($data);
        return $view;
    }

    /**
     * WSSE Token Remove
     *
     * @return FOSView
     *
     * @ApiDoc(
     *  input="S2M\ProfileBundle\Form\UserType\profileKey",
     *  output="S2M\ProfileBundle\Entity\User",
     *  statusCodes={
     *         200="Returned when successful",
     *      }
     * )
     */
    public function getTokenDestroyAction()
    {
        $view = FOSView::create();
        $security = $this->get('security.context');
        $token = new AnonymousToken(null, new User());
        $security->setToken($token);
        $this->get('session')->invalidate();
        $view->setStatusCode(200)->setData('Logout successful');
        return $view;
    }



    protected function getEncoder(User $user)
    {
        $this->encoderFactory = $this->get('security.encoder_factory');
           return $this->encoderFactory->getEncoder($user);
    }
}

```

