<?php

use Mautic\UserBundle\Entity\Permission;
use Mautic\UserBundle\Entity\Role;
use Mautic\UserBundle\Entity\User;

// Mautic user/role admin for mPass SSO (no one has a password, so admins are managed here).
// Baked into the image at /opt/mautic-users.php; run it as www-data in the mautic container:
//   docker compose exec -u www-data mautic php /opt/mautic-users.php <command> [args]
// Uses Mautic's own models (no raw SQL on the bitwise permission table). Commands:
//   list
//   member-perms <marketer|contributor|viewer|none>  set the "mPass Member" role's permissions
//   ensure-member-role                     create "mPass Member" (marketer) if missing; print its id
//   grant-admin <email>...                 give the admin role (pre-creates the user if needed)
//   revoke-admin <email>...                back to the SSO default role (MPASS_SSO_DEFAULT_ROLE)

define('IN_MAUTIC_CONSOLE', 1);
define('MAUTIC_ROOT_DIR', '/var/www/html');
require MAUTIC_ROOT_DIR.'/autoload.php';
require MAUTIC_ROOT_DIR.'/app/config/bootstrap.php';

$kernel = new AppKernel($_SERVER['APP_ENV'] ?? 'prod', false);
$kernel->boot();
$c         = $kernel->getContainer();
$em        = $c->get('doctrine.orm.entity_manager');
$roleModel = $c->get('mautic.user.model.role');
$userModel = $c->get('mautic.user.model.user');

const MEMBER_ROLE = 'mPass Member';

// Same shape as the SSO authenticator's first-login provisioning.
function normalise(string $email): string
{
    $email = strtolower(trim($email));
    if (!str_contains($email, '@') || strlen($email) > 191) {
        fwrite(STDERR, "not an email: $email\n");
        exit(2);
    }

    return $email;
}

function findUser($em, string $email): ?User
{
    return $em->getRepository(User::class)->findOneBy(['email' => $email]);
}

function adminRole($em): Role
{
    $role = $em->getRepository(Role::class)->findOneBy(['isAdmin' => true, 'isPublished' => true], ['id' => 'ASC']);
    $role ?? exit("no published admin role\n");

    return $role;
}

function memberRole($em): Role
{
    $id   = getenv('MPASS_SSO_DEFAULT_ROLE');
    $role = $id ? $em->getRepository(Role::class)->find((int) $id) : $em->getRepository(Role::class)->findOneBy(['name' => MEMBER_ROLE]);
    if (!$role || $role->isAdmin()) {
        fwrite(STDERR, "SSO default role not found or is an admin role (MPASS_SSO_DEFAULT_ROLE=$id)\n");
        exit(1);
    }

    return $role;
}

$own  = ['viewown', 'viewother', 'editown', 'create', 'deleteown'];
$pub  = [...$own, 'publishown'];
$view = ['viewown', 'viewother'];
$permSets = [
    'none'     => [],
    'viewer'   => [
        'lead:leads'         => $view,
        'lead:lists'         => $view,
        'lead:notes'         => $view,
        'email:emails'       => $view,
        'campaign:campaigns' => $view,
        'form:forms'         => $view,
        'asset:assets'       => $view,
        'report:reports'     => $view,
    ],
    // Day-to-day marketing user: works on their own items, sees everyone's.
    // No users/roles/config/plugins/API/webhooks. Mirrors Chatwoot's "agent".
    'marketer' => [
        'user:profile'         => ['editname'],
        'lead:leads'           => $own,
        'lead:lists'           => $own,
        'lead:notes'           => $own,
        'email:emails'         => $pub,
        'campaign:campaigns'   => $pub,
        'form:forms'           => $pub,
        'asset:assets'         => $pub,
        'report:reports'       => $own,
        'category:categories'  => ['view'],
        'email:categories'     => ['view'],
        'campaign:categories'  => ['view'],
        'form:categories'      => ['view'],
        'asset:categories'     => ['view'],
    ],
];
// Marketer that drafts but cannot take anything live; an admin publishes.
$permSets['contributor'] = array_map(fn ($p) => array_values(array_diff($p, ['publishown'])), $permSets['marketer']);

[$cmd, $args] = [$argv[1] ?? 'list', array_slice($argv, 2)];

switch ($cmd) {
    case 'list':
        foreach ($em->getRepository(User::class)->findBy([], ['id' => 'ASC']) as $u) {
            printf("%-4d %-40s %-20s%s\n", $u->getId(), $u->getEmail(), $u->getRole()->getName(), $u->isAdmin() ? '  [admin]' : '');
        }
        break;

    case 'ensure-member-role':
        // Run by the entrypoint at every SSO boot. Creates the SSO default role with the
        // regular-member (marketer) set on first run only; later runs never touch
        // permissions an admin may have changed in the UI.
        $role = $em->getRepository(Role::class)->findOneBy(['name' => MEMBER_ROLE]);
        if (!$role) {
            $role = (new Role())
                ->setName(MEMBER_ROLE)
                ->setDescription('Default role for mPass SSO users: regular member (marketer).')
                ->setIsAdmin(false);
            $role->setIsPublished(true);
            $roleModel->setRolePermissions($role, $permSets['marketer']);
            $roleModel->saveEntity($role);
            echo "created role '".MEMBER_ROLE."' with the 'marketer' permission set\n";
        }
        echo MEMBER_ROLE." role id: {$role->getId()}\n";
        // Unset MPASS_SSO_DEFAULT_ROLE means this role, by name; only a set, different id is a problem.
        $id = (string) getenv('MPASS_SSO_DEFAULT_ROLE');
        if ('' !== $id && $id !== (string) $role->getId()) {
            fwrite(STDERR, "MPASS_SSO_DEFAULT_ROLE=$id names another role; unset it to use '".MEMBER_ROLE."'\n");
        }
        break;

    case 'member-perms':
        $set = $args[0] ?? '';
        isset($permSets[$set]) or exit('usage: member-perms <'.implode('|', array_keys($permSets)).">\n");
        $role = memberRole($em);
        $em->getRepository(Permission::class)->purgeRolePermissions($role);
        $em->refresh($role);
        $roleModel->setRolePermissions($role, $permSets[$set]);
        $roleModel->saveEntity($role);
        echo "role #{$role->getId()} '{$role->getName()}' now has the '$set' permission set\n";
        break;

    case 'grant-admin':
    case 'revoke-admin':
        $args or exit("usage: $cmd <email>...\n");
        $role = 'grant-admin' === $cmd ? adminRole($em) : memberRole($em);
        foreach ($args as $raw) {
            $email = normalise($raw);
            $user  = findUser($em, $email);
            if (!$user) {
                if ('revoke-admin' === $cmd) {
                    echo "$email: no such user, skipped\n";
                    continue;
                }
                // Pre-provision so the first SSO login finds this row; the
                // authenticator never re-roles an existing user.
                [$local, $domain] = explode('@', $email, 2);
                $user = (new User())
                    ->setUsername($email)
                    ->setEmail($email)
                    ->setFirstName($local)
                    ->setLastName($domain)
                    ->setPassword(password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT));
            }
            $user->setRole($role);
            $userModel->saveEntity($user);
            echo "$email -> {$role->getName()}\n";
        }
        break;

    default:
        exit("unknown command: $cmd (list | member-perms | grant-admin | revoke-admin)\n");
}
