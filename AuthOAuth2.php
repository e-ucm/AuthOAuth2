<?php

/* @version 1.5.0 */

require_once(__DIR__ . '/vendor/autoload.php');
use League\OAuth2\Client\Provider\GenericProvider;
use LimeSurvey\PluginManager\AuthPluginBase;
use LimeSurvey\PluginManager\LimesurveyApi;
use LimeSurvey\PluginManager\PluginEvent;
use LimeSurvey\PluginManager\PluginManager;


class AuthOAuth2 extends AuthPluginBase
{
    protected const SESSION_STATE_KEY = 'oauth_auth_state';

    protected $storage = 'DbStorage';
    protected static $name = 'OAuth2 Authentication';
    protected static $description = 'Enable Single Sign-On using OAuth2';

    protected $resourceData = [];

    /* @var array Check getPluginSettings */
    protected $settings = [];

    public function init(): void
    {
        $this->subscribe('beforeLogin');
        $this->subscribe('beforeLogout');
        $this->subscribe('newUserSession');
        $this->subscribe('newLoginForm');
        $this->subscribe('getGlobalBasePermissions');
    }

    /**
     * @see parent:getPluginSettings
     * @param mixed $getValues
     */
    public function getPluginSettings($getValues = true)
    {
        if (!Permission::model()->hasGlobalPermission('settings', 'read')) {
            throw new CHttpException(403);
        }
        /* Definition and default */
        $fixedPluginSettings = $this->getFixedGlobalSetting();
        $this->settings = [
            'client_id' => [
                'type' => 'string',
                'label' => $this->gT('Client ID'),
                'default' => $this->getGlobalSetting('client_id'),
                'htmlOptions' => [
                    'readonly' => in_array('client_id', $fixedPluginSettings)
                ]
            ],
            'client_secret' => [
                'type' => 'string',
                'label' => $this->gT('Client Secret'),
                'default' => $this->getGlobalSetting('client_secret'),
                'htmlOptions' => [
                    'readonly' => in_array('client_secret', $fixedPluginSettings)
                ]
            ],
            'redirect_uri' => [
                'type' => 'info',
                'label' => $this->gT('Redirect URI'),
                'content' => CHtml::tag(
                    'input',
                    [
                        'type' => 'text',
                        'class' => 'form-control',
                        'readonly' => true,
                        'value' => $this->api->createUrl('admin/authentication/sa/login', []),
                    ]
                ),
            ],
            'authorize_url' => [
                'type' => 'string',
                'label' => $this->gT('Authorize URL'),
                'default' => $this->getGlobalSetting('authorize_url'),
                'htmlOptions' => [
                    'readonly' => in_array('authorize_url', $fixedPluginSettings)
                ]
            ],
            'scopes' => [
                'type' => 'string',
                'label' => $this->gT('Scopes'),
                'help' => $this->gT('Comma-separated list of scopes to use for authorization.'),
                'default' => $this->getGlobalSetting('scopes'),
                'htmlOptions' => [
                    'readonly' => in_array('scopes', $fixedPluginSettings)
                ]
            ],
            'scope_separator' => [
                'type' => 'string',
                'label' => $this->gT('Scopes separator in URL'),
                'help' => $this->gT('Separate scopes in authorization URL.'),
                'default' => $this->getGlobalSetting('scope_separator', ','),
                'htmlOptions' => [
                    'readonly' => in_array('scope_separator', $fixedPluginSettings)
                ]
            ],
            'access_token_url' => [
                'type' => 'string',
                'label' => $this->gT('Access Token URL'),
                'default' => $this->getGlobalSetting('access_token_url', ''),
                'htmlOptions' => [
                    'readonly' => in_array('access_token_url', $fixedPluginSettings)
                ]
            ],
            'resource_owner_details_url' => [
                'type' => 'string',
                'label' => $this->gT('User Details URL'),
                'help' => $this->gT('URL to load the user details from using the retrieved access token.'),
                'default' => $this->getGlobalSetting('resource_owner_details_url', ''),
                'htmlOptions' => [
                    'readonly' => in_array('resource_owner_details_url', $fixedPluginSettings)
                ]
            ],
            'logout_url' => [
                'type' => 'string',
                'label' => $this->gT('Logout URL'),
                'default' => $this->getGlobalSetting('logout_url', ''),
                'htmlOptions' => [
                    'readonly' => in_array('logout_url', $fixedPluginSettings)
                ]
            ],
            'identifier_attribute' => [
                'type' => 'select',
                'label' => $this->gT('Identifier Attribute'),
                'help' => $this->gT('Attribute of the LimeSurvey user to match against.'),
                'options' => [
                    'username' => $this->gT('Username'),
                    'email' => $this->gT('E-Mail'),
                ],
                'default' => $this->getGlobalSetting('identifier_attribute', 'username'),
                'htmlOptions' => [
                    'disabled' => in_array('identifier_attribute', $fixedPluginSettings)
                ],
                'selectOptions' => [
                    'disabled' => in_array('identifier_attribute', $fixedPluginSettings)
                ]
            ],
            'username_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for username in user details'),
                'help' => $this->gT('Key for the username in the user details data. Only required if used as "Identifier Attibute" or if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('username_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('username_key', $fixedPluginSettings)
                ]
            ],
            'email_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for e-mail in user details'),
                'help' => $this->gT('Key for the e-mail in the user details data. Only required if used as "Identifier Attibute" or if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('email_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('email_key', $fixedPluginSettings)
                ]
            ],
            'display_name_key' => [
                'type' => 'string',
                'label' => $this->gT('Key for display name in user details'),
                'help' => $this->gT('Key for the full name in the user details data. Only required if "Create new users" is enabled.'),
                'default' => $this->getGlobalSetting('display_name_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('display_name_key', $fixedPluginSettings)
                ]
            ],
            'is_default' => [
                'type' => 'checkbox',
                'label' => $this->gT('Use as default login'),
                'help' => sprintf(
                    '%s<br>%s',
                    $this->gT('If enabled instead of showing the LimeSurvey login the user is redirected directly to the OAuth2 login. The default login form can always be accessed via:'),
                    htmlspecialchars($this->api->createUrl('admin/authentication/sa/login', ['authMethod' => 'Authdb']))
                ),
                'default' => $this->getGlobalSetting('is_default', false),
                'htmlOptions' => [
                    'disabled' => in_array('is_default', $fixedPluginSettings)
                ]
            ],
            'autocreate_users' => [
                'type' => 'checkbox',
                'label' => $this->gT('Create new users'),
                'help' => $this->gT('If enabled users that do not exist yet will be created in LimeSurvey after successfull login.'),
                'default' => $this->getGlobalSetting('autocreate_users', false),
                'htmlOptions' => [
                    'disabled' => in_array('autocreate_users', $fixedPluginSettings)
                ]
            ],
            'introduction_text' => [
                'type' => 'string',
                'label' => $this->gT('Introduction to the OAuth login button.'),
                'default' => $this->getGlobalSetting('introduction_text', ''),
                'htmlOptions' => [
                    'placeholder' => $this->gT('Login with OAuth2'),
                    'readonly' => in_array('introduction_text', $fixedPluginSettings)
                ]
            ],
            'button_text' => [
                'type' => 'string',
                'label' => $this->gT('Text on login button.'),
                'default' => $this->getGlobalSetting('button_text', ''),
                'htmlOptions' => [
                    'placeholder' => $this->gT('Login'),
                    'readonly' => in_array('button_text', $fixedPluginSettings)
                ]
            ],
            'key_separator' => [
                'type' => 'string',
                'label' => $this->gT('Separate key for user detail'),
                'help' => $this->gT('Separate key to get to the user details. Split key by dot notation by default.'),
                'default' => $this->getGlobalSetting('key_separator', '.'),
                'htmlOptions' => [
                    'readonly' => in_array('key_separator', $fixedPluginSettings)
                ]
            ],
            'word_separator' => [
                'type' => 'string',
                'label' => $this->gT('Separate word key for user detail'),
                'help' => $this->gT('Separate word key to get to the user details. Split word key by plus notation by default.'),
                'default' => $this->getGlobalSetting('word_separator', '+'),
                'htmlOptions' => [
                    'readonly' => in_array('word_separator', $fixedPluginSettings)
                ]
            ],
            'display_separator_username' => [
                'type' => 'string',
                'label' => $this->gT('Display separation if using for username in user details'),
                'help' => $this->gT('Separate word key for username. Split by dot notation by default.'),
                'default' => $this->getGlobalSetting('display_separator_username', '.'),
                'htmlOptions' => [
                    'readonly' => in_array('display_separator_username', $fixedPluginSettings)
                ]
            ],
            'display_separator_display_name' => [
                'type' => 'string',
                'label' => $this->gT('Display separation if using for display name in user details'),
                'help' => $this->gT('Separate word key for display name. Split by space notation by default.'),
                'default' => $this->getGlobalSetting('display_separator_display_name', ' '),
                'htmlOptions' => [
                    'readonly' => in_array('display_separator_display_name', $fixedPluginSettings)
                ]
            ],
            'debug' => [
                'type' => 'checkbox',
                'label' => $this->gT('Activate debugger'),
                'help' => $this->gT('Activate debugger'),
                'default' => $this->getGlobalSetting('debug', false),
                'htmlOptions' => [
                    'readonly' => in_array('debug', $fixedPluginSettings)
                ]
            ]
        ];

        if (method_exists(Permissiontemplates::class, 'applyToUser')) {
            $roles = [];
            foreach (Permissiontemplates::model()->findAll() as $role) {
                $roles[$role->ptid] = $role->name;
            }

            $this->settings['autocreate_roles'] = [
                'type' => 'select',
                'label' => $this->gT('Global roles for new users'),
                'help' => $this->gT('Global user roles to be assigned to users that are automatically created.'),
                'options' => $roles,
                'htmlOptions' => [
                    'multiple' => true,
                    'disabled' => in_array('autocreate_roles', $fixedPluginSettings)
                ],
                'default' => $this->getGlobalSetting('autocreate_roles', ''),
                'selectOptions' => [
                    'disabled' => in_array('autocreate_roles', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_key'] = [
                'type' => 'string',
                'label' => $this->gT('Key for roles in user detail'),
                'help' => $this->gT('Key to get the user roles. Must be an array, if roles exist : it was assigned to the user when it was created.'),
                'default' => $this->getGlobalSetting('roles_key', ''),
                'htmlOptions' => [
                    'readonly' => in_array('roles_key', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_update'] = [
                'type' => 'checkbox',
                'label' => $this->gT('Update roles at each log in'),
                'help' => $this->gT('Check and update roles each time an user log in.'),
                'default' => $this->getGlobalSetting('roles_update', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_update', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_needed'] = [
                'type' => 'checkbox',
                'label' => $this->gT('Need a minimum one role to allow log in or create user.'),
                'help' => $this->gT('If user didn\'t have any roles : disallow log in.'),
                'default' => $this->getGlobalSetting('roles_needed', false),
                'htmlOptions' => [
                    'disabled' => in_array('roles_needed', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_to_check'] = [
                'type' => 'string',
                'label' => $this->gT('Separated Roles Name List'),
                'help' => $this->gT('Separated Roles Name List to be compared with user role list. If one is present, allow login. If user didn\'t have at least one of the role : disallow log in. Default separator comma'),
                'default' => $this->getGlobalSetting('roles_to_check', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_to_check', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_to_check_separator'] = [
                'type' => 'string',
                'label' => $this->gT('Role name list separator'),
                'help' => $this->gT('Role name list separator. Default to comma'),
                'default' => $this->getGlobalSetting('roles_to_check_separator', ','),
                'htmlOptions' => [
                    'disabled' => in_array('roles_to_check_separator', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_removetext'] = [
                'type' => 'string',
                'label' => $this->gT('Allow you to remove specific string on the roles returned'),
                'help' => $this->gT('This string was removed to the roles returned before comparaison.'),
                'default' => $this->getGlobalSetting('roles_removetext', ''),
                'htmlOptions' => [
                    'readonly' => in_array('roles_removetext', $fixedPluginSettings)
                ]
            ];
            $this->settings['roles_insensitive'] = [
                'type' => 'checkbox',
                'label' => $this->gT('Insensitive comparaison for roles'),
                'help' => $this->gT('Do an insensitive comparaison before search the roles.'),
                'default' => $this->getGlobalSetting('roles_insensitive', ''),
                'htmlOptions' => [
                    'disabled' => in_array('roles_insensitive', $fixedPluginSettings)
                ]
            ];
        }

         $this->settings['auto_create_labelsets'] = array (
            'type' => 'string',
            'label' => '- Permissions: Label Sets',
            'default' => '',
            'help' => $this->gT('Comma-separated list of permissions to be set to true for label sets when a user is automatically created. Possible permissions are: create_p, read_p, update_p, delete_p, import_p, export_p.'),
            'htmlOptions' => [
                'disabled' => in_array('auto_create_labelsets', $fixedPluginSettings)
            ],
        );
        $this->settings['auto_create_participant_panel'] = array (
            'type' => 'string',
            'label' => '- Permissions: Participant panel',
            'default' => '',
            'help' => $this->gT('Comma-separated list of permissions to be set to true for participant panel when a user is automatically created. Possible permissions are: create_p, read_p, update_p, delete_p, import_p, export_p.'),
            'htmlOptions' => [
                'disabled' => in_array('auto_create_participant_panel', $fixedPluginSettings)
            ]
        );
        $this->settings['auto_create_settings_plugins'] = array (
            'type' => 'string',
            'label' => '- Permissions: Settings & Plugins',
            'default' => '',
            'help' => $this->gT('Comma-separated list of permissions to be set to true for settings & plugins when a user is automatically created. Possible permissions are: create_p, read_p, update_p, delete_p, import_p, export_p.'),
            'htmlOptions' => [
                'disabled' => in_array('auto_create_settings_plugins', $fixedPluginSettings)
            ]
        );
        $this->settings['auto_create_surveys'] = array (
            'type' => 'string',
            'label' => '- Permissions: Surveys',
            'default' => 'create_p,update_p,delete_p,export_p',
            'help' => $this->gT('Comma-separated list of permissions to be set to true for surveys when a user is automatically created. Possible permissions are: create_p, read_p, update_p, delete_p, import_p, export_p.'),
            'htmlOptions' => [
                'disabled' => in_array('auto_create_surveys', $fixedPluginSettings)
            ],
        );
        $this->settings['auto_create_templates'] = array (
            'type' => 'string',
            'label' => '- Permissions: Templates',
            'default' => 'create_p,update_p,delete_p,import_p,export_p',
            'help' => $this->gT('Comma-separated list of permissions to be set to true for templates when a user is automatically created. Possible permissions are: create_p, read_p, update_p, delete_p, import_p, export_p.'),
            'htmlOptions' => [
                'disabled' => in_array('auto_create_templates', $fixedPluginSettings)
            ],
        );
        $this->settings['auto_create_user_groups'] = array (
            'type' => 'string',
            'label' => '- Permissions: User groups',
            'default' => 'create_p,read_p,update_p,delete_p',
            'help' => $this->gT('Comma-separated list of permissions to be set to true for user groups when a user is automatically created. Possible permissions are: create_p, read_p, update_p, delete_p, import_p, export_p.'),
            'htmlOptions' => [
                'disabled' => in_array('auto_create_user_groups', $fixedPluginSettings)
            ],
        );
        /* Get current */
        $pluginSettings = parent::getPluginSettings($getValues);
        /* Update current for fixed one */
        if ($getValues) {
            foreach ($fixedPluginSettings as $setting) {
                $pluginSettings[$setting]['current'] = $this->getGlobalSetting($setting);
            }
        }
        /* Remove hidden */
        foreach ($this->getHiddenGlobalSetting() as $setting) {
            unset($pluginSettings[$setting]);
        }
        return $pluginSettings;
    }

    public function newLoginForm()
    {
        $oEvent = $this->getEvent();
        $introductionText = viewHelper::purified(trim($this->getGlobalSetting('introduction_text','')));
        if (empty($introductionText)) {
            $introductionText = $this->gT("Login with Oauth2");
        }
        $buttonText = viewHelper::purified(trim($this->getGlobalSetting('button_text', '')));
        if (empty($buttonText)) {
            $buttonText = $this->gT("Login");
        }
        $aData = [
            'introductionText' => $introductionText,
            'buttonText' => $buttonText,
        ];
        $authContent = $content = $this->renderPartial('admin.authentication.Oauth2LoginButton', $aData, true);
        $allFromsContent = $oEvent->getAllContent();
        foreach ($allFromsContent as $plugin => $content) {
            $oEvent->getContent($plugin)->addContent($authContent, 'prepend');
        }
    }

    /**
     * @throws CHttpException
     */
    public function beforeLogin()
    {
        $debug = (boolean)$this->getGlobalSetting('debug', false);
        
        $request = $this->api->getRequest();
        if ($error = $request->getParam('error')) {
            throw new CHttpException(401, $request->getParam('error_description', $error));
        }

        $provider = new GenericProvider([
            'clientId' => $this->getGlobalSetting('client_id'),
            'clientSecret' => $this->getGlobalSetting('client_secret'),
            'redirectUri' => $this->api->createUrl('admin/authentication/sa/login', []),
            'urlAuthorize' => $this->getGlobalSetting('authorize_url'),
            'urlAccessToken' => $this->getGlobalSetting('access_token_url'),
            'urlResourceOwnerDetails' => $this->getGlobalSetting('resource_owner_details_url'),
            'scopeSeparator' => $this->getGlobalSetting('scope_separator'),
            'scopes' => array_map(
                function ($scope) {
                    return trim($scope);
                },
                explode(',', $this->getGlobalSetting('scopes', ''))
            ),
        ]);

        $code = $request->getParam('code');
        $defaultAuth = $this->getGlobalSetting('is_default') ? self::class : null;
        if (empty($code) && $request->getParam('authMethod', $defaultAuth) !== self::class) {
            return;
        }

        if (empty($code)) {
            $authorizationUrl = $provider->getAuthorizationUrl();
            Yii::app()->session->add(self::SESSION_STATE_KEY, $provider->getState());

            $request->redirect($authorizationUrl);
        }

        $state = $request->getParam('state');
        $safedState = Yii::app()->session->get(self::SESSION_STATE_KEY);
        if ($state !== $safedState) {
            throw new CHttpException(400, $this->gT('Invalid state in OAuth response'));
        }

        Yii::app()->session->remove(self::SESSION_STATE_KEY);

        try {
            $accessToken = $provider->getAccessToken('authorization_code', ['code' => $code]);
            if($debug) {
                error_log("AccessToken : " . $accessToken);
            }
        } catch (Throwable $exception) {
            error_log($exception);
            throw new CHttpException(400, $this->gT('Failed to retrieve access token'));
        }
        Yii::app()->session['access_token']=$accessToken;

        try {
            $resourceOwner = $provider->getResourceOwner($accessToken);
            $this->resourceData = $resourceOwner->toArray();
        } catch (Throwable $exception) {
            error_log($exception);
            throw new CHttpException(400, $this->gT('Failed to retrieve user details'));
        }

        if ($this->getGlobalSetting('identifier_attribute') === 'email') {
            $identifierKey = $this->getGlobalSetting('email_key');
            $userIdentifier = $this->getFromResourceData($identifierKey);
        } else {
            $identifierKey = $this->getGlobalSetting('username_key');
            $identifierSeparator = $this->getGlobalSetting('display_separator_username', '.');
            $userIdentifier = $this->getTemplatedKey($identifierKey, $identifierSeparator);
        }

        if (empty($userIdentifier)) {
            throw new CHttpException(400, 'User identifier not found or empty');
        }
        $this->setUsername($userIdentifier);
        $this->setAuthPlugin();
    }

    /**
     * @throws CHttpException
     */
    public function newUserSession()
    {
        $userIdentifier = $this->getUserName();
        $identity = $this->getEvent()->get('identity');
        $hasRoleNeeded = false;
        if ($identity->plugin != self::class || $identity->username !== $userIdentifier) {
            return;
        }
        $oIdentityEvent = $this->getEvent();

        if ($this->getGlobalSetting('identifier_attribute') === 'email') {
            $user = $this->api->getUserByEmail($userIdentifier);
        } else {
            $user = $this->api->getUserByName($userIdentifier);
        }

        if (!$user && !$this->getGlobalSetting('autocreate_users')) {
            if ($this->getGlobalSetting('is_default')) {
                $this->beforeLogout();
                /* No way to connect : throw a 403 error (avoid looping) */
                throw new CHttpException(403, gT('Incorrect username and/or password!'));
            } else {
                $this->beforeLogout();
                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                return;
            }
        }
        if ($this->getGlobalSetting('roles_needed', false)  && $rolesKey = $this->getGlobalSetting('roles_key', '')) {
            $aRoles = $this->getFromResourceData($rolesKey);
            $debug = (boolean)$this->getGlobalSetting('debug', false);
            if($debug) {
                error_log("Data : " . json_encode($aRoles));
            }
            if (empty($aRoles)) {
                if ($this->getGlobalSetting('is_default')) {
                    $this->beforeLogout();
                    /* No way to connect : throw a 403 error (avoid looping) */
                    throw new CHttpException(403, gT('Incorrect username and/or password!'));
                } else {
                    $this->beforeLogout();
                    $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                    return;
                }
            }
        }
        if ($this->getGlobalSetting('roles_to_check', '') != '' && $rolesKey = $this->getGlobalSetting('roles_key', '')) {
            $aRoles = $this->getFromResourceData($rolesKey);
            $rolesToCheck=explode($this->getGlobalSetting('roles_to_check_separator', ','),$this->getGlobalSetting('roles_to_check', ''));
            
            $debug = (boolean)$this->getGlobalSetting('debug', false);
            if($debug) {
                error_log("Data : " . json_encode($aRoles));
                error_log("rolesToCheck : " . json_encode($rolesToCheck));
            }
            
            $incorrectRole=true;
            foreach ($rolesToCheck as $role) {
                if(in_array($role, $aRoles)) {
                    $incorrectRole=false;
                    $hasRoleNeeded = true;
                }
            }
            if ($incorrectRole) {
                $hasRoleNeeded = false;
                if ($this->getGlobalSetting('is_default')) {
                    $this->beforeLogout();
                    /* No way to connect : throw a 403 error (avoid looping) */
                    throw new CHttpException(403, gT('Incorrect role!'));
                } else {
                    $this->beforeLogout();
                    $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                    return;
                }
            }
        } else {
            $hasRoleNeeded = null;
        }
        if (!$user) {
            /* unregister to don't update event */
            $this->unsubscribe('getGlobalBasePermissions');

            $usernameKey = $this->getGlobalSetting('username_key');
            $usernameSeparator = $this->getGlobalSetting('display_separator_username', '.');
            $username = $this->getTemplatedKey($usernameKey, $usernameSeparator);
            $displayNameKey = $this->getGlobalSetting('display_name_key');
            $displayNameSeparator = $this->getGlobalSetting('display_separator_displayname', ' ');
            $displayName = $this->getTemplatedKey($displayNameKey, $displayNameSeparator);
            $emailKey = $this->getGlobalSetting('email_key');
            $email = $this->getFromResourceData($emailKey);

            $user = new User();
            $user->parent_id = 1;
            $user->setPassword(createPassword());

            $user->users_name = $username;
            $user->full_name = $displayName;
            $user->email = $email;

            if (!$user->save()) {
                throw new CHttpException(401, $this->gT('Failed to create new user'));
            }

            /* Add optional roles */
            if (method_exists(Permissiontemplates::class, 'applyToUser')) {
                $autocreateRoles = $this->getGlobalSetting('autocreate_roles');
                if (!empty($autocreateRoles)) {
                    foreach ($autocreateRoles as $role) {
                        Permissiontemplates::model()->applyToUser($user->uid, $role);
                    }
                }
                $this->setRolesToUser($user->uid, $hasRoleNeeded);
            }
            $this->setUsername($user->users_name);
            $this->setAuthSuccess($user, $oIdentityEvent);
        } else {
            /* Update roles if needed */
            if ($this->getGlobalSetting('roles_update', false)) {
                UserInPermissionrole::model()->deleteAll("uid = :uid", [':uid' => $user->uid]);
                $this->setRolesToUser($user->uid, $hasRoleNeeded);
            }
            /* Check for permission */
            if (!Permission::model()->hasGlobalPermission('auth_oauth2', 'read', $user->uid)) {
                /* Check if permission exist : if not create as true, else send error */
                $permissionnExist = Permission::model()->findByAttributes([
                    'entity_id' => 0,
                    'entity' => 'global',
                    'uid' => $user->uid,
                    'permission' => 'auth_oauth2'
                ]);
                if (empty($permissionnExist)) {
                    Permission::model()->setGlobalPermission($user->uid, 'auth_oauth2');
                } else {
                    if ($this->getGlobalSetting('is_default')) {
                        $this->beforeLogout();
                        /* No way to connect : throw a 403 error (avoid looping) */
                        throw new CHttpException(403, gT('Incorrect username and/or password!'));
                    } else {
                        $this->beforeLogout();
                        $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID);
                        return;
                    }
                }
            }
            $this->setUsername($user->users_name);
            $this->setAuthSuccess($user);
        }
    }

    /**
     * @throws CHttpException
     */
    public function beforeLogout(): void
    {
        $logoutUrl = $this->getGlobalSetting("logout_url");
        $clientId = $this->getGlobalSetting("client_id");
        $clientSecret = $this->getGlobalSetting("client_secret");
        
        $debug = (boolean)$this->getGlobalSetting('debug', false);

        if($debug) {
            error_log("LogoutUrl : " . $logoutUrl);
            error_log("clientid : " . $clientId);
            error_log(json_encode(Yii::app()->session));
        }
        $accessToken = Yii::app()->session['access_token'];
        if (!$accessToken) {
            return;
        }

        $refreshToken = $accessToken->getRefreshToken();
        if (!$refreshToken) {
            return;
        }

        if($debug) {
            error_log("AccessToken and RefreshToken presents.");
        }

        $postData = http_build_query([
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'refresh_token' => $refreshToken,
        ]);
        
        $headers = [
            'Authorization: Bearer ' . $accessToken,
            'Content-Type: application/x-www-form-urlencoded',
        ];
        
        $ch = curl_init($logoutUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        // Optionally log the response or check for errors 
        if (intval($httpCode / 100) !== 2) { // Ok for 200 201 204 etc
            error_log("Logout request failed: HTTP $httpCode - $response");
        }
        
        // Clear session data after logout
        Yii::app()->session->clear();
        Yii::app()->session->destroy();     
    }

    public function getGlobalBasePermissions(): void
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_oauth2' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => "Use OAuth2 authentication",
                'description' => "Use OAuth2 authentication",
                'img' => 'fa fa-user-circle-o'
            ),
        ));
    }

    /**
     * @param string $iKey
     * @param string $iSeparator
     * @return string
     */
    public function getTemplatedKey(string $iKey, string $iSeparator = '.'): string
    {
        $rValue = '';
        $keySeparator = $this->getGlobalSetting('key_separator', '.');
        $wordSeparator = $this->getGlobalSetting('word_separator', '+');
        if (str_contains($iKey, $keySeparator) || str_contains($iKey, $wordSeparator)) {
            $newUsernameKey = '';
            $sub_values = array_map(
                function ($sub_key) {
                    return $this->getFromResourceData($sub_key, true);
                },
                explode($wordSeparator, $iKey)
            );
            $rValue = join($iSeparator, $sub_values);
        } else {
            $rValue = $this->getFromResourceData($iKey);
        }
        return $rValue;
    }

    /**
     * @param string $key
     * @param bool $modifier
     * @return mixed
     */
    private function getFromResourceData(string $key, bool $modifier=false): mixed
    {
        $keySeparator = $this->getGlobalSetting('key_separator', '.');
        $keys = explode($keySeparator, $key); // Split key by dot notation
        $value = $this->resourceData;

        $debug = (boolean)$this->getGlobalSetting('debug', false);
        if($debug) {
            error_log("Data : " . json_encode($value));
            error_log("Keys : " . json_encode($keys));
        }
        
        foreach ($keys as $part) {
            if (!is_array($value)) {
                if($modifier) {
                    // Apply modifications if a known modifier exists
                    if ($part === 'first_letter') {
                        $value = join('', array_map(fn($word) => strtolower($word[0]), explode(' ', $value)));
                    } elseif ($part === 'capitalize') {
                        $value = ucfirst(strtolower($value));
                    } elseif ($part === 'upper_case') {
                        $value = strtoupper($value);
                    } elseif ($part === 'lower_case') {
                        $value = strtolower($value);
                    } else {
                        throw new CHttpException(401, $this->gT('User data or modifier is missing required attributes to create new user:') . $key);
                    }
                } else {
                    throw new CHttpException(401, $this->gT('User data is missing required attributes to create new user:') . $key);
                }
            } else {
                if (array_key_exists($part, $value)) {
                    $value = $value[$part]; // Move deeper into the array
                } else {
                    throw new CHttpException(401, $this->gT('User data is missing required attributes to create new user:') . $key);
                }
            }
        }
        if($debug) {
            error_log("Value : " . json_encode($value));
        }
        return $value;
    }

    /**
     * get settings according to current DB and fixed config.php
     * @param string $setting
     * @param mixed $default
     * @return mixed
     */
    private function getGlobalSetting($setting, $default = null)
    {
        $AuthOAuth2Settings = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Settings['fixed'][$setting])) {
            return $AuthOAuth2Settings['fixed'][$setting];
        }
        if (isset($AuthOAuth2Settings[$setting])) {
            return $this->get($setting, null, null, $AuthOAuth2Settings[$setting]);
        }
        return $this->get($setting, null, null, $default);
    }

    /**
     * Get the fixed settings name
     * @return string[]
     */
    private function getFixedGlobalSetting()
    {
        $AuthOAuth2Setting = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Setting['fixed'])) {
            return array_keys($AuthOAuth2Setting['fixed']);
        }
        return [];
    }

    /**
     * Get the hidden settings name
     * @return string[]
     */
    private function getHiddenGlobalSetting()
    {
        $AuthOAuth2Setting = App()->getConfig('AuthOAuth2Settings');
        if (isset($AuthOAuth2Setting['hidden'])) {
            return $AuthOAuth2Setting['hidden'];
        }
        return [];
    }

    /**
     * Set the roles using current settings
     * @param integer $userId
     * @param boolean $hasRoleNeeded
     */
    private function setRolesToUser($userId, $hasRoleNeeded = false)
    {
        $rolesKey = $this->getGlobalSetting('roles_key', '');
        if (!empty($rolesKey)) {
            $aRoles = $this->getFromResourceData($rolesKey);
            if (!empty($aRoles)) {
                $resetPermission = false;
                $aRoles = (array) $aRoles;
                foreach ($aRoles as $role) {
                    $rolesRemovetext = $this->getGlobalSetting('roles_removetext', '');
                    $role = str_replace($rolesRemovetext, '', $role);
                    $criteria = new CDbCriteria();
                    if ($this->getGlobalSetting('roles_insensitive', false)) {
                        $criteria->compare('LOWER(name)', strtolower($role), true);
                    } else {
                        $criteria->compare('name', $role, true);
                    }
                    $oRole = Permissiontemplates::model()->find($criteria);
                    if ($oRole) {
                        $resetPermission = true;
                        Permissiontemplates::model()->applyToUser($userId, $oRole->ptid);
                    }
                }
                error_log(sprintf("Roles %s checked to user %d", implode(', ', $aRoles), $userId));
                // Set the auth_oauth global permission to 0 (not used if have roles, but keep it at 1 for roles_needed
                $this->setOauthPermission($userId, $hasRoleNeeded);
            }
        }
    }
    /**
     * Set Oauth2 permission and assign default permissions to a new user.
     * @param integer $userId
     * @param boolean $allow
     */
    private function setOauthPermission($userId, $allow = true)
    {
        // 1. Set the auth_oauth2 global permission (controls login access)
        $oPermission = Permission::model()->find(
            "uid = :uid AND entity = :entity AND permission = :permission",
            [
                ':uid'        => $userId,
                ':entity'     => 'global',
                ':permission' => 'auth_oauth2',
            ]
        );
        if (!$oPermission) {
            $oPermission = new Permission();
            $oPermission->uid       = $userId;
            $oPermission->entity    = 'global';
            $oPermission->entity_id = 0;
            $oPermission->permission = 'auth_oauth2';
        }
        $oPermission->create_p = 0;
        $oPermission->read_p   = $allow ? 1 : 0;
        $oPermission->update_p = 0;
        $oPermission->delete_p = 0;
        $oPermission->import_p = 0;
        $oPermission->export_p = 0;
        $oPermission->save();

        // Only assign default permissions when allowing (i.e. new user creation)
        if (!$allow) {
            return;
        }

        // Delete any stale global permission records before reinserting
        foreach (['surveys', 'templates', 'usergroups', 'labelsets', 'participantpanel', 'settings'] as $perm) {
            Permission::model()->deleteAll(
                "uid = :uid AND entity = 'global' AND permission = :permission",
                [':uid' => $userId, ':permission' => $perm]
            );
        }
        // Also clean up template read permission to avoid duplicate on retry
        Permission::model()->deleteAll(
            "uid = :uid AND entity = 'template' AND permission = :permission",
            [':uid' => $userId, ':permission' => getGlobalSetting('defaulttheme')]
        );
        
        // 2. Default theme template read permission (mirrors SAML's insertSomeRecords)
        Permission::model()->insertSomeRecords([
            'uid'        => $userId,
            'permission' => getGlobalSetting('defaulttheme'),
            'entity_id'  => 0,
            'entity'     => 'template',
            'read_p'     => 1,
        ]);
        // 3. Set permissions: Label Sets
        $auto_create_labelsets = $this->getGlobalSetting('auto_create_labelsets', '');
        if (!empty($auto_create_labelsets)) {
            Permission::model()->setGlobalPermission($userId, 'labelsets', explode(',', $auto_create_labelsets));
        }

        // 4. Set permissions: Participant Panel
        $auto_create_participant_panel = $this->getGlobalSetting('auto_create_participant_panel', '');
        if (!empty($auto_create_participant_panel)) {
            Permission::model()->setGlobalPermission($userId, 'participantpanel', explode(',', $auto_create_participant_panel));
        }

        // 5. Set permissions: Settings & Plugins
        $auto_create_settings_plugins = $this->getGlobalSetting('auto_create_settings_plugins', '');
        if (!empty($auto_create_settings_plugins)) {
            Permission::model()->setGlobalPermission($userId, 'settings', explode(',', $auto_create_settings_plugins));
        }

        // 6. Set permissions: Surveys
        $auto_create_surveys = $this->getGlobalSetting('auto_create_surveys', 'create_p,read_p,update_p,delete_p,export_p');
        if (!empty($auto_create_surveys)) {
            Permission::model()->setGlobalPermission($userId, 'surveys', explode(',', $auto_create_surveys));
        }

        // 7. Set permissions: Templates
        $auto_create_templates = $this->getGlobalSetting('auto_create_templates', 'create_p,read_p,update_p,delete_p,import_p,export_p');
        if (!empty($auto_create_templates)) {
            Permission::model()->setGlobalPermission($userId, 'templates', explode(',', $auto_create_templates));
        }

        // 8. Set permissions: User Groups
        $auto_create_user_groups = $this->getGlobalSetting('auto_create_user_groups', 'create_p,read_p,update_p,delete_p');
        if (!empty($auto_create_user_groups)) {
            Permission::model()->setGlobalPermission($userId, 'usergroups', explode(',', $auto_create_user_groups));
        }
    }
}
