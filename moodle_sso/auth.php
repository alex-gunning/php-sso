<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * MOODLE SSO Plugin: Does Single Sign-On with an arbitrary system.
 * Uses CURL to authenticate the username and password combination against
 * and arbitrary database. Serves the returned cookie to the user's browser.
 *
 * @package    auth_moodle_sso
 * @copyright  2015 onwards Alex Gunning (https://github.com/alex-gunning/)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');

/**
 * SSO authentication plugin.
 *
 * @package    auth_moodle_sso
 * @subpackage manual
 * @copyright  2015 onwards Alex Gunning (https://github.com/alex-gunning/)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class auth_plugin_moodle_sso extends auth_plugin_base {

    private $loginform_action; //Action attribute of the remote login form
    private $logout_url; //Logout URL of the remote login form
    private $username_field; //Field name (username) of the remote login form
    private $password_field; //Field name (password) of the remote login form


    /**
     * Constructor.
     */
    function auth_plugin_moodle_sso() {
        global $DB;

        $this->authtype = 'moodle_sso';
        $this->config = get_config('auth/moodle_sso');

        $this->loginform_action = $DB->get_record("moodle_sso_plugin", array("id" => 1))->value;
        $this->logout_url = $DB->get_record("moodle_sso_plugin", array("id" => 2))->value;
        $this->username_field = $DB->get_record("moodle_sso_plugin", array("id" => 3))->value;
        $this->password_field = $DB->get_record("moodle_sso_plugin", array("id" => 4))->value;

        $this->username_field = ($this->username_field ? $this->username_field : "username");
        $this->password_field = ($this->password_field ? $this->password_field : "password");
    }

    /**
     * Post authentication hook.
     * This method is called from authenticate_user_login() for all enabled auth plugins.
     *
     * @param object $user user object, later used for $USER
     * @param string $username (with system magic quotes)
     * @param string $password plain text password (with system magic quotes)
     */
    function user_authenticated_hook(&$user, $username, $password) {

        //die($this->loginform_action);
        $ch = curl_init($this->loginform_action);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $this->username_field.'='.$username.'&'.$this->password_field.'='.$password);

        $result = curl_exec($ch);
        
        preg_match_all('/^Set-Cookie:\s*([^\r\n]*)/mi', $result, $ms);
        
        $cookies = array();
        foreach ($ms[1] as $m) {
            list($name, $value) = explode('=', $m, 2);    
            $cookies[$name] = (stripos($value, 'path=') ? array("location" => substr(stristr($value, 'path='), 5),
                                                                "value" => substr($value, 0, strpos($value, 'path=')-2)) : substr($value, 0, -1));
        }
        
        foreach($cookies as $name=>$value) {
            if(is_array($value)) {
                setcookie($name, $value['value'], 0, $value['location']);
            } else {
                setcookie($name, $value, 0);
            }
        }
    }

    function prevent_local_passwords() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return true;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return true;
    }

    /**
     * Returns true if plugin can be manually set.
     *
     * @return bool
     */
    function can_be_manually_set() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $config An object containing all the data for this page.
     * @param string $error
     * @param array $user_fields
     * @return void
     */
    function config_form($config, $err, $user_fields) {
        include 'config.html';
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param array $config
     * @return void
     */
    function process_config($config) {
        return true;
    }

   /**
    * Confirm the new user as registered. This should normally not be used,
    * but it may be necessary if the user auth_method is changed to manual
    * before the user is confirmed.
    *
    * @param string $username
    * @param string $confirmsecret
    */
    function user_confirm($username, $confirmsecret = null) {
        global $DB;

        $user = get_complete_user_data('username', $username);

        if (!empty($user)) {
            if ($user->confirmed) {
                return AUTH_CONFIRM_ALREADY;
            } else {
                $DB->set_field("user", "confirmed", 1, array("id"=>$user->id));
                if ($user->firstaccess == 0) {
                    $DB->set_field("user", "firstaccess", time(), array("id"=>$user->id));
                }
                return AUTH_CONFIRM_OK;
            }
        } else  {
            return AUTH_CONFIRM_ERROR;
        }
    }

}


