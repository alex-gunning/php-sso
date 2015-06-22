<?php
/**
 * @package Wordpress-SSO
 */
/*
Plugin Name: Wordpress Single Sign-On
Description: Sign on to an arbitrary system with CRON using the same login credentials as Wordpress.
Version: 1.0.0
Author: <a href="https://github.com/alex-gunning">Alex Gunning</a>
License: GPLv2
Text Domain: moodle-sso
*/
/*  Copyright 2015  <a href="https://github.com/alex-gunning">Alex Gunning</a>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/


/**
 * Main plugin class
 *
 * @since 0.1
 **/
class WORDPRESS_SSO {

	private $options;


	public function __construct() {
		$this->options = get_option('WORDPRESS_SSO_options');
	}

	/**
	 * Build Administration Menu
	 *
	 * @since 0.1
	 **/
	public function admin_menu() {
		add_options_page("Wordpress Single Sign-On", "Wordpress SSO", "manage_options", "wordpress-sso", array("WORDPRESS_SSO", "wordpress_sso_options"));
	}

	public function wordpress_sso_options() {
		if ( !current_user_can( 'manage_options' ) )  {
			wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
		}
		echo '<div class="wrap">';
		echo '<h3>Wordpress Single Sign-On to an arbitrary system.</h3>';
		echo '<p>Uses CURL to authenticate a user on a remote system and passes the resulting session cookie to the user\'s browser.</p>';
		echo '<br/>';
		
		echo '<form action="options.php" method="post">';
		settings_fields('wordpress-sso-plugin-options');
		do_settings_sections('wordpress-sso-plugin');
		 
		submit_button();
		echo '</form>';
		echo '</div>';
	}

	public function plugin_admin_init() {

		add_settings_section('wordpress-sso-plugin-main', 'Remote System Settings', array($this, 'plugin_section_text'), 'wordpress-sso-plugin');
		add_settings_field('wordpress-sso-plugin-form-action-url', 'Login Action URL', array($this, 'plugin_setting_action'), 'wordpress-sso-plugin', 'wordpress-sso-plugin-main');
		add_settings_field('wordpress-sso-plugin-form-username-field', 'Field name [Username]', array($this, 'plugin_setting_username_field'), 'wordpress-sso-plugin', 'wordpress-sso-plugin-main');
		add_settings_field('wordpress-sso-plugin-form-password-field', 'Field name [Password]', array($this, 'plugin_setting_password_field'), 'wordpress-sso-plugin', 'wordpress-sso-plugin-main');
		register_setting( 'wordpress-sso-plugin-options', 'WORDPRESS_SSO_options');
	}

	function plugin_setting_action() {
		echo "<input id='plugin_url' name='WORDPRESS_SSO_options[url]' size='60' type='text' value='{$this->options['url']}' />";
	}

	function plugin_setting_username_field() {
		echo "<input id='plugin_username' name='WORDPRESS_SSO_options[username]' size='60' type='text' placeholder='username' value='{$this->options['username']}' />";
	}

	function plugin_setting_password_field() {
		echo "<input id='plugin_password' name='WORDPRESS_SSO_options[password]' size='60' type='text' placeholder='password' value='{$this->options['password']}' />";
	}


	public function plugin_section_text() {
		echo '<p>Settings for the remote login form to allow SSO. Username and Password are the text field names of the remote<br/>login form. (These can be left blank for most systems.)</p>';
	}


	/**
	 * Login via SSO
	 *
	 * @since 0.1
	 **/
	public function SSO_login($username, $password) {
	
		$username_field = ($this->options['username'] ? $this->options['username'] : "username");
		$password_field = ($this->options['password'] ? $this->options['password'] : "password");

		$ch = curl_init($this->options['url']);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_HEADER, 1);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $username_field.'='.$username.'&'.$password_field.'='.$password);

		$result = curl_exec($ch);

		
		preg_match_all('/^Set-Cookie:\s*([^\r\n]*)/mi', $result, $ms);
		
		$cookies = array();
		foreach ($ms[1] as $m) {
		    list($name, $value) = explode('=', $m, 2);    
            $cookies[] = array('name' => $name, 'content' => (stripos($value, 'path=') ? array("path" => substr(stristr($value, 'path='), 5),
                                                                "value" => substr($value, 0, strpos($value, 'path=')-2)) : substr($value, 0, -1)));
		}
		
		foreach($cookies as $cookie) {    
            if(is_array($cookie['content'])) {
                setcookie($cookie['name'], $cookie['content']['value'], 0, $cookie['content']['path']);
            } else {
                setcookie($name, $cookie['content']['value'], 0);
            }
        }


	}

	/**
	 * Logout via SSO
	 *
	 * @since 0.1
	 **/
	public function SSO_logout() {

	}

}

$SSO = new WORDPRESS_SSO();

add_action('wp_authenticate', array($SSO, 'SSO_login'), 10, 2);
add_action('admin_init', array($SSO, 'plugin_admin_init'));
add_action('admin_menu', array($SSO, 'admin_menu'));

