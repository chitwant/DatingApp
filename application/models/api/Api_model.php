<?php
defined('BASEPATH') or exit('No direct script access allowed');

/**
 * Api Model Class
 * 
 * This class is used for database query purposes.
 * 
 * @package 		Codeigniter
 * @subpackage      Model
 * @category        Model
 * @author 			Prosanjeet Adhikary
 */
class Api_model extends CI_Model
{

	/**
	 * Constructor function
	 * 
	 * This is constructor function.
	 * 
	 * @access 			public
	 * @param        	void
	 * @author 			Prosanjeet Adhikary
	 */
	function __construct()
	{
		parent::__construct();
	}

	/**
	 * Register function
	 * 
	 * This function is called to register a user.
	 * 
	 * @access 			public
	 * @param        	array $array
	 * @return 			bool | string
	 * @author 			Prosanjeet Adhikary
	 */
	function register($array)
	{
		$data = $this->validate_user($array['username'], $array['email']);
		if (!empty($data)) {
			return FALSE;
		}

		$this->db->insert('users', $array);
		return $this->db->insert_id();
	}

	/**
	 * Validate User function
	 * 
	 * This function is called to validate user.
	 * 
	 * @access 			public
	 * @param        	string $username
	 * @param        	string $email
	 * @return 			array
	 * @author 			Prosanjeet Adhikary
	 */
	function validate_user($username, $email = '')
	{
		$data = $this->db->select('id, username, email')
			->where('username', $username)
			->or_where('email', $email)
			->get('users')->result_array();

		return $data;
	}

	/**
	 * Login function
	 * 
	 * This function is called for checking user credentials and login.
	 * 
	 * @access 			public
	 * @param        	array $array
	 * @return 			array
	 * @author 			Prosanjeet Adhikary
	 */
	function login($array)
	{
		$data = $this->db->select('id, username, email')
			->where('email', $array['username'])
			->or_where('username', $array['username'])
			->where('password', $array['password'])
			->get('users')->row();
		return $data;
	}

	/**
	 * Update Password function
	 * 
	 * This function is called to update password.
	 * 
	 * @access 			public
	 * @param        	array $user_details
	 * @param        	string $new_password
	 * @return 			bool | string
	 * @author 			Prosanjeet Adhikary
	 */
	function update_password($user_details, $new_password)
	{
		$array['password'] = hash('sha512', $new_password);
		return $this->db->where('id', $user_details->id)
			->update('users', $array);
	}

}
