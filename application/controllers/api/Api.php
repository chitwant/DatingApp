<?php
defined('BASEPATH') OR exit('No direct script access allowed');

require APPPATH . 'libraries/REST_Controller.php';
require APPPATH . 'libraries/Format.php';

class Api extends REST_Controller
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
		$this->load->library('email');
		$this->load->model('api/api_model', 'api_model');
		$this->load->model('api/authorization_codes_model');
		$this->load->model('api/access_tokens_model');
	}

	/**
	 * Register function
	 * 
	 * This function is called to register a user.
	 * 
	 * @access 			public
	 * @param        	void
	 * @author 			Prosanjeet Adhikary
	 */
	public function register_post()
	{
		$array['username'] = strtolower($this->post('username'));
		$array['email'] = strtolower($this->post('email'));
		$array['password'] = hash('sha512', $this->post('password'));

		$error = [];

		if (!filter_var($array['email'], FILTER_VALIDATE_EMAIL)) {
			$error[] = 'Invalid email format.';
		}
		if (!preg_match('/^[A-Za-z][A-Za-z0-9]{5,100}$/', $array['username'])) {
			$error[] = 'Invalid username format. Only alphabets & numbers are allowed.';
		}

		if (!empty($error)) {
			$this->response(['status' => FALSE, 'error' => $error], REST_Controller::HTTP_BAD_REQUEST);
		}

		if (empty($array['username'])) {
			$this->response(['status' => FALSE, 'error' => 'Username is empty'], REST_Controller::HTTP_BAD_REQUEST);
		} else if (empty($array['email'])) {
			$this->response(['status' => FALSE, 'error' => 'Email is empty'], REST_Controller::HTTP_BAD_REQUEST);
		} else if (empty($array['password'])) {
			$this->response(['status' => FALSE, 'error' => 'Password is empty'], REST_Controller::HTTP_BAD_REQUEST);
		} else {
			$data = $this->api_model->register($array);
			if ($data === FALSE) {
				$this->response(['status' => FALSE, 'error' => 'Email or username already registered.'], REST_Controller::HTTP_BAD_REQUEST);
			} else {
				$this->response(['status' => TRUE, 'message' => 'Account registered successfully.'], REST_Controller::HTTP_OK);
			}
		}
	}

	/**
	 * Login function
	 * 
	 * This function is called for checking user credentials and login.
	 * 
	 * @access 			public
	 * @param        	void
	 * @author 			Prosanjeet Adhikary
	 */
	public function login_post()
	{
		$array['username'] = strtolower($this->post('username'));
		$array['password'] = hash('sha512', $this->post('password'));

		$error = [];

		if (filter_var($array['username'], FILTER_VALIDATE_EMAIL) 
			OR preg_match('/^[A-Za-z][A-Za-z0-9]{5,100}$/', $array['username'])) {

			if (empty($array['username'])) {
				$this->response(['status' => FALSE, 'error' => 'Username is empty'], REST_Controller::HTTP_BAD_REQUEST);
			} else if (empty($array['password'])) {
				$this->response(['status' => FALSE, 'error' => 'Password is empty'], REST_Controller::HTTP_BAD_REQUEST);
			} else {
				$data = $this->api_model->login($array);
				$auth_code = $this->createAuthorizationCode($data->id);
	        	$is_auth_code_valid = (new Authorization_codes_model)->isValid($auth_code->code);
		        if (!$is_auth_code_valid) {
		            $this->response(['status' => FALSE, 'error' => ['Invalid Authorization Code.']], REST_Controller::HTTP_BAD_REQUEST);
		        }

	        	$accesstoken = $this->createAccesstoken($auth_code->code);

				if (empty($data)) {
					$this->response(['status' => FALSE, 'error' => ['Username or password is incorrect']], REST_Controller::HTTP_BAD_REQUEST);
				} else {
					$result = array(
						'user_id' => (int) $data->id,
						'username' => $data->username,
						'email' => $data->email,
						'access_token' => $accesstoken->token,
					);

					$this->response(['status' => TRUE, 'message' => 'Login successful.', 'user_details' => $result], REST_Controller::HTTP_OK);
				}
			}
		} else {
			$error[] = 'Invalid username format.';
			$this->response(['status' => FALSE, 'error' => $error], REST_Controller::HTTP_BAD_REQUEST);
		}
	}

	/**
	 * Forgot Password function
	 * 
	 * This function is called to reset user password.
	 * 
	 * @access 			public
	 * @param        	void
	 * @author 			Prosanjeet Adhikary
	 */
	public function forgot_password_post()
	{
		$array['username'] = strtolower($this->post('username'));

		$error = [];

		if (filter_var($array['username'], FILTER_VALIDATE_EMAIL) 
			OR preg_match('/^[A-Za-z][A-Za-z0-9]{5,100}$/', $array['username'])) {

			if (empty($array['username'])) {
				$this->response(['status' => FALSE, 'error' => 'Username is empty'], REST_Controller::HTTP_BAD_REQUEST);
			} else {
				$validate_user = $this->api_model->validate_user($array['username'], $array['username']);
				
				if ($validate_user) {
					$new_password = $this->get_random_string();
					$update_user = $this->api_model->update_password($validate_user, $new_password);
					if ($update_user) {
						$send_email = $this->send_email($validate_user['email'], $new_password);
						if ($send_email) {
							$this->response(['status' => TRUE, 'message' => 'New password sent to email'], REST_Controller::HTTP_OK);
						} else {
							$this->response(['status' => FALSE, 'error' => ['Something went wrong']], REST_Controller::HTTP_BAD_REQUEST);
						}
					} else {
						$this->response(['status' => FALSE, 'error' => ['Password update failed']], REST_Controller::HTTP_BAD_REQUEST);
					}
				} else {
					$this->response(['status' => FALSE, 'error' => ['Username or email is incorrect']], REST_Controller::HTTP_BAD_REQUEST);
				}
			}
		} else {
			$error[] = 'Invalid username format.';
			$this->response(['status' => FALSE, 'error' => $error], REST_Controller::HTTP_BAD_REQUEST);
		}
	}

	/**
	 * Get Random String function
	 * 
	 * This function is called to generate a random string.
	 * 
	 * @access 			private
	 * @param        	string $length
	 * @return 			string
	 * @author 			Prosanjeet Adhikary
	 */
	private function get_random_string($length = 10)
	{
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$string = '';

		for ($i = 0; $i < $length; $i++) {
			$string .= $characters[mt_rand(0, strlen($characters) - 1)];
		}

		return $string;
	}

	/**
	 * Send Email function
	 * 
	 * This function is called to send email to the user.
	 * 
	 * @access 			public
	 * @param        	string $email
	 * @param        	string $new_password
	 * @return 			bool
	 * @author 			Prosanjeet Adhikary
	 */
	public function send_email($email, $new_password)
	{

		$config = [
            'protocol' => 'smtp',
            'smtp_host' => 'ssl://smtp.googlemail.com',
            'smtp_port' => 465,
            'smtp_user' => 'esetnod32av.008@gmail.com',
            'smtp_pass' => 'websoftq',
            'mailtype' => 'html',
            'charset' => 'iso-8859-1',
            'wordwrap' => TRUE
        ];

		$to = $email;
		$subject = 'New password generated';

		$message = '<html>
						<body>
							<p>Hi ' . $email . ',</p>
							<p>Your password has been updated. Please use <b>' . $new_password . '</b> to login.</p>
							<p><b>Regards</b></p>
							<p>WEBSOFT</p>
						</body>
					</html>';

		// $this->email->clear();
		$this->email->initialize($config);
		$this->email->set_newline("\r\n");

		$this->email->to($to);
		$this->email->from('noreply@websoft.com', 'Websoft');
		$this->email->subject($subject);
		$this->email->message($message);

		return $this->email->send();
	}

	public function createAuthorizationCode($user_id)
    {
        $model = new Authorization_codes_model;
        $model->code = bin2hex(random_bytes(128));
        $model->expires_at = time() + (60 * 5);
        $model->user_id = $user_id;

        if (isset($_SERVER['HTTP_X_WEBSOFT_APPLICATION_ID']))
            $app_id = $_SERVER['HTTP_X_WEBSOFT_APPLICATION_ID'];
        else
            $app_id = null;

        $model->app_id = $app_id;
        $model->created_at = date('Y-m-d H:i:s');
        $model->updated_at = date('Y-m-d H:i:s');
        $model->save();

        return ($model);

    }

    public function createAccesstoken($authorization_code)
    {

        $auth_code = (new Authorization_codes_model)->findOne(['code' => $authorization_code]);

        $model = new Access_tokens_model();
        $model->token = bin2hex(random_bytes(128));
        $model->auth_code = $auth_code->code;
        $model->expires_at = time() + (60 * 60 * 24 * 60); // 60 days
        $model->user_id = $auth_code->user_id;
        $model->created_at = date('Y-m-d H:i:s');
        $model->updated_at = date('Y-m-d H:i:s');
        $model->save();

        return ($model);

    }
}
