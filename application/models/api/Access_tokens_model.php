<?php

defined('BASEPATH') or exit('No direct script access allowed');

// require APPPATH . 'libraries/REST_Controller.php';
// require APPPATH . 'libraries/Format.php';

/**
 * This is the model class for table "access_tokens".
 *
 * @property int $id
 * @property string $token
 * @property int $expires_at
 * @property string $auth_code
 * @property int $user_id
 * @property string $app_id
 * @property string $created_at
 * @property string $updated_at
 */
class Access_tokens_model extends CI_Model
{

    public $token;
    public $auth_code;
    public $expires_at;
    public $user_id;
    public $app_id;
    public $created_at;
    public $updated_at;

    public function save()
    {
        $this->db->insert('access_tokens', $this);
    }

    public function findIdentityByAccessToken($token, $type = null)
    {
        $access_token = $this->findOne(['token' => $token]);
        if ($access_token) {
            if ($access_token->expires_at < time()) {
                $this->response(['status' => FALSE, 'error' => ['Access token expired']], REST_Controller::HTTP_BAD_REQUEST);
            }
            
            return $this->db->select('id, username, email')
                    ->where(['id' => $access_token->user_id])
                    ->get('users')->row();
        } else {
            return (false);
        }
        //throw new NotSupportedException('"findIdentityByAccessToken" is not implemented.');
    }

    public function findOne($array)
    {
        $model = $this->db->select('*')
                ->where($array)
                ->get('access_tokens')
                ->row();

        return($model);
    }
}
