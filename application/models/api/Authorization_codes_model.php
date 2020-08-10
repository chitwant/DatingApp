<?php

defined('BASEPATH') or exit('No direct script access allowed');

// require APPPATH . 'libraries/REST_Controller.php';
// require APPPATH . 'libraries/Format.php';

/**
 * This is the model class for table "authorization_codes".
 *
 * @property int $id
 * @property string $code
 * @property int $expires_at
 * @property int $user_id
 * @property string $app_id
 * @property string $created_at
 * @property string $updated_at
 */
class Authorization_codes_model extends CI_Model
{

    public $code;
    public $expires_at;
    public $user_id;
    public $app_id;
    public $created_at;
    public $updated_at;

    public function isValid($code)
    {
        $model = $this->db->select('*')
                ->where(['code' => $code])
                ->get('authorization_codes')
                ->row();

        if(!$model||$model->expires_at<time())
        {
            $this->response(['status' => FALSE, 'error' => ['Authcode Expired']], REST_Controller::HTTP_BAD_REQUEST);
            return(false);
        }
        else
            return($model);
    }

    public function save()
    {
        $this->db->insert('authorization_codes', $this);
    }

    public function findOne($array)
    {
        $model = $this->db->select('*')
                ->where($array)
                ->get('authorization_codes')
                ->row();

        return($model);
    }
}
