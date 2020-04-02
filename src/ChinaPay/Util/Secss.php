<?php

namespace ITPony\ChinaPay\Util;

use ITPony\ChinaPay\Exception;

// define('CP_SIGN_FILE', "sign.file");
// define('CP_SIGN_FILE_PASSWORD', "sign.file.password");
// define('CP_SIGN_CERT_TYPE', "sign.cert.type");
// define('CP_SIGN_INVALID_FIELDS', "sign.invalid.fields");
define('CP_VERIFY_FILE', "verify.file");
define('CP_SIGNATURE_FIELD', "signature.field");
define('CP_SUCCESS', "00");
define("CP_LOAD_CONFIG_ERROR", "01");
define("CP_SIGN_CERT_ERROR", "02");
define("CP_SIGN_CERT_PWD_ERROR", "03");
define("CP_SIGN_CERT_TYPE_ERROR", "04");
define("CP_INIT_SIGN_CERT_ERROR", "05");
define("CP_VERIFY_CERT_ERROR", "06");
define("CP_INIT_VERIFY_CERT_ERROR", "07");
define("CP_GET_PRI_KEY_ERROR", "08");
define("CP_GET_CERT_ID_ERROR", "09");
define("CP_GET_SIGN_STRING_ERROR", "10");
define("CP_SIGN_GOES_WRONG", "11");
define("CP_VERIFY_GOES_WRONG", "12");
define("CP_VERIFY_FAILED", "13");
define("CP_SIGN_FIELD_NULL", "14");
define("CP_SIGN_VALUE_NULL", "15");
define("CP_UNKNOWN_WRONG", "16");
define("CP_ENCPIN_GOES_WRONG", "17");
define("CP_ENCDATA_GOES_WRONG", "18");
define("CP_DECDATA_GOES_WRONG", "19");
define("CP_DEFAULTINIT_GOES_WRONG", "20");
define("CP_SPECIFYINIT_GOES_WRONG", "21");
define("CP_RELOADSC_GOES_WRONG", "22");
define("CP_NO_INIT", "23");
define("CP_CONFIG_WRONG", "24");
define("CP_INIT_CONFIG_WRONG", "25");
define("CP_KEY_VALUE_CONNECT", "=");
define("CP_MESSAGE_CONNECT", "&");
define("CP_SIGN_ALGNAME", "SHA512WithRSA");
define("CP_ENC_ALG_PREFIX", "RSA");
define("CP_CHARSET_COMM", "UTF-8");
// define("CP_PKCS12", "PKCS12");
class Secss {
    private static $VERSION = 1.0;
    private static $errMap = array(CP_SUCCESS => "操作成功", CP_LOAD_CONFIG_ERROR => "加载security.properties配置文件出错，请检查文件路径！", CP_SIGN_CERT_ERROR => "签名文件路径配置错误！", CP_SIGN_CERT_PWD_ERROR => "签名文件访问密码配置错误！", CP_SIGN_CERT_TYPE_ERROR => "签名文件密钥容器类型配置错误，需为PKCS12！", CP_INIT_SIGN_CERT_ERROR => "初始化签名文件出错！", CP_VERIFY_CERT_ERROR => "验签证书路径配置错误！", CP_INIT_VERIFY_CERT_ERROR => "初始化验签证书出错！", CP_GET_PRI_KEY_ERROR => "获取签名私钥出错！", CP_GET_CERT_ID_ERROR => "获取签名证书ID出错！", CP_GET_SIGN_STRING_ERROR => "获取签名字符串出错！", CP_SIGN_GOES_WRONG => "签名过程发生错误！", CP_VERIFY_GOES_WRONG => "验签过程发生错误！", CP_VERIFY_FAILED => "验签失败！", CP_SIGN_FIELD_NULL => "配置文件中签名字段名称为空！", CP_SIGN_VALUE_NULL => "报文中签名为空！", CP_UNKNOWN_WRONG => "未知错误", CP_ENCPIN_GOES_WRONG => "Pin加密过程发生错误！", CP_ENCDATA_GOES_WRONG => "数据加密过程发生错误！", CP_DECDATA_GOES_WRONG => "数据解密过程发生错误！", CP_DEFAULTINIT_GOES_WRONG => "从默认配置文件初始化安全控件发生错误！", CP_SPECIFYINIT_GOES_WRONG => "从指定属性集初始化安全控件发生错误！", CP_RELOADSC_GOES_WRONG => "重新加载签名证书发生错误！", CP_NO_INIT => "未初化安全控件", CP_CONFIG_WRONG => "控件初始化信息未正确配置，请检查！", CP_INIT_CONFIG_WRONG => "初始化配置信息发生错误！");
    private static $encryptFieldMap = array("CardTransData");
    private $CPPublicKey;
    private $MerPrivateKey;
    private $sign;
    private $encPin;
    private $encValue;
    private $decValue;
    private $privatePFXCertId;
    private $publicCERCertId;
    private $errCode = CP_SUCCESS;
    private $errMsg;
    private $signFile;
    private $merPkcs12;
    private $signFilePassword = '';
    private $signInvalidFieldsArray;
    private $verifyFile;
    private $initFalg = false;
    function __construct() {
    }
    function __destruct() {
    }
    public function getVerstion() {
        return self::$VERSION;
    }

    /**
     * 设置 PKCS12 证书文件
     * @param string $path
     * @throws Exception
     */
    public function setSignFile($path = ''){
        $this->signFile = $path;
        $this->loadSignPkcs12File();
        return $this;
    }
    /**
     * 设置 PKCS12 证书文件内容
     * @param string $path
     * @throws Exception
     */
    public function setMerPkcs12($data = ''){
        if (empty($data)){
            throw new Exception('读取pfx证书不能为空', 'SIGN_FILE_PFX_CERT_NOT_EMPTY');
        }
        $this->merPkcs12 = $data;
        return $this;
    }

    /**
     * 加载签名文件
     * @throws Exception
     */
    protected function loadSignPkcs12File(){
        if (empty($this->signFile)){
            throw new Exception('signFile不能为空', 'SIGN_FILE_CANNOT_EMPTY');
        }
        if (!file_exists($this->signFile)) {
            throw new Exception('sign文件不存在,调用setSignFile配置', 'SIGN_FILE_NOT_EXISTE', CP_SIGN_CERT_ERROR);
        }

        $merPkcs12 = file_get_contents($this->signFile);
        if (empty($merPkcs12)) {
            throw new Exception('读取pfx证书文件失败', 'SIGN_FILE_PFX_CERT_READ_FAIL', CP_GET_PRI_KEY_ERROR);
        }
        $this->setMerPkcs12($merPkcs12);
        return $this;
    }

    /**
     * 设置 PKCS12 证书密码
     * @param string $password
     */
    public function setSignFilePassword($password = ''){
        $this->signFilePassword = empty($password)?'':$password;
        return $this;
    }

    /**
     * 设置 签名的字段
     * @param string $fields
     * @throws Exception
     */
    public function setSignInvalidFields($fields = ''){
        if (empty($fields)){
            $fields = array();
        }
        if (is_string($fields)){
            $fields = explode(',', $fields);
        }
        if (!is_array($fields)){
            throw new Exception('fields必须是数字或者英文逗号隔开字符串', 'SIGN_FILE_INVALID_FIELDS_MUST_ARRAY');
        }
        $this->signInvalidFieldsArray = $fields;
        return $this;
    }

    /**
     * 配置验证文件
     * @param $path
     * @throws Exception
     */
    public function setVerifyFile($path){
        $this->verifyFile = $path;
        $this->loadCPPublicKey();
        return $this;
    }

    /**
     * 设置CP公钥证书内容
     * @throws Exception
     */
    public function setCPPublicKey($data){
        if (empty($data)) {
            throw new Exception('读取CP公钥证书文件失败', 'SIGN_FILE_CP_CERT_READ_FAIL', INIT_VERIFY_CERT_ERROR);
        }
        $this->CPPublicKey = $data;
        return $this;
    }

    /**
     * 读取CP公钥证书
     * @throws Exception
     */
    protected function loadCPPublicKey(){
        if (empty($this->verifyFile)){
            throw new Exception('signFile不能为空', 'SIGN_VERIFY_FILE_CANNOT_EMPTY', CP_VERIFY_CERT_ERROR);
        }
        if (!file_exists($this->verifyFile)) {
            throw new Exception('verify文件不存在,调用setVerifyFile配置', 'SIGN_VERIFY_FILE_NOT_EXISTE', CP_VERIFY_CERT_ERROR);
        }
        $this->setCPPublicKey(file_get_contents($this->verifyFile));
        return $this;
    }

    /**
     * @param $securityPropFile
     * @return bool
     * @throws Exception
     */
    public function init() {
        try {
            if (empty($this->merPkcs12)){
                $this->loadSignPkcs12File();
            }
            if (!openssl_pkcs12_read($this->merPkcs12, $this->MerPrivateKey, $this->signFilePassword)) {
                throw new Exception('[pkcs12]读取pfx证书内容错误', 'SIGN_FILE_PFX_CERT_PARSE_ERROR', CP_GET_PRI_KEY_ERROR);
            }
            $x509data = $this->MerPrivateKey['cert'];
            if (!openssl_x509_read($x509data)) {
                throw new Exception('[x509]读取pfx证书公钥错误', 'SIGN_FILE_PFX_X509_READ_FAIL', CP_GET_PRI_KEY_ERROR);
            }
            $certdata = openssl_x509_parse($x509data);
            if (empty($certdata)) {
                throw new Exception('[x509]解析pfx证书公钥成功，但解析证书错误', 'SIGN_FILE_PFX_X509_PARSE_FAIL', CP_GET_PRI_KEY_ERROR);
            }
            $this->privatePFXCertId = $certdata['serialNumber'];
            $this->writeLog("in SecssUitl->init 解析pfx证书公钥成功，证书编号=[" . $this->privatePFXCertId . "]");
            if (empty($this->CPPublicKey)) {
                $this->loadCPPublicKey();
            }
            $pk = openssl_pkey_get_public($this->CPPublicKey);
            $a = openssl_pkey_get_details($pk);
            $certdata = openssl_x509_parse($this->CPPublicKey, false);
            if (empty($certdata)) {
                throw new Exception('[x509]解析CP证书公钥成功，但解析证书错误', 'SIGN_FILE_CP_CERT_X509_READ_ERROR', INIT_VERIFY_CERT_ERROR);
            }
            $this->publicCERCertId = $certdata['serialNumber'];
            $this->writeLog("in SecssUitl->init 解析CP证书公钥成功，证书编号=[" . $this->publicCERCertId . "]");
            $this->initFalg = true;
            return true;
        }
        catch(Exception $e) {
            $this->writeLog("in SecssUitl->init 初始化CP签名控件出错,message=" . $e->getMessage());
            throw $e;
        }
    }

    /**
     * 签名
     * @param $paramArray
     * @return $this
     * @throws Exception
     */
    public function sign($paramArray) {
        try {
            $this->sign = null;
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行签名', 'CP_NO_INIT', CP_NO_INIT);
            }
            ksort($paramArray);
            $signRawData = $this->getSignStr($paramArray);
            if (empty($signRawData)) {
                throw new Exception('获取待签名字符串失败', 'CP_GET_SIGN_STRING_ERROR', CP_GET_SIGN_STRING_ERROR);
            }
            $charSet = mb_detect_encoding($signRawData, array("UTF-8", "GB2312", "GBK"));
            $tempSignRawData = mb_convert_encoding($signRawData, "UTF-8", $charSet);
            $this->writeLog("in SecssUitl->sign 待签名数据=[" . $tempSignRawData . "]");
            $sign_falg = openssl_sign($tempSignRawData, $signature, $this->MerPrivateKey['pkey'], OPENSSL_ALGO_SHA512);
            if (!$sign_falg) {
                throw new Exception('签名过程发生错误！', 'CP_SIGN_GOES_WRONG', CP_SIGN_GOES_WRONG);
            }
            $this->sign = base64_encode($signature);
            $this->errCode = CP_SUCCESS;
            return $this->sign;
        }
        catch(Exception $e) {
            $this->writeLog("in SecssUitl->sign 签名异常,message=" . $e->getMessage());
            throw $e;
        }
    }

    /**
     * @param $paramArray
     * @return $this
     * @throws Exception
     */
    public function verify($paramArray) {
        try {
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行签名', 'CP_NO_INIT', CP_NO_INIT);
            }
            $orgSignMsg = $paramArray["Signature"];
            if (empty($orgSignMsg)) {
                throw new Exception('paramArray数组中签名字段为空。', 'CP_SIGN_VALUE_NULL', CP_SIGN_VALUE_NULL);
            }
            unset($paramArray["Signature"]);
            ksort($paramArray);
            $verifySignData = $this->getSignStr($paramArray);
            $charSet = mb_detect_encoding($verifySignData, array("UTF-8", "GB2312", "GBK"));
            $tempVerifySignData = mb_convert_encoding($verifySignData, "UTF-8", $charSet);
            $this->writeLog("in SecssUitl->verify  待验证签名数据 =[" . $tempVerifySignData . "]");
            $result = openssl_verify($tempVerifySignData, base64_decode($orgSignMsg), $this->CPPublicKey, OPENSSL_ALGO_SHA512);
            if ($result == 1) {
                $this->errCode = CP_SUCCESS;
            } else if ($result == 0) {
                $this->errCode = CP_VERIFY_FAILED;
            } else {
                $this->errCode = CP_VERIFY_GOES_WRONG;
            }
            if ($this->errCode !== CP_SUCCESS) {
                $message = empty(self::$errMap[$this->errCode])?'未知错误':self::$errMap[$this->errCode];
                throw new Exception($message, 'CP_VERIFY_GOES_WRONG', $this->errCode);
            } else {
                return $this;
            }
        }
        catch(Exception $e) {
            $this->writeLog("in SecssUitl->verify 验证签名异常,message=" . $e->getMessage());
            throw $e;
        }
    }
    public function getSignCertId() {
        return $this->privatePFXCertId;
    }

    /**
     * @param $pin
     * @param $card
     * @return bool
     * @throws Exception
     */
    public function encryptPin($pin, $card) {
        try {
            $this->encPin = null;
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行加密', 'CP_NO_INIT', CP_NO_INIT);
            }
            $pinBlock = $this->pin2PinBlockWithCardNO($pin, $card);
            if (empty($pinBlock)) {
                throw new Exception('PIN加密异常,计算得到的PinBlock为空', 'PIN_NOT_EMPTY', CP_ENCPIN_GOES_WRONG);
            }
            $pk = openssl_pkey_get_public($this->CPPublicKey);
            $a = openssl_pkey_get_details($pk);
            $n = $a["rsa"]["n"];
            $e = $a["rsa"]["e"];
            $intN = $this->bin2int($n);
            $intE = $this->bin2int($e);
            $crypted = bcpowmod($this->bin2int($pinBlock), $intE, $intN);
            if (!$crypted) {
                throw new Exception('pin加密失败,errCode=[' . $this->errCode . ']', 'ENCRYPT_PIN_FAIL', CP_ENCPIN_GOES_WRONG);
            }
            $rb = $this->bcdechex($crypted);
            $rb = $this->padstr($rb);
            $crypted = hex2bin($rb);
            $this->encPin = base64_encode($crypted);
            $this->errCode = CP_SUCCESS;
            return $this->encPin;
        }
        catch(Exception $e) {
            $this->writeLog("in SecssUitl->encryptPin PIN加密异常,message=" . $e->getMessage());
            throw $e;
        }
    }
    private function pin2PinBlockWithCardNO($aPin, $aCardNO) {
        $tPinByte = $this->pin2PinBlock($aPin);
        if (empty($tPinByte)) {
            return null;
        }
        if (strlen($aCardNO) == 11) {
            $aCardNO = "00" . $aCardNO;
        } else if (strlen($aCardNO) == 12) {
            $aCardNO = "0" . $aCardNO;
        }
        $tPanByte = $this->formatPan($aCardNO);
        if (empty($tPanByte)) {
            return null;
        }
        $tByte = array();
        for ($i = 0;$i < 8;$i++) {
            $tByte[$i] = $tPinByte[$i] ^ $tPanByte[$i];
        }
        $result = "";
        foreach ($tByte as $key => $value) {
            $result.= chr($value);
        }
        return $result;
    }
    private function formatPan($aPan) {
        $tPanLen = strlen($aPan);
        $tByte = array();
        $temp = $tPanLen - 13;
        try {
            $tByte[0] = 0;
            $tByte[1] = 0;
            for ($i = 2;$i < 8;$i++) {
                $a = "\x" . substr($aPan, $temp, 2);
                $tByte[$i] = hexdec($a);
                $temp+= 2;
            }
        }
        catch(Exception $e) {
            return null;
        }
        return $tByte;
    }
    private function pin2PinBlock($aPin) {
        $tTemp = 1;
        $tPinLen = strlen($aPin);
        $tByte = array();
        try {
            $tByte[0] = $tPinLen;
            $i = 0;
            if ($tPinLen % 2 == 0) {
                for ($i = 0;$i < $tPinLen;) {
                    $a = hexdec("\x" . substr($aPin, $i, 2));
                    $tByte[$tTemp] = $a;
                    if (($i == $tPinLen - 2) && ($tTemp < 7)) {
                        for ($x = $tTemp + 1;$x < 8;$x++) {
                            $tByte[$x] = - 1;
                        }
                    }
                    $tTemp++;
                    $i+= 2;
                }
            } else {
                for ($i = 0;$i < $tPinLen - 1;) {
                    $a = hexdec("\x" . substr($aPin, $i, $i + 2));
                    $tByte[$tTemp] = $a;
                    if ($i == $tPinLen - 3) {
                        $b = hexdec("\x" . substr($aPin, $tPinLen - 1) . "F");
                        $tByte[($tTemp + 1) ] = $b;
                        if ($tTemp + 1 < 7) {
                            for ($x = $tTemp + 2;$x < 8;$x++) {
                                $tByte[$x] = - 1;
                            }
                        }
                    }
                    $tTemp++;
                    $i+= 2;
                }
            }
        }
        catch(Exception $e) {
            return null;
        }
        return $tByte;
    }

    /**
     * 加密数据
     * @param $data
     * @return string
     * @throws Exception
     */
    public function encryptData($data) {
        try {
            $this->encValue = null;
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行加密', 'CP_NO_INIT', CP_NO_INIT);
            }
            $charSet = mb_detect_encoding($data, array("UTF-8", "GB2312", "GBK"));
            $tmpData = mb_convert_encoding($data, "UTF-8", $charSet);
            $pk = openssl_pkey_get_public($this->CPPublicKey);
            $a = openssl_pkey_get_details($pk);
            $n = $a["rsa"]["n"];
            $e = $a["rsa"]["e"];
            $intN = $this->bin2int($n);
            $intE = $this->bin2int($e);
            $crypted = bcpowmod($this->bin2int($tmpData), $intE, $intN);
            if (!$crypted) {
                throw new Exception('数据加密失败', 'ENCRYPT_DATA_FAIL', CP_ENCDATA_GOES_WRONG);
            }
            $rb = $this->bcdechex($crypted);
            $rb = $this->padstr($rb);
            $crypted = hex2bin($rb);
            $this->encValue = base64_encode($crypted);
            $this->errCode = CP_SUCCESS;
            return $this->encValue;
        }
        catch(Exception $e) {
            $this->writeLog("in SecssUitl->encryptData 数据加密异常,message=" . $e->getMessage());
            throw $e;
        }
    }

    /**
     * 解密数据
     * @param $data
     * @return bool|string
     * @throws Exception
     */
    public function decryptData($data) {
        try {
            $this->decValue = null;
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行加密', 'CP_NO_INIT', CP_NO_INIT);
            }
            $pkeyResource = openssl_pkey_get_private($this->MerPrivateKey['pkey']);
            if (!openssl_private_decrypt(base64_decode($data), $tmpDecValue, $pkeyResource, OPENSSL_NO_PADDING)) {
                throw new Exception('数据解密过程发生错误!', 'CP_DECDATA_GOES_WRONG', CP_DECDATA_GOES_WRONG);
            }
            $this->decValue = $this->remove_padding($tmpDecValue);
            $this->errCode = CP_SUCCESS;
            return $this->decValue;
        }
        catch(Exception $e) {
            $this->writeLog("in SecssUitl->decryptData 数据解密异常,message=" . $e->getMessage());
            throw $e;
        }
    }
    private function getSignStr($paramArray) {
        $result = "";
        $invalidFieldsArray = $this->signInvalidFieldsArray;
        foreach ($paramArray as $key => $value) {
            if (in_array($key, $invalidFieldsArray)) {
                continue;
            }
            $result = $result . $key . CP_KEY_VALUE_CONNECT . $value . CP_MESSAGE_CONNECT;
        }
        if (CP_MESSAGE_CONNECT === substr($result, -1, 1)) {
            $result = substr($result, 0, strlen($result) - 1);
        }
        return $result;
    }
    public function getSign() {
        return $this->sign;
    }
    public function getEncPin() {
        return $this->encPin;
    }
    public function getEncValue() {
        return $this->encValue;
    }
    public function getDecValue() {
        return $this->decValue;
    }
    public function getPrivatePFXCertId() {
        return $this->privatePFXCertId;
    }
    public function getPublicCERCertId() {
        return $this->publicCERCertId;
    }
    public function getErrCode() {
        return $this->errCode;
    }
    public function getErrMsg() {
        if (empty($this->errCode)) {
            $this->errMsg = self::$errMap[CP_UNKNOWN_WRONG];
        } else {
            $this->errMsg = self::$errMap[$this->errCode];
        }
        if (empty($this->errMsg)) {
            $this->errMsg = self::$errMap[CP_UNKNOWN_WRONG];
        }
        return $this->errMsg;
    }
    private function writeLog($log) {
        error_log($log . "\n", 0);
    }
    private function bin2int($bindata) {
        $hexdata = bin2hex($bindata);
        return $this->bchexdec($hexdata);
    }
    private function bchexdec($hexdata) {
        $ret = '0';
        $len = strlen($hexdata);
        for ($i = 0;$i < $len;$i++) {
            $hex = substr($hexdata, $i, 1);
            $dec = hexdec($hex);
            $exp = $len - $i - 1;
            $pow = bcpow('16', $exp);
            $tmp = bcmul($dec, $pow);
            $ret = bcadd($ret, $tmp);
        }
        return $ret;
    }
    private function padstr($src, $len = 256, $chr = '0', $d = 'L') {
        $ret = trim($src);
        $padlen = $len - strlen($ret);
        if ($padlen > 0) {
            $pad = str_repeat($chr, $padlen);
            if (strtoupper($d) == 'L') {
                $ret = $pad . $ret;
            } else {
                $ret = $ret . $pad;
            }
        }
        return $ret;
    }
    private function bcdechex($decdata) {
        $s = $decdata;
        $ret = '';
        while ($s != '0') {
            $m = bcmod($s, '16');
            $s = bcdiv($s, '16');
            $hex = dechex($m);
            $ret = $hex . $ret;
        }
        return $ret;
    }
    private function number_to_binary($number, $blocksize) {
        $base = "256";
        $result = "";
        $div = $number;
        while ($div > 0) {
            $mod = bcmod($div, $base);
            $div = bcdiv($div, $base);
            $result = chr($mod) . $result;
        }
        return str_pad($result, $blocksize, "\x00", STR_PAD_LEFT);
    }
    private function binary_to_number($data) {
        $base = "256";
        $radix = "1";
        $result = "0";
        for ($i = strlen($data) - 1;$i >= 0;$i--) {
            $digit = ord($data{$i});
            $part_res = bcmul($digit, $radix);
            $result = bcadd($result, $part_res);
            $radix = bcmul($radix, $base);
        }
        return $result;
    }
    private function remove_padding($data) {
        $offset = strrpos($data, "\x00", 1);
        return substr($data, $offset + 1);
    }
    private function signFromStr($signStr) {
        try {
            $this->sign = null;
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行签名', 'CP_NO_INIT', CP_NO_INIT);
            }
            if (empty($signStr)) {
                $this->errCode = CP_GET_SIGN_STRING_ERROR;
                $this->writeLog("in SecssUitl->signFromStr 获取待签名字符串失败");
                return false;
            }
            $sign_falg = openssl_sign($signStr, $signature, $this->MerPrivateKey['pkey'], OPENSSL_ALGO_SHA512);
            if (!$sign_falg) {
                $this->errCode = CP_SIGN_GOES_WRONG;
                return false;
            }
            $base64Result = base64_encode($signature);
            $this->sign = $base64Result;
            $this->errCode = CP_SUCCESS;
            return true;
        }
        catch(Exception $e) {
            $this->errCode = CP_SIGN_GOES_WRONG;
            $this->writeLog("in SecssUitl->signFromStr 签名异常,message=" . $e->getMessage());
            return false;
        }
    }
    private function verifyFromStr($paramArray) {
        try {
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行验签', 'CP_NO_INIT', CP_NO_INIT);
            }
            $orgSignMsg = $paramArray["Signature"];
            if (empty($orgSignMsg)) {
                $this->writeLog("in SecssUitl->verifyFromStr paramArray数组中签名字段为空。");
                $this->errCode = CP_SIGN_VALUE_NULL;
                return false;
            }
            unset($paramArray["Signature"]);
            $verifySignData = $paramArray["plainData"];
            $result = openssl_verify($verifySignData, base64_decode($orgSignMsg), $this->CPPublicKey, OPENSSL_ALGO_SHA512);
            if ($result == 1) {
                $this->errCode = CP_SUCCESS;
            } else {
                if ($result == 0) {
                    $this->errCode = CP_VERIFY_FAILED;
                } else {
                    $this->errCode = CP_VERIFY_GOES_WRONG;
                }
            }
            if ($this->errCode === CP_SUCCESS) {
                return true;
            } else {
                return false;
            }
        }
        catch(Exception $e) {
            $this->errCode = CP_VERIFY_GOES_WRONG;
            $this->writeLog("in SecssUitl->verifyFromStr 验证签名异常,message=" . $e->getMessage());
            return false;
        }
    }
    public function signFile($filePath) {
        try {
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行签名', 'CP_NO_INIT', CP_NO_INIT);
            }
            $tempFilePath = mb_convert_encoding($filePath, "GBK", "auto");
            $this->signFileByParams($tempFilePath, "sha512", "");
        }
        catch(Exception $e) {
            $this->errCode = CP_SIGN_GOES_WRONG;
            $this->writeLog("in SecssUitl->signFile 文件签名异常,message=" . $e->getMessage());
            return false;
        }
    }
    public function signFileByParams($filePath, $sigAlgName, $encoding) {
        try {
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行签名', 'CP_NO_INIT', CP_NO_INIT);
            }
            if (!is_file($filePath)) {
                $this->errCode = CP_SIGN_GOES_WRONG;
                $this->writeLog("in SecssUitl->signFileByParams 文件不存在，无法进行签名.file=[" . $filePath . "]");
                return false;
            }
            $ctx = hash_init($sigAlgName);
            $handle = fopen($filePath, "r");
            $max = filesize($filePath);
            $chunk = 4096;
            if ($max <= $chunk) {
                $endIndex = 0;
            } else {
                $endIndex = ($max % $chunk === 0 ? $max / $chunk : $max / $chunk + 1);
            }
            $endReadLength = $max % $chunk;
            $readData = "";
            $ctx = hash_init($sigAlgName);
            for ($i = 0;$i <= $endIndex;$i++) {
                if ($i == $endIndex) {
                    if ($endReadLength > 0) {
                        $readData = fread($handle, $endReadLength);
                    } else {
                        $readData = fread($handle, $chunk);
                    }
                } else {
                    $readData = fread($handle, $chunk);
                }
                $readData = str_replace(array("\r\n", "\r", "\n"), "", $readData);
                hash_update($ctx, $readData);
            }
            fclose($handle);
            clearstatcache();
            $hashResult = hash_final($ctx);
            if ($this->signFromStr(hex2bin($hashResult))) {
                $data = "\r\n" . $this->getSign();
                if (file_put_contents($filePath, $data, FILE_APPEND) !== false) {
                    clearstatcache();
                    return true;
                } else {
                    $this->errCode = CP_SIGN_GOES_WRONG;
                    $this->writeLog("in SecssUitl->signFileByParams 写入签名数据至文件失败.file=[" . $filePath . "]");
                    clearstatcache();
                    return false;
                }
            } else {
                $this->errCode = CP_SIGN_GOES_WRONG;
                $this->writeLog("in SecssUitl->signFileByParams 文件签名失败.file=[" . $filePath . "]");
                clearstatcache();
                return false;
            }
        }
        catch(Exception $e) {
            $this->errCode = CP_SIGN_GOES_WRONG;
            $this->writeLog("in SecssUitl->signFileByParams 文件签名异常,message=" . $e->getMessage());
            clearstatcache();
            return false;
        }
    }
    public function verifyFile($filePath) {
        try {
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行签名', 'CP_NO_INIT', CP_NO_INIT);
            }
            $tempFilePath = mb_convert_encoding($filePath, "GBK", "auto");
            return $this->verifyFileByParams($tempFilePath, "sha512", "");
        }
        catch(Exception $e) {
            $this->errCode = CP_SIGN_GOES_WRONG;
            $this->writeLog("in SecssUitl->verifyFile 文件验签异常,message=" . $e->getMessage());
            return false;
        }
    }
    public function verifyFileByParams($filePath, $sigAlgName, $encoding) {
        try {
            if (!$this->initFalg) {
                throw new Exception('未调用init方法，无法进行签名', 'CP_NO_INIT', CP_NO_INIT);
            }
            if (!is_file($filePath)) {
                $this->errCode = CP_VERIFY_GOES_WRONG;
                $this->writeLog("in SecssUitl->verifyFileByParams 文件不存在，无法进行验签.file=[" . $filePath . "]");
                return false;
            }
            $max = filesize($filePath);
            $handle = fopen($filePath, "r");
            $index = - 1;
            fseek($handle, $index, SEEK_END);
            $orgSignature = "";
            while (($c = fread($handle, 1)) !== false) {
                if ($c == "\n" || $c == "\r") break;
                $orgSignature = $c . $orgSignature;
                $index = $index - 1;
                fseek($handle, $index, SEEK_END);
            }
            fclose($handle);
            $handle = fopen($filePath, "a+");
            ftruncate($handle, $max - strlen($orgSignature));
            fclose($handle);
            clearstatcache();
            $max = filesize($filePath);
            $handle = fopen($filePath, "r");
            $chunk = 4096;
            if ($max <= $chunk) {
                $endIndex = 0;
            } else {
                $endIndex = ($max % $chunk === 0 ? $max / $chunk : $max / $chunk + 1);
            }
            $endReadLength = $max % $chunk;
            $readData = "";
            $ctx = hash_init($sigAlgName);
            for ($i = 0;$i <= $endIndex;$i++) {
                if ($i === $endIndex) {
                    if ($endReadLength > 0) {
                        $readData = fread($handle, $endReadLength);
                    } else {
                        $readData = fread($handle, $chunk);
                    }
                } else {
                    $readData = fread($handle, $chunk);
                }
                $readData = str_replace(array("\r\n", "\r", "\n"), "", $readData);
                hash_update($ctx, $readData);
            }
            fclose($handle);
            clearstatcache();
            $hashResult = hash_final($ctx);
            $paramArray = array("plainData" => hex2bin($hashResult), "Signature" => $orgSignature);
            $verifyResult = $this->verifyFromStr($paramArray);
            if (file_put_contents($filePath, $orgSignature, FILE_APPEND) !== false) {
                clearstatcache();
                return $verifyResult;
            } else {
                $this->errCode = CP_VERIFY_FAILED;;
                $this->writeLog("in SecssUitl->signFileByParams 写入原签名数据至文件失败.file=[" . $filePath . "]");
                clearstatcache();
                return false;
            }
        }
        catch(Exception $e) {
            $this->errCode = CP_VERIFY_GOES_WRONG;
            $this->writeLog("in SecssUitl->verifyFileByParams 文件签名验证异常,message=" . $e->getMessage());
            clearstatcache();
            return false;
        }
    }
}
