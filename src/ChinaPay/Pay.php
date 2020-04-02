<?php

namespace ITPony\ChinaPay;

use ITPony\ChinaPay\Util\Url;
use ITPony\ChinaPay\Util\Secss;

class Pay
{
	protected $domain = [
		'dev' => 'https://newpayment-test.chinapay.com',
		'pro' => 'https://payment.chinapay.com'
	];

	protected $apiUriQuery = '/CTITS/service/rest/forward/syn/000000000060/0/0/0/0/0';

	protected $apiUriPay = '/CTITS/service/rest/page/nref/000000000017/0/0/0/0/0';

	private $config = array();
	/**
	 * @var $secss Secss|null
	 */
	protected $secss = null;
	private $transResveredKey = 'TranReserved';
	private $signatureKey = 'Signature';

	private $signFile;
	private $merPkcs12;
	private $signFilePassword = '';
	private $signInvalidFieldsArray;
	private $verifyFile;
	private $CPPublicKey;

	private $busiType = '0001'; //业务类型,固定值:0001
	private $acqCode = ''; //业务类型,固定值:0001
	private $merId = ''; //商户号
	private $accessType = '0'; //接入类型:0:商户身份接入(默认) 1:机构身份接入
	private $curryNoArray = array( //ISO 4217的货币代码
		'CNY', //人民币
		'HKD', //港元
		'USD', //美元
		'GBP',//英镑
		'JPY' //日元
	);
	//分账类型 0001 实时分账 0002 延时分账
	private $splitTypeArray = array(0, 1);
	//分账方式 0 按金额分账1 按比例分账
	private $cplitMethodArray = array(0, 1);

	// 魔术方法
	public function __construct($config = null)
	{

		isset($config) && is_array($config) && $this->setConfig($config);
	}

	public function setTransResveredKey($key = 'TranReserved')
	{
		$this->transResveredKey = $key;
		return $this;
	}

	public function setSignatureKey($key = 'Signature')
	{
		$this->signatureKey = $key;
		return $this;
	}

	public function setAcqCode($acqCode)
	{
		$this->acqCode = $acqCode;
		return $this;
	}

	public function setMerId($merId)
	{
		$this->merId = $merId;
		return $this;
	}

	public function getMerId()
	{
		return $this->merId;
	}
	public function setAccessType($accessType)
	{
		$this->accessType = $accessType;
		return $this;
	}

	/**
	 * 设置 PKCS12 证书文件
	 * @param string $path
	 * @throws Exception
	 */
	public function setSignFile($path = '')
	{
		$this->signFile = $path;
		return $this;
	}

	/**
	 * 设置 PKCS12 证书文件内容
	 * @param string $path
	 * @throws Exception
	 */
	public function setMerPkcs12($data = '')
	{
		if (empty($data)) {
			throw new Exception('读取pfx证书不能为空', 'SIGN_FILE_PFX_CERT_NOT_EMPTY');
		}
		$this->merPkcs12 = $data;
		return $this;
	}

	/**
	 * 设置 PKCS12 证书密码
	 * @param string $password
	 */
	public function setSignFilePassword($password = '')
	{
		$this->signFilePassword = empty($password) ? '' : $password;
		return $this;
	}

	/**
	 * 设置 签名的字段
	 * @param string $fields
	 * @throws Exception
	 */
	public function setSignInvalidFields($fields = '')
	{
		if (empty($fields)) {
			$fields = array();
		}
		if (is_string($fields)) {
			$fields = explode(',', $fields);
		}
		if (!is_array($fields)) {
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
	public function setVerifyFile($path)
	{
		$this->verifyFile = $path;
		$this->loadCPPublicKey();
		return $this;
	}

	/**
	 * 设置CP公钥证书内容
	 * @throws Exception
	 */
	public function setCPPublicKey($data)
	{
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

	public function setConfig($config = null)
	{
		if (!is_array($config)) {
			return;
		}

		if (!empty($config['mode'])) {
			$this->apiUriQuery = $this->domain[$config['mode']]. $this->apiUriQuery;
			$this->apiUriPay = $this->domain[$config['mode']].$this->apiUriPay;
		} else {
			$this->apiUriQuery = $this->domain['pro']. $this->apiUriQuery;
			$this->apiUriPay = $this->domain['pro'].$this->apiUriPay;
		}

		if (empty($config['merPkcs12'])) {
			$this->setSignFile($config['signFile']);
		} else {
			$this->setMerPkcs12($config['merPkcs12']);
		}
		if (!empty($config['signFilePassword'])) {
			$this->setSignFilePassword($config['signFilePassword']);
		}
		if (empty($config['CPPublicKey'])) {
			$this->setVerifyFile($config['verifyFile']);
		} else {
			$this->setCPPublicKey($config['CPPublicKey']);
		}

		if (!empty($config['signInvalidFieldsArray'])) {
			$this->setSignInvalidFields($config['signInvalidFieldsArray']);
		}
		if (!empty($config['acqCode'])) {
			$this->setAcqCode($config['acqCode']);
		}
		if (!empty($config['merId'])) {
			$this->setMerId($config['merId']);
		}
		if (!empty($config['accessType'])) {
			$this->setAccessType($config['accessType']);
		}

	}

	public function loadSecssUtil()
	{
		$this->secss = new Secss();

		if (empty($this->merPkcs12)) {
			$this->secss->setSignFile($this->signFile);
		} else {
			$this->secss->setMerPkcs12($this->merPkcs12);
		}
		if ($this->signFilePassword) {
			$this->secss->setSignFilePassword($this->signFilePassword);
		}
		if (empty($this->CPPublicKey)) {
			$this->secss->setVerifyFile($this->verifyFile);
		} else {
			$this->secss->setCPPublicKey($this->CPPublicKey);
		}

		if (!empty($this->signInvalidFieldsArray)) {
			$this->secss->setSignInvalidFields($this->signInvalidFieldsArray);
		}

		$this->secss->init();
	}

	public function getBaseParams($params = array())
	{
		//业务类型 固定值:0001
		if (empty($params['BusiType'])) {
			$params['BusiType'] = $this->busiType;
		}
		// 由 ChinaPay 分配，用于确 认商户身份
		if (empty($params['MerId'])) {
			$params['MerId'] = $this->merId;
		}
		// 由 ChinaPay 分配，用于确 认商户身份
		if (empty($params['AccessType'])) {
			$params['AccessType'] = $this->accessType;
		}
		if (empty($params["MerId"])) {
			// 由 ChinaPay 分配，用于确 认商户身份
			throw new Exception('商户号不能为空', 'MERID_MUST_INPUT');
		}
		if (empty($params['Version'])) {
			//认证支付和快捷支付:20150922 其余:20140728
			throw new Exception("版本号不能为空", 'VERSIOB_NOT_EMPTY');
		}
		return $params;
	}

	public function webB2bPay($params = array())
	{
		if (empty($this->secss)) {
			$this->loadSecssUtil();
		}
		if (empty($params['Version'])) {
			$params['Version'] = '20140728';
		}
		$params = $this->getBaseParams($params);
		if (empty($params["MerOrderNo"])) {
			// 可包含字母和数字，与 MerId 和 TranDate 一起， 唯一确定一笔订单
			throw new Exception('订单号不能为空', 'MER_ORDER_NO_MUST_INPUT');
		}
		if (empty($params["TranDate"]) || !is_numeric($params["TranDate"])) {
			//商户提交交易的日期，格 式为YYYYMMDD，例如交易日期为2015年1月2 日，则值为 20150102
			throw new Exception("交易日期不能为空", "TRANDATE_MUST_INPUT");
		}
		if (empty($params["TranTime"]) || !is_numeric($params["TranTime"])) {
			//商户提交交易的时间，格 式为 HHMMDD，例如交 易时间10点01分22秒， 则值为 100122
			throw new Exception("交易时间不能为空", "TRANTIME_MUST_INPUT");
		}
		if (empty($params["OrderAmt"]) || !is_numeric($params["OrderAmt"])) {
			//订单金额(单位：分)
			throw new Exception("金额不能为空", 'ORDERAMT_MUST_INPUT');
		}
		if (!empty($params["TranReserved"])) {
			if (is_array($params["TranReserved"])) {
				// 强制转json
				$params["TranReserved"] = json_encode($params["TranReserved"]);
			}
			if (!is_string($params["TranReserved"])) {
				throw new Exception('TranReserved必须是json字符串或者数组', 'MER_ORDER_NO_MUST_INPUT');
			}
			$transResvedStr = $this->secss->decryptData($transResvedStr);
			$params[$this->transResveredKey] = $transResvedStr;
		}
		if (!empty($params['CurryNo'])) {
			//交易币种,符合 ISO4217 标准的的货币代码
			if (!in_array($params['CurryNo'], $this->curryNoArray)) {
				throw new Exception('交易币种不符合ISO4217标准的的货币', 'CURRY_NO_ERROR');
			}
		}
		if (!empty($params['SplitType'])) {
			//分账类型 0001 实时分账 0002 延时分账
			if (!in_array($params['SplitType'], $this->splitTypeArray)) {
				throw new Exception('分账类型错误', 'SPLIT_TYPE_ERROR');
			}
		}
		if (!empty($params['SplitMethod'])) {
			//分账类型 0001 实时分账 0002 延时分账
			if (!in_array($params['SplitMethod'], $this->splitMethodArray)) {
				throw new Exception('分账类型错误', 'SPLIT_TYPE_ERROR');
			}
		}
		if (!empty($params["MerSplitMsg"])) {
			//分账信息
			if (is_array($params["MerSplitMsg"])) {
				// 强制转json
				$params["MerSplitMsg"] = json_encode($params["MerSplitMsg"]);
			}
			if (!is_string($params["MerSplitMsg"])) {
				throw new Exception('MerSplitMsg必须是json字符串或者数组', 'MER_SPLIT_MSG_MUST_INPUT');
			}
		}
		if (!empty($params['BankInstNo'])) {
			//支付机构号
			if (!is_numeric($params['BankInstNo'])) {
				throw new Exception('BANKINSTNO必须是数字', 'BANKINSTNO_ERROR');
			}
		}
		if (!empty($params['MerPageUrl'])) {
			//商户前台通知 地址 ,用来接收交易结果的前台跳转页面的地址，用于引导付款人支付后返回商户网站页面
			if (!filter_var($params['MerPageUrl'], FILTER_VALIDATE_URL)) {
				throw new Exception('MERPAGEURL非法', 'MERPAGEURL_NOT_URL');
			}
		}
		if (empty($params['MerBgUrl'])) {
			//商户后台通知 地址 ,用来接收交易结果后台通知的地址
			throw new Exception('MerBgUrl不能为空', 'MERBGURL_MUST_INPUT');
		} else {
			if (!filter_var($params['MerBgUrl'], FILTER_VALIDATE_URL)) {
				throw new Exception('MERBGURL非法', 'MERBGURL_NOT_URL');
			}
		}
		if (!empty($params["CommodityMsg"])) {
			//商品信息,用来描述购买商品的信息，ChinaPay会原样返回
			if (is_array($params["CommodityMsg"])) {
				// 强制转json
				$params["CommodityMsg"] = json_encode($params["CommodityMsg"]);
			}
			if (!is_string($params["CommodityMsg"])) {
				throw new Exception('CommodityMsg必须是json字符串或者数组', 'COMMODITY_MSG_MUST_INPUT');
			}
		}
		if (!empty($params["MerResv"])) {
			//商户私有域,商户自定义填写， ChinaPay会原样返回
			if (is_array($params["MerResv"])) {
				// 强制转json
				$params["MerResv"] = json_encode($params["MerResv"]);
			}
			if (!is_string($params["MerResv"])) {
				throw new Exception('MerResv必须是json字符串或者数组', 'MER_RESV_MUST_INPUT');
			}
		}
		if (!empty($params['CardTranData'])) {
			//有卡交易信息域
			if (is_array($params["CardTranData"])) {
				// 强制转json
				$params["CardTranData"] = json_encode($params["CardTranData"]);
			}
			if (!is_string($params["CardTranData"])) {
				throw new Exception('CardTranData必须是json字符串或者数组', 'MER_RESV_MUST_INPUT');
			}
		}
		if (!empty($params['Term'])) {
			//分期数,需要分期付款交易的分期 数，支持 3、6、12 期，分 别取值 03、06、12。
			if (!is_numeric($params['Term'])) {
				throw new Exception('Term必须是数字', 'TERM_MUST_NUMBER');
			}
		}
		if (!empty($params['PayTimeOut'])) {
			//支付超时时间,单位:分钟 超过此时间段后用户支付成功的 交易，不通知商户，系统自动退款。
			if (!is_numeric($params['PayTimeOut'])) {
				throw new Exception('PayTimeOut必须是数字', 'PAY_TIME_OUT_MUST_NUMBER');
			}
		}
		if (!empty($params['TimeStamp'])) {
			//当前系统时间，以北京时间为准。格式:YYYYMMDDHHMMSS,如商户开户时开通了时间戳防钓鱼校验，ChinaPay 系统配置商户系统时间和商户 系统时间的时间差(以秒为单位)，如时间超过系统配置的间隔，则会进行防钓鱼提 示或拦截交易。
			if (!is_numeric($params['TimeStamp'])) {
				throw new Exception('TimeStamp必须是数字', 'TIMESTAMP_MUST_NUMBER');
			}
		}
		if (!empty($params['RemoteAddr'])) {
			//防钓鱼客户浏览器 IP如商户开通校验 IP 防钓鱼验证，可填写此域做防钓鱼使用。 ChinaPay 会获取持卡人访问 IP 和该字段进行比较，如果不一致，则会进行防钓鱼 提示或拦截交易。
			if (!filter_var($params['RemoteAddr'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
				throw new Exception('RemoteAddr必须是数字', 'REMOTE_ADDR_MUST_NUMBER');
			}
		}
		if (!empty($params['RiskData'])) {
			if (is_array($params["RiskData"])) {
				// 强制转json
				$params["RiskData"] = json_encode($params["RiskData"]);
			}
			if (!is_string($params["RiskData"])) {
				throw new Exception('RiskData必须是json字符串或者数组', 'RISK_DATA_MUST_STRING');
			}
		}

		$this->secss->sign($params);
		$params[$this->signatureKey] = $this->secss->getSign();
		$params['PayMentUrl'] = $this->apiUriPay;
		return $params;
	}

	public function webB2Notify($params = array())
	{
		if (empty($this->secss)) {
			$this->loadSecssUtil();
		}

		if ($this->secss->verify($params)) {
			$results = "success";
		} else {
			$results = "fail";
		}

		$data = [];

		foreach($params as $key => $value){
			$data[$key] = urldecode($value);
		}

		return ['result' => $results, 'data' => $data];
	}

	public function webB2bQuery($params = array())
	{
		if (empty($this->secss)) {
			$this->loadSecssUtil();
		}
		// 查询交易为0502，此处因为是查询交易 所以写死
		$params['TranType'] = '0502';
		$params['BusiType'] = '0001';
		if (empty($params['Version'])) {
			$params['Version'] = '20140728';
		}
		$paramsExtra = $this->getBaseParams($params);
		$params = array_merge($params, $paramsExtra);

		if (empty($params["MerOrderNo"])) {
			// 可包含字母和数字，与 MerId 和 TranDate 一起， 唯一确定一笔订单
			throw new Exception('订单号不能为空', 'MER_ORDER_NO_MUST_INPUT');
		}
		if (empty($params["TranDate"]) || !is_numeric($params["TranDate"])) {
			//商户提交交易的日期，格 式为YYYYMMDD，例如交易日期为2015年1月2 日，则值为 20150102
			throw new Exception("交易日期不能为空", "TRANDATE_MUST_INPUT");
		}

		$this->secss->sign($params);
		$params[$this->signatureKey] = $this->secss->getSign();
		$result = $this->sendPost($this->apiUriQuery, $params);

		return Url::parseQuery($result);
	}

	/**
	 * @param $params
	 * 验证银联回调数据
	 */
	public function verify($params)
	{
		if (empty($this->secss)) {
			$this->loadSecssUtil();
		}
		$this->secss->verify($params);
		if ("00" !== $this->secss->getErrCode()) {
			throw new Exception("验证数据错误", "VERIFY_ERROR");
		}
	}

	public function sendPost($url, $postData)
	{
		$postdata = Url::buildQuery($postData);
		$options = array(
			'http' => array(
				'method' => 'POST',
				'header' => 'Content-type:application/x-www-form-urlencoded',
				'content' => $postdata,
				'timeout' => 15 * 60
			)
		);
		$context = stream_context_create($options);
		$result = file_get_contents($url, false, $context);
		return $result;
	}
}