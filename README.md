# 使用说明

```.env
// 引入类库
use ITPony\ChinaPay;
```

```.env
$config = [
    // dev是测试环境，生产环境mode参数可不设置或者设置成pro即可
    'mode'	        	=> 'dev',
    'signFile'                  => '.pfx的商户交易证书所在地址',
    'signFilePassword'          => '证书密码',
    'verifyFile' 		=> 'cp.cer的验证证书所在地址',
    'signInvalidFieldsArray' 	=> 'Signature',
    'merId' 			=> '商户ID',
    'AccessType' 		=> 0,
];

$chinaPay = new ChinaPay($config);

$params = [
    'MerOrderNo' 	=> '15位订单号',
    'TranType'		=> 'B2C：0001，B2B：0002；其他类型请查阅官方文档',
    'TranDate'		=> '日期：格式yyyymmdd',
    'TranTime'		=> '时间：hhiiss',
    'OrderAmt'		=> '支付金额',
    'MerBgUrl'		=> '回调地址',
    'RemoteAddr'	=> '客户端IP',
];

// 该结果会返回一个地址和提交支付的参数，自行适配页面
$chinaPay->webB2bPay($params)

// 回调传入银联回调回来的数据即可使用
$chinapay->webB2Notify();

```

