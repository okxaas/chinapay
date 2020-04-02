<?php
namespace ITPony\ChinaPay;

class Exception
{
  // 魔术方法
  public function __construct( $message = 'Chinapay Error', $errorId = 'CHINAPAY_ERROR' , $code = '400', $errorData = array() )
  {
    return [
    	'errMsg' 	=> $message ,
		'errId' 	=> $errorId ,
		'errCode' 	=> $code,
		'errData' 	=> $errorData
	];
  }
}
