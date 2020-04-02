<?php
namespace ITPony\ChinaPay\Util;

class Url
{
	public static $PERCENT_ENCODED_STRINGS = array();

	//在uri编码中不能对'/'编码
	public static function urlEncodeExceptSlash($path)
	{
		return str_replace("%2F", "/", self::urlEncode($path));
	}

	//使用编码数组编码
	public static function urlEncode($value)
	{
		$result = '';
		for ($i = 0; $i < strlen($value); ++$i) {
			$result .= self::$PERCENT_ENCODED_STRINGS[ord($value[$i])];
		}
		return $result;
	}

	//使用编码数组编码

	//使用编码数组编码
	public static function urlDecode($value)
	{
		return urldecode($value);
	}
	//使用编码数组编码
	public static function build($value)
	{
		return http_build_url($value);
	}
	public static function parse($value)
	{
		return parse_url($value);
	}
	public static function parseQuery($query)
	{
		parse_str($query, $params);
		return $params;
	}
	public static function buildQuery($params=array(), $isQuery = false){
		$r = implode('&', self::buildParamsToArray($params, ''));
		if ($isQuery) {
			$r = str_replace("%20", "+", $r);
		}
		return $r;
	}

	/**
	 * @param $data
	 * @param $prefix
	 * @return array
	 */
	public static function buildParamsToArray($data, $prefix){
		$r = array();
		if (is_array($data)){
			if (self::isIndexArray($data)){
				for ($i=0; $i < count($data) ; $i++) {
					// 值
					$value = $data[$i];
					if (!isset($value)) continue;
					// 键
					$keyt = self::buildParamsAddPrefix($i, $prefix, is_array($value));
					if (is_array($value)){
						$r = array_merge($r, self::buildParamsToArray($value, $keyt));
					}else{
						$r[] = self::urlEncode($keyt) . '=' . self::urlEncode($value);
					}
				}
			}else{
				foreach ($data as $key => $value) {
					if (!isset($value)) continue;
					// 键
					$keyt = self::buildParamsAddPrefix($key, $prefix);
					if (is_array($value)){
						$r = array_merge($r, self::buildParamsToArray($value, $keyt));
					}else{
						$r[] = self::urlEncode($keyt) . '=' . self::urlEncode($value);
					}
				}
			}
		}
		return $r;
	}
	public static function buildParamsAddPrefix ($key, $prefix, $isNotArray = null) {
		if ($prefix) {
			return $prefix . '[' . ($isNotArray !== false ? $key : '') . ']';
		} else {
			return $key;
		}
	}

	public static function formatPath($path){
		$path = '/'.implode('/', array_filter(explode('/', $path)));
		// 强制/开头
		if (substr($path, 0, 1) !== '/') {
			$path = '/' . $path;
		}
		return $path;
	}

	/**
	 * 把数组中所以驼峰的key转小写下滑杠
	 * @param array $array [数组]
	 * @return array  [请求数组]
	 */
	public static function isIndexArray ($array = array()){
		return array_keys($array) === range(0, count($array) - 1);
	}
	public static function isAssocArray($array = array()){
		return !self::isIndexArray($array);
	}
}

// 根据RFC 3986，除了：
//   1.大小写英文字符
//   2.阿拉伯数字
//   3.点'.'、波浪线'~'、减号'-'以及下划线'_'
// 以外都要编码
Url::$PERCENT_ENCODED_STRINGS = array();
for ($i = 0; $i < 256; ++$i) {
	Url::$PERCENT_ENCODED_STRINGS[$i] = sprintf("%%%02X", $i);
}

//a-z不编码
foreach (range('a', 'z') as $ch) {
	Url::$PERCENT_ENCODED_STRINGS[ord($ch)] = $ch;
}

//A-Z不编码
foreach (range('A', 'Z') as $ch) {
	Url::$PERCENT_ENCODED_STRINGS[ord($ch)] = $ch;
}

//0-9不编码
foreach (range('0', '9') as $ch) {
	Url::$PERCENT_ENCODED_STRINGS[ord($ch)] = $ch;
}

//以下4个字符不编码
Url::$PERCENT_ENCODED_STRINGS[ord('-')] = '-';
Url::$PERCENT_ENCODED_STRINGS[ord('.')] = '.';
Url::$PERCENT_ENCODED_STRINGS[ord('_')] = '_';
Url::$PERCENT_ENCODED_STRINGS[ord('~')] = '~';