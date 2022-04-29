<?php
/*
Plugin Name: Easy Location
Plugin URI: https://fatesinger.com
Description: Easy Location
Version: 1.0.0
Author: Bigfa
Author URI: https://fatesinger.com
License: GPL2
*/

class Reader
{
	const IPV4 = 1;
	const IPV6 = 2;

	private $file       = NULL;
	private $fileSize   = 0;
	private $nodeCount  = 0;
	private $nodeOffset = 0;

	private $meta = [];

	private $database = '';

	/**
	 * Reader constructor.
	 * @param $database
	 * @throws \Exception
	 */
	public function __construct($database)
	{
		$this->database = $database;

		$this->init();
	}

	private function init()
	{
		if (is_readable($this->database) === FALSE) {
			throw new \InvalidArgumentException("The IP Database file \"{$this->database}\" does not exist or is not readable.");
		}
		$this->file = @fopen($this->database, 'rb');
		if ($this->file === FALSE) {
			throw new \InvalidArgumentException("IP Database File opening \"{$this->database}\".");
		}
		$this->fileSize = @filesize($this->database);
		if ($this->fileSize === FALSE) {
			throw new \UnexpectedValueException("Error determining the size of \"{$this->database}\".");
		}

		$metaLength = unpack('N', fread($this->file, 4))[1];
		$text = fread($this->file, $metaLength);

		$this->meta = json_decode($text, 1);

		if (!isset($this->meta['fields']) || !isset($this->meta['languages'])) {
			throw new \Exception('IP Database metadata error.');
		}

		$fileSize = 4 + $metaLength + $this->meta['total_size'];
		if ($fileSize != $this->fileSize) {
			throw  new \Exception('IP Database size error.');
		}

		$this->nodeCount = $this->meta['node_count'];
		$this->nodeOffset = 4 + $metaLength;
	}

	/**
	 * @param $ip
	 * @param string $language
	 * @return array|NULL
	 */
	public function find($ip, $language = 'CN')
	{
		if (is_resource($this->file) === FALSE) {
			throw new \BadMethodCallException('closed IPIP DB.');
		}

		if (!isset($this->meta['languages'][$language])) {
			throw new \InvalidArgumentException("language : {$language} not support");
		}

		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) === FALSE) {
			throw new \InvalidArgumentException("The value \"$ip\" is not a valid IP address.");
		}

		if (strpos($ip, '.') !== FALSE && !$this->supportV4()) {
			throw new \InvalidArgumentException("The Database not support IPv4 address.");
		} elseif (strpos($ip, ':') !== FALSE && !$this->supportV6()) {
			throw new \InvalidArgumentException("The Database not support IPv6 address.");
		}

		try {
			$node = $this->findNode($ip);
			if ($node > 0) {
				$data = $this->resolve($node);

				$values = explode("\t", $data);

				return array_slice($values, $this->meta['languages'][$language], count($this->meta['fields']));
			}
		} catch (\Exception $e) {
			return NULL;
		}

		return NULL;
	}

	public function findMap($ip, $language = 'CN')
	{
		$array = $this->find($ip, $language);
		if (NULL == $array) {
			return NULL;
		}

		return array_combine($this->meta['fields'], $array);
	}

	/**
	 * @param $ip
	 * @return int
	 * @throws \Exception
	 */
	private function findNode($ip)
	{
		static $v4offset = 0;
		static $v6offsetCache = [];

		$binary = inet_pton($ip);
		$bitCount = strlen($binary) * 8; // 32 | 128
		$key = substr($binary, 0, 2);
		$node = 0;
		$index = 0;
		if ($bitCount === 32) {
			if ($v4offset === 0) {
				for ($i = 0; $i < 96 && $node < $this->nodeCount; $i++) {
					if ($i >= 80) {
						$idx = 1;
					} else {
						$idx = 0;
					}
					$node = $this->readNode($node, $idx);
					if ($node > $this->nodeCount) {
						return 0;
					}
				}
				$v4offset = $node;
			} else {
				$node = $v4offset;
			}
		} else {
			if (isset($v6offsetCache[$key])) {
				$index = 16;
				$node = $v6offsetCache[$key];
			}
		}

		for ($i = $index; $i < $bitCount; $i++) {
			if ($node >= $this->nodeCount) {
				break;
			}

			$node = $this->readNode($node, 1 & ((0xFF & ord($binary[$i >> 3])) >> 7 - ($i % 8)));

			if ($i == 15) {
				$v6offsetCache[$key] = $node;
			}
		}

		if ($node === $this->nodeCount) {
			return 0;
		} elseif ($node > $this->nodeCount) {
			return $node;
		}

		throw new \Exception("find node failed");
	}

	/**
	 * @param $node
	 * @param $index
	 * @return mixed
	 * @throws \Exception
	 */
	private function readNode($node, $index)
	{
		return unpack('N', $this->read($this->file, $node * 8 + $index * 4, 4))[1];
	}

	/**
	 * @param $node
	 * @return mixed
	 * @throws \Exception
	 */
	private function resolve($node)
	{
		$resolved = $node - $this->nodeCount + $this->nodeCount * 8;
		if ($resolved >= $this->fileSize) {
			return NULL;
		}

		$bytes = $this->read($this->file, $resolved, 2);
		$size = unpack('N', str_pad($bytes, 4, "\x00", STR_PAD_LEFT))[1];

		$resolved += 2;

		return $this->read($this->file, $resolved, $size);
	}

	public function close()
	{
		if (is_resource($this->file) === TRUE) {
			fclose($this->file);
		}
	}

	/**
	 * @param $stream
	 * @param $offset
	 * @param $length
	 * @return bool|string
	 * @throws \Exception
	 */
	private function read($stream, $offset, $length)
	{
		if ($length > 0) {
			if (fseek($stream, $offset + $this->nodeOffset) === 0) {
				$value = fread($stream, $length);
				if (strlen($value) === $length) {
					return $value;
				}
			}

			throw new \Exception("The Database file read bad data");
		}

		return '';
	}

	public function supportV6()
	{
		return ($this->meta['ip_version'] & self::IPV6) === self::IPV6;
	}

	public function supportV4()
	{
		return ($this->meta['ip_version'] & self::IPV4) === self::IPV4;
	}
}

if (!function_exists('get_user_city')) :
	function get_user_city($ip)
	{
		$reader = new Reader(__DIR__ . '/ipipfree.ipdb');
		try {
			return $reader->find($ip) ? $reader->find($ip)[1] : false;
		} catch (\Throwable $th) {
			return false;
		}
	}
endif;

if (!function_exists('easy_location_handle_comment')) :
	function easy_location_handle_comment($comment_text)
	{
		$comment_ID = get_comment_ID();
		$comment = get_comment($comment_ID);
		if ($comment->comment_author_IP && get_user_city($comment->comment_author_IP)) {
			$comment_text .= '<div class="comment--location"><svg version="1.1" viewBox="0 0 368.666 368.666"  width="14" height="14"><g><path d="M184.333,0C102.01,0,35.036,66.974,35.036,149.297c0,33.969,11.132,65.96,32.193,92.515
		c27.27,34.383,106.572,116.021,109.934,119.479l7.169,7.375l7.17-7.374c3.364-3.46,82.69-85.116,109.964-119.51
		c21.042-26.534,32.164-58.514,32.164-92.485C333.63,66.974,266.656,0,184.333,0z M285.795,229.355
		c-21.956,27.687-80.92,89.278-101.462,110.581c-20.54-21.302-79.483-82.875-101.434-110.552
		c-18.228-22.984-27.863-50.677-27.863-80.087C55.036,78.002,113.038,20,184.333,20c71.294,0,129.297,58.002,129.296,129.297
		C313.629,178.709,304.004,206.393,285.795,229.355z" /><path d="M184.333,59.265c-48.73,0-88.374,39.644-88.374,88.374c0,48.73,39.645,88.374,88.374,88.374s88.374-39.645,88.374-88.374
		S233.063,59.265,184.333,59.265z M184.333,216.013c-37.702,0-68.374-30.673-68.374-68.374c0-37.702,30.673-68.374,68.374-68.374
		s68.373,30.673,68.374,68.374C252.707,185.341,222.035,216.013,184.333,216.013z" /></g></svg>来自' . get_user_city($comment->comment_author_IP) . '</div>';
		}
		return $comment_text;
	}
endif;

if (!function_exists('easy_location_styles')) :
	function easy_location_styles()
	{
		echo "<style>.comment--location {
			display: flex;
			margin-top: 8px;
			align-items: center;
			font-size: 14px!important;
			padding-left: 10px;
			color: rgba(0,0,0,.5)!important;
			fill: rgba(0,0,0,.5)!important;
		}
		.comment--location svg {
			margin-right: 5px;
		}
		</style>";
	}
endif;

add_filter('comment_text', 'easy_location_handle_comment');
add_action('wp_head', 'easy_location_styles', 100);
