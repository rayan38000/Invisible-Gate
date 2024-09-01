<?php

include 'config.php';

$blacklistFile = 'blacklist.txt';

function addToBlacklist($ip, $blacklistFile) {
    $ip = trim($ip);
    if (!empty($ip)) {
        $currentBlacklist = file_exists($blacklistFile) ? file_get_contents($blacklistFile) : '';
        $blacklistEntries = array_map('trim', explode(PHP_EOL, $currentBlacklist));
        
        if (!in_array($ip, $blacklistEntries)) {
            file_put_contents($blacklistFile, $ip . PHP_EOL, FILE_APPEND);
        }
    }
}


if ($honeypot){
    // Vérifier le champ honeypot
    if (!empty($_POST['honeypot'])){

        $ipAddress = $_SERVER['REMOTE_ADDR'];
        addToBlacklist($ipAddress, $blacklistFile);
        header('Location: https://www.google.com');
        exit;
    
    }
}

exit;
?>
