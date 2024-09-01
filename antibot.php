<?php
session_start();
include 'config.php';

// Met les données de l'utilisateur en minuscule pour une comparaison de meilleur qualité
$ip = $_SERVER['REMOTE_ADDR'];
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$headers = getallheaders();

$blacklist = [

    // Firme suspecte
    '/alibaba/', '/cloudflare/', '/aws/', '/google/', '/microsoft/', '/ovh/', '/digitalocean/', '/linode/', '/vultr/', '/hetzner/',
    '/proxymesh/', '/smartproxy/', '/luminati/', '/geosurf/', '/scraperapi/', '/mordern/', '/shadowsocks/', '/torguard/', '/nordvpn/', '/purevpn/',
    '/surfshark/', '/expressvpn/', '/cyberghost/', '/hidemyass/', '/zenmate/', '/windscribe/', '/tunnelbear/', '/ipvanish/', '/privadovpn/', '/strongvpn/',
    '/pia/', '/hidemyip/', '/unblocker/', '/proxyscape/', '/proxyrack/', '/webshare/', '/proxycrawl/', '/bright data/', '/storm proxies/', '/hma/',
    '/noobox/', '/anonymizer/', '/keenetic/', '/dia/', '/turbovpn/', '/iprovpn/', '/cactusvpn/', '/vpn.ac/', '/browsec/', '/holavpn/',
    '/vpnbook/', '/getflix/', '/unlocator/', '/cloak/', '/unblock-us/', '/myprivateproxy/', '/thesocialproxy/', '/proxify/', '/proxyvip/', '/vpn.ht/',
    '/proxyserver/', '/proxies24/', '/vpnshadows/', '/proxyip/', '/justvpn/', '/proxyway/', '/vpnfast/', '/vpnserver/', '/fastvpn/',
    '/anonymousvpn/', '/vpnhouse/', '/shieldvpn/', '/privatevpn/', '/trustzone/', '/vpninja/', '/eliteproxy/', '/socksproxy/', '/proxyland/', '/globalvpn/',
    '/vpn-by/', '/proxygeek/', '/cybervpn/', '/securevpn/', '/quickvpn/', '/proxyzilla/', '/stormvpn/', '/ultravpn/', '/onevpn/', '/zvpn/',
    '/skyvpn/', '/betternet/', '/vpnkey/', '/vpn2go/', '/vpnssecure/', '/freevpn/', '/vpnpro/', '/quickproxy/', '/elitevpn/', '/globalproxy/',
    '/ultraproxy/', '/stealthvpn/', '/proxifyvpn/', '/vpnway/', '/socks5proxy/', '/proxyexpert/', '/rapidvpn/', '/proxybot/', '/vpnfastly/', '/proxyhub/',
    '/webvpn/', '/netshield/', '/safevpn/', '/secureproxy/', '/vpnsharp/', '/anonymousproxy/', '/fastproxy/', '/vpncentral/', '/vpnzone/', '/proxystar/',
    '/vpnlab/', '/proxysafe/', '/hidemyproxy/', '/instantvpn/', '/trustvpn/', '/proxyguard/', '/vpncloud/', '/ultraproxy/', '/netvpn/', '/proxyking/',
    '/proxifier/', '/vpncom/', '/vnguard/', '/proxyhost/', '/netguardvpn/', '/proxytiger/', '/socksproxyvpn/', '/vnglobal/', '/primevpn/', '/tunnelproxy/',
    '/darknetvpn/', '/vpnx/', '/proxyprovider/', '/globalshield/', '/eliteguardvpn/', '/anonymoustunnel/', '/securenetvpn/', '/proxymaster/', '/speedvpn/', '/proxylink/',
    '/swiftvpn/', '/safeproxy/', '/ultrashieldvpn/', '/globalnetvpn/', '/primeshield/', '/netshieldvpn/', '/rapidproxy/', '/securetunnel/', '/proxyforce/', '/cyberproxy/',
    '/vpnstation/', '/vnguard/', '/maxproxy/', '/quickshieldvpn/', '/cybershieldvpn/', '/trustguardvpn/', '/proxyzone/', '/netnetvpn/', '/vexpert/', '/supervpn/',
    '/cybergatevpn/', '/shieldnetvpn/', '/proxynator/', '/netshieldpro/', '/proxydrive/', '/vpnportal/', '/securevpnpro/', '/elitetunnel/', '/proxywave/', '/shieldlinkvpn/',
    '/vpnxtreme/', '/maxnetvpn/', '/rapidshieldvpn/', '/primenetvpn/', '/globaltunnelvpn/', '/proxyextreme/', '/netsecurevpn/', '/elitenetvpn/', '/turbotunnelvpn/', '/safenetvpn/',
    '/fastguardvpn/', '/primetunnel/', '/ultratunnelvpn/', '/securewavevpn/', '/quicknetvpn/', '/proxystorm/', '/vpnflash/', '/nettunnelvpn/', '/speedtunnelvpn/', '/cyberlinkvpn/',
    '/eliteproxyvpn/', '/globaltunnel/', '/maxtunnelvpn/', '/cybermaxvpn/', '/rapidnetvpn/', '/safunnel/', '/vpnmax/', '/netmaxvpn/', '/ultraguardvpn/', '/primeguardvpn/',
    '/vpnprox/', '/globalguardvpn/', '/secureproxynet/', '/quickproxynet/', '/rapidtunnelvpn/', '/maxguardvpn/', '/cybernetvpn/', '/safeproxynet/', '/elitewavevpn/', '/turbonetvpn/',
    '/anonymouse/', '/proxylist/', '/vpnbook/', '/socksproxy/', '/vpnjunkie/', '/anonymousvpn/', '/foxyproxy/', '/proxymesh/', '/anonymousproxy/', '/proxyshark/',
    '/proxydrop/', '/vpn4all/', '/proxyking/', '/vpnlist/', '/mysecurevpn/', '/yourprivateproxy/', '/securemyvpn/', '/mysecureproxy/', '/proxygenius/', '/securetunnelvpn/',
    '/proxizen/', '/tunnelmaster/', '/quickvpn/', '/nettunnel/', '/privatetunnel/', '/stealthproxy/', '/invisiblevpn/', '/shieldproxy/', '/securelinkvpn/', '/proxifyvpn/',
    '/cybersafevpn/', '/eliteprotectvpn/', '/primenetproxy/', '/netguardproxy/', '/maxguardproxy/', '/rapidtunnel/', '/safenetproxy/', '/ultratunnel/', '/elitetunnelvpn/', '/globalguard/',
    '/turbovpn/', '/primeproxy/', '/safeguardvpn/', '/rapidnet/', '/stealthnetvpn/', '/invisibleproxy/', '/quickguardvpn/', '/netsecureproxy/', '/vpnmaster/', '/elitesafevpn/',
    '/cyberguardvpn/', '/globaltunnelproxy/', '/maxtunnelproxy/', '/primetunnelproxy/', '/ultranetvpn/', '/rapidtunnelvpn/', '/securewavevpn/', '/quicktunnelvpn/', '/safeproxvpn/', '/invisibletunnel/',
    '/stealthguardvpn/', '/elitenetproxy/', '/turbonetproxy/', '/safetunnelvpn/', '/globalprotectvpn/', '/maxsecurevpn/', '/quickprotectvpn/', '/cybertunnelvpn/', '/primeguardproxy/', '/netshieldproxy/',
    '/rapidnetproxy/', '/ultrasecurevpn/', '/safewavevpn/', '/cybersafeproxy/', '/eliteguardproxy/', '/turboprotectvpn/', '/netnetproxy/', '/globaltunnelvpn/', '/maxwavevpn/', '/primenetunnel/',
    '/rapidwavevpn/', '/stealthnetproxy/', '/securenetproxy/', '/quicksafevpn/', '/elitetunnelproxy/', '/turbowavevpn/', '/safenetunnel/', '/invisiblenetvpn/', '/primetunnelproxy/', '/globalshieldproxy/',
    '/maxprotectvpn/', '/rapidtunnelproxy/', '/ultratunnelproxy/', '/safetunnelproxy/', '/stealthwavevpn/', '/quicknetproxy/', '/cyberprotectvpn/', '/elitesafeproxy/', '/globalguardproxy/', '/turboguardvpn/',
    '/primesecurevpn/', '/nettunnelproxy/', '/maxguardproxy/', '/stealthtunnelvpn/', '/safenetproxy/', '/rapidsafevpn/', '/ultranetproxy/', '/quicktunnelproxy/', '/invisibleprotectvpn/', '/globalwavevpn/',
    '/maxsecureproxy/', '/stealthnetvpn/', '/primesafeproxy/', '/netguardproxy/', '/cybernetvpn/', '/elitewaveproxy/', '/globaltunnelproxy/', '/turbonettunnel/', '/safenetguard/', '/rapidprotectproxy/',
    '/primenetprotect/', '/quickguardproxy/', '/stealthtunnelproxy/', '/ultraprotectvpn/', '/globalsafevpn/', '/maxtunnelprotect/', '/cyberwavevpn/', '/rapidnetprotect/', '/primetunnelprotect/', '/netwavevpn/',
    '/stealthproxyvpn/', '/globalsecuretunnel/', '/turboprotectproxy/', '/safettunnelprotect/', '/elitetunnelprotect/', '/maxwaveproxy/', '/primeguardtunnel/', '/netsecuretunnel/', '/rapidsafettunnel/', '/ultraguardproxy/',
    '/quicksafeproxy/', '/cybernetprotect/', '/stealthnetprotect/', '/globaltunnelprotect/', '/turbosafvpn/', '/maxnettunnel/', '/primetunnelvpn/', '/safe.waveproxy/', '/netprotectproxy/', '/rapidguardvpn/',
    '/elitesafetunnel/', '/globalsafetunnel/', '/stealthwaveproxy/', '/maxsecureprotect/', '/quickprotectproxy/', '/turbotunnelprotect/', '/primesafettunnel/', '/netsafproxy/', '/cyberguardtunnel/', '/elitewavevpn/',


    // Service suspect
    '/scrapingbee/', '/dataminer/', '/octoparse/', '/parsehub/', '/webharvy/', '/diffbot/', '/content grabber/', '/import.io/', '/mozenda/', '/kapow/',
    '/bright data/', '/zyte/', '/proxycrawl/', '/scraperapi/', '/web scraper io/', '/crawlera/', '/scrapinghub/', '/apify/', '/common crawl/', '/datasift/',
    '/web robot/', '/graphtap/', '/scrapingstorm/', '/botstar/', '/datagrabber/', '/scrapingrobot/', '/spinn3r/', '/datadome/', '/botsify/',
    '/oxylabs/', '/smartproxy/', '/geosurf/', '/luminati/', '/storm proxies/', '/proxymesh/', '/crawlera/', '/zyte/', '/proxyrack/', '/netnut/',
    '/webproxies/', '/publicproxyservers/', '/iproyal/', '/proxyseller/', '/buyproxies/', '/myprivateproxy/', '/highproxies/', '/squidproxies/',
    '/blazing seo/', '/ssl private proxy/', '/vip72/', '/hma vpn/', '/purevpn/', '/nordvpn/', '/cyberghost/', '/hidemyass/', '/surfshark/', '/tunnelbear/',
    '/private internet access \(pia\)/', '/zenmate/', '/windscribe/', '/ivacy/', '/safervpn/', '/trust\.zone/', '/kaspersky vpn/', '/avira phantom vpn/',
    '/mullvad/', '/protonvpn/', '/vpn.ac/', '/perfect privacy/', '/goonet/', '/proxy-n-vpn/', '/anonymous proxy/', '/ipvanish/', '/hide\.me/',
    '/unblock-us/', '/spotflux/', '/strongvpn/', '/vpnbook/', '/hola vpn/', '/torguard/', '/vpn\.ht/', '/frootvpn/', '/vpncity/', '/cactusvpn/',
    '/vpnbook/', '/betternet/', '/proxysite/', '/kproxy/', '/hidemy\.name/', '/getproxy/', '/whoer\.net/', '/proxy4free/', '/freeproxylist/', '/us-proxy\.org/',
    '/socks-proxy\.net/', '/proxylistplus/', '/spys\.one/', '/proxyscrape/', '/proxybunker/', '/vpn\.proxy/', '/proxymesh/', '/hushpuppy/',
    '/net-proxy/', '/proxify/', '/proxy-store/', '/proxyhero/', '/ultraproxy/', '/vpnproxy/', '/proxyfree/', '/ip-proxy/', '/proxynow/', '/bestproxy/',
    '/hidemyproxy/', '/megaproxy/', '/proxyninja/', '/proxies\.com/', '/freeproxylist\.net/', '/socksproxylists/', '/proxylist\.org/', '/proxymesh\.com/',
    '/proxylistplus\.com/', '/proxyscrape\.com/', '/spysone\.com/', '/hidemyass\.com/', '/proxy-store\.com/', '/proxyhero\.com/', '/ultraproxy\.com/',
    '/proxynow\.com/', '/bestproxy\.com/', '/hidemyproxy\.com/', '/megaproxy\.com/', '/proxyninja\.com/', '/proxies\.com/', '/socksproxylists\.net/',
    '/freeproxylist\.org/', '/proxy-store\.org/', '/proxyhero\.net/', '/ultraproxy\.net/', '/proxynow\.net/', '/bestproxy\.net/', '/hidemyproxy\.net/',
    '/megaproxy\.net/', '/proxyninja\.net/', '/proxies\.net/', '/socksproxylists\.org/', '/freeproxylist\.net/', '/proxylistplus\.net/', '/spysone\.net/',
    '/proxyscrape\.net/', '/proxymesh\.org/', '/proxylistplus\.org/', '/proxy-store\.com/', '/proxyhero\.org/', '/ultraproxy\.org/', '/proxynow\.org/',
    '/bestproxy\.org/', '/hidemyproxy\.org/', '/megaproxy\.org/', '/proxyninja\.org/', '/proxies\.org/', '/socksproxylists\.com/', '/freeproxylist\.com/',
    '/proxy-store\.co/', '/proxyhero\.co/', '/ultraproxy\.co/', '/proxynow\.co/', '/bestproxy\.co/', '/hidemyproxy\.co/', '/megaproxy\.co/', '/proxyninja\.co/',
    '/proxies\.co/', '/socksproxylists\.co/', '/freeproxylist\.co/', '/proxylistplus\.co/', '/spysone\.co/', '/proxyscrape\.co/', '/proxymesh\.co/',
    '/proxylistplus\.co/', '/proxy-store\.biz/', '/proxyhero\.biz/', '/ultraproxy\.biz/', '/proxynow\.biz/', '/bestproxy\.biz/', '/hidemyproxy\.biz/',
    '/megaproxy\.biz/', '/proxyninja\.biz/', '/proxies\.biz/', '/socksproxylists\.biz/', '/freeproxylist\.biz/', '/proxylistplus\.biz/', '/spysone\.biz/',
    '/proxyscrape\.biz/', '/proxymesh\.biz/', '/hushpuppy\.biz/', '/proxy-store\.biz/', '/net-proxy\.biz/', '/anonymousproxy\.biz/', '/ip-proxy\.biz/', '/bestproxy\.biz/',
    '/proxynow\.biz/', '/proxyninja\.biz/', '/proxies\.biz/', '/socksproxylists\.biz/', '/freeproxylist\.biz/', '/proxylistplus\.biz/', '/spysone\.biz/', '/proxyscrape\.biz/'
];

$suspiciousPatterns = [
    '/python/i', '/curl/i', '/wget/i', '/scrapy/i', '/postmanruntime/i', '/bot/i', '/spider/i', '/crawl/i',
    '/httpclient/i', '/java/i', '/libwww-perl/i', '/php/i', '/ruby/i', '/node.js/i', '/requests/i',
    '/selenium/i', '/phantomjs/i', '/httplib/i', '/lwp/i', '/mechanize/i', '/django/i',
    '/apache-httpclient/i', '/http-headers/i', '/googlebot/i', '/bingbot/i', '/yahoo! slurp/i',
    '/baidu/i', '/duckduckbot/i', '/facebookexternalhit/i', '/twitterbot/i', '/linkedinbot/i',
    '/t.co/i', '/applebot/i', '/msnbot/i', '/yandexbot/i', '/sogou/i', '/exabot/i', '/ia_archiver/i',
    '/pinterest/i', '/bitly/i', '/whatsapp/i', '/telegrambot/i', '/feedly/i', '/slackbot/i',
    '/upflow/i', '/surveybot/i', '/nutch/i', '/wget/i', '/paws/i', '/crawler/i', '/netcraft/i',
    '/browsershots/i', '/archive.org/i', '/screenshot/i', '/openlinkprofiler/i', '/sitebot/i',
    '/crawlher/i', '/fbcli/i', '/riddler/i', '/dataminer/i', '/duke/i', '/scrapbot/i',
    '/python-requests/i', '/crawling/i', '/webscraper/i', '/urlmon/i', '/outwit/i',
    '/hacker/i', '/robot/i', '/bingpreview/i', '/virtualbox/i', '/diskpace/i', '/scraper/i',
    '/robocrawler/i', '/linkextractor/i', '/webcrawler/i', '/auto-i/i', '/reachbot/i',
    '/datacollect/i', '/benjo/i', '/browser/i', '/googlebot/i', '/linkbot/i'
];





function isSuspiciousIP($ip) {
    global $blacklist, $suspiciousFirms;

    $url = "http://ip-api.com/json/{$ip}";

    $response = file_get_contents($url);
    if ($response === FALSE) {
        return false;
    }

    $data = json_decode($response, true);

    if (!isset($data['isp']) || !isset($data['org']) || !isset($data['as'])) {
        return false;
    }

    $isp = strtolower($data['isp']);
    $organization = strtolower($data['org']);
    $as = strtolower($data['as']);

    // Vérifier contre la blacklist
    foreach ($blacklist as $entry) {
        if (strpos($isp, $entry) !== false || strpos($organization, $entry) !== false || strpos($as, $entry) !== false) {
            return true;
        }
    }

    // Si aucune correspondance considérer l'IP comme non suspecte
    return false;
}


function loadBlacklistedIPs($filename) {
    $blacklistedIPs = [];

    if (file_exists($filename)) {
        $file = fopen($filename, 'r');
        while (($line = fgets($file)) !== false) {
            $blacklistedIPs[] = trim(strtolower($line));
        }
        fclose($file);
    } else {
        throw new Exception("Le fichier de blacklist n'existe pas.");
    }

    return $blacklistedIPs;
}

function analyzeRequest($userAgent, $headers, $ip) {
    global $suspiciousPatterns, $blacklist;


    // Charger les IP blacklistées
    try {
        $blacklistedIPs = loadBlacklistedIPs('blacklist.txt');
    } catch (Exception $e) {
        return "Erreur de chargement du fichier blacklist: " . $e->getMessage();
    }

    // Vérifie si l'IP est blacklistée localement
    if (in_array($ip, $blacklistedIPs)) {
        return "BLACKLISTED_IP";
    }

    // Vérifie le navigateur de l'utilisateur
    foreach ($suspiciousPatterns as $pattern) {
        if (preg_match($pattern, $userAgent)) {
            return "SUSPICIOUS_NAV";
        }
    }

    // Vérifie l'absence de mention de firme dans l'entête de l'utilisateur 
    foreach ($headers as $header => $value) {
        foreach ($blacklist as $firm) {
            if (preg_match($firm, $value)) {
                return "SUSPICIOUS_HEADER";
            }
        }
    }

    // Vérifie si un proxy est utilisé en détectant des en-têtes spécifiques
    $proxyHeaders = ['X-Forwarded-For', 'X-Real-IP', 'Via', 'Forwarded', 'Client-IP', 'True-Client-IP'];
    foreach ($proxyHeaders as $proxyHeader) {
        if (isset($headers[$proxyHeader])) {
            return "PROXY_DETECTED";
        }
    }

    return "RAS";
}

function analyzeUserBehavior() {
    include 'config.php';

    // initialisation si c'est bien la première visite de l'utilisateur
    if (!isset($_SESSION['behavior'])) {
        $_SESSION['behavior'] = [
            'last_request_time' => time(),
            'request_count' => 0,
            'visited_pages' => [],
            'suspicious_actions' => 0,
            'last_user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'page_refresh_count' => 0,
            'last_ip_address' => $_SERVER['REMOTE_ADDR'],
        ];
    }

    $currentTime = time();
    $timeSinceLastRequest = $currentTime - $_SESSION['behavior']['last_request_time'];
    $_SESSION['behavior']['last_request_time'] = $currentTime;
    $_SESSION['behavior']['request_count'] += 1;

    // enregistre la page visitée
    $currentUrl = $_SERVER['REQUEST_URI'];
    if (!in_array($currentUrl, $_SESSION['behavior']['visited_pages'])) {
        $_SESSION['behavior']['visited_pages'][] = $currentUrl;
    } else {
        // Si la même page est visitée plusieurs fois, augmenter le compteur de rafraîchissements
        $_SESSION['behavior']['page_refresh_count'] += 1;
    }

    // Analyse du comportement ---------------------------------------------------------------------------------------------------------------------------

    // Vérifie si les requêtes sont trop fréquentes
    if ($timeSinceLastRequest < $timingBetwenRequests) {
        $_SESSION['behavior']['suspicious_actions'] += 1;
    }

    // Détecte les changements fréquents d'agent utilisateur
    if ($useragentSwitcherDetector){
        $currentUserAgent = $_SERVER['HTTP_USER_AGENT'];
        if ($_SESSION['behavior']['last_user_agent'] !== $currentUserAgent) {
            $_SESSION['behavior']['suspicious_actions'] += 1;
            $_SESSION['behavior']['last_user_agent'] = $currentUserAgent;
        }
    }


    // Vérifie si l'adresse IP a changé (peut indiquer un comportement suspect ou un utilisateur utilisant un proxy)
    if ($ipSwitcherDetector){
        $currentIpAddress = $_SERVER['REMOTE_ADDR'];
        if ($_SESSION['behavior']['last_ip_address'] !== $currentIpAddress) {
            $_SESSION['behavior']['suspicious_actions'] += 1;
            $_SESSION['behavior']['last_ip_address'] = $currentIpAddress;
        }
    }


    // Détecte un nombre inhabituel de requêtes (par exemple, plus de 100 requêtes en 5 minutes)
    if ($_SESSION['behavior']['request_count'] > $exceedRequests && ($currentTime - $_SESSION['behavior']['last_request_time']) < 300) {
        $_SESSION['behavior']['suspicious_actions'] += 1;
    }

    // Marque l'utilisateur comme suspect si le nombre d'actions suspectes dépasse un seuil
    if ($_SESSION['behavior']['suspicious_actions'] > $suspiciousActionNumber) {
        return "SUSPICIOUS_BEHAVIOR";
    }

    return "NORMAL_BEHAVIOR";
}


if ($antibot) {
    $result = analyzeRequest($userAgent, $headers, $ip);
    $suspiciousIP = isSuspiciousIP($ip);
    
    // Applications des fonctions
    
    if ($userBehaviorMonitoring){
        $behaviorAnalysisResult = analyzeUserBehavior();
        if ($behaviorAnalysisResult == "SUSPICIOUS_BEHAVIOR"){
            if ($debugMode == True){
                echo "IP blacklisted : $ip<br>";
                echo "Reason: $behaviorAnalysisResult";
            }
            else{
                header("Location: $redirection");
            }
        }
    }
    
    if ($checkingIP == True){
        if ($suspiciousIP == True){
            if ($debugMode == True){
                echo "IP blacklisted : $ip<br>";
                echo "Reason: SUSPICIOUS_IP";
            }
            else{
                header("Location: $redirection");
            }
        }
        elseif ($result == "BLACKLISTED_IP"){
            if ($debugMode == True){
                echo "IP blacklisted : $ip<br>";
                echo "Reason: BLACKLISTED_IP";
            }
            else{
                header("Location: $redirection");
            }
        }
        
    }
    
    if ($checkingNav == True){
        if ($result == "SUSPICIOUS_NAV"){
            if ($debugMode == True){
                echo "Suspicious User-Agent : $userAgent";
            }
            else{
                header("Location: $redirection");
            }
        }
    }
    
    if ($checkingHeader == True){
        if ($result == "SUSPICIOUS_HEADER"){
            if ($debugMode == True){
                echo "Suspicious Header : $headers";
            }
            else{
                header("Location: $redirection");
            }
        }
    }

    if ($checkingHeader == True){
        if ($result == "PROXY_DETECTED"){
            if ($debugMode == True){
                echo "Proxy detected : $ip";
            }
            else{
                header("Location: $redirection");
            }
        }
    }
    
    if ($suspiciousIP == False) {
        if ($result == "RAS"){
            if ($behaviorAnalysisResult == "NORMAL_BEHAVIOR") {
                if ($debugMode == True){
                    echo "RAS";
                }
            }
        }   
    }
}


?>

<!-- Honneypot -->

<style>
    .invisible-form {
        position: absolute;
        left: -9999px;
        top: -9999px;
    }
</style>
<body>
    <form class="invisible-form" action="honeypot.php" method="post">
        <input type="text" name="honeypot" value="test">
        <input type="submit" value="Submit">
    </form>
</body>
