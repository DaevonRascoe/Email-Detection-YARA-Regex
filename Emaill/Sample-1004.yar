rule detect_phishing_email {
    Meta:
        description = YARA rule to detect sample-1004.eml from phishing_pot
        author = Daevon Rascoe
        date = 2024-02-06
    strings:
        $from_string = "from:"
        $return_path_string = "return-path:"

        $header1 = "Received: from DS7PR19MB5974.namprd19.prod.outlook.com"
        $header2 = "Received: from FR0P281CA0242.DEUP281.PROD.OUTLOOK.COM"
        $header3 = "Received: from VI1EUR04FT036.eop-eur04.prod.protection.outlook.com"

        $subject = "Subject: Seus pontos Livelo expiram em breve - PROTOCOLO:" [0-9]+/
        $content_type = "Content-type: text\/html; charset=UTF-8/ "
        $spf_temperror = "Authentication-Results: spf=temperror"
        $sender_IP = "sender IP is 147.182.193.196"
            $content_type = "Content-type: text\/html; charset=UTF-8/ "

    condition:
        $from_string and $return_path_string and
        for any i in (1..#from_string): 
            $from_string[i] != $return_path_string[i]

        3 of ($header*) and $from_address and $subject and $message_id and $date and $content_type and $return_path and $x_ms_exchange_org and $mime_version
}
