/* 
This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
/*


rule DarkGate
{
    Meta:
            description: 
            author = Daevon Rascoe
            Date = 2024-01-23
    strings:
        $url1 = "https://hielee.com/qxz31"
        $url2 = "https://nathumvida.org"
        $url3 = "https://searcherbigdea1k.com:2351"
        $url4 = "https://kairoscounselingmi.com/"

        $url_hash1 = "96ca146b6bb95de35f61289c2725f979a2957ce54761aff5f37726a85f2f9e77"
        $url_hash2 = "e2a8a53e117f1dda2c09e5b83a13c99b848873a75b14d20823318840e84de243"   
        $url_hash3 = "237d1bca6e056df5bb16a1216a434634109478f882d3b1d58344c801d184f95d"
        $url_hash4 = "2f5af97b13b077a00218c60305b4eee5d88d14a9bd042beed286434c3fc6e084"
        $url_hash5 =  "fce452bcf10414ece8eee6451cf52b39211eb65ecaa02a15bc5809c8236369a4"
        $url_hash6 =  "ea8f893c080159a423c9122b239ec389939e4c3c1f218bdee16dde744e08188f"
        $url_hash7 =  "7562c213f88efdb119a9bbe95603946ba3beb093c326c3b91e7015ae49561f0f"


    condition:
        $text_string
}
