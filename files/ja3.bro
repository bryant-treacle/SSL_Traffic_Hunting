# This Bro script appends JA3 to ssl.log
# Version 1.3 (June 2017)
#
# Authors: John B. Althouse (jalthouse@salesforce.com) & Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

module JA3;

export {
redef enum Log::ID += { LOG };
}

type TLSFPStorage: record {
       client_version:  count &default=0 &log;
       client_ciphers:  string &default="" &log;
       extensions:      string &default="" &log;
       e_curves:        string &default="" &log;
       ec_point_fmt:    string &default="" &log;
};

redef record connection += {
       tlsfp: TLSFPStorage &optional;
};

redef record SSL::Info += {
  ja3:            string &optional &log;
# LOG FIELD VALUES ##
#  ja3_version:  string &optional &log;
#  ja3_ciphers:  string &optional &log;
#  ja3_extensions: string &optional &log;
#  ja3_ec:         string &optional &log;
#  ja3_ec_fmt:     string &optional &log;
# Added for JA3 Lookup Table
ja3_desc:        string &optional &log;
};

# Google. https://tools.ietf.org/html/draft-davidben-tls-grease-01
const grease: set[int] = {
    2570,
    6682,
    10794,
    14906,
    19018,
    23130,
    27242,
    31354,
    35466,
    39578,
    43690,
    47802,
    51914,
    56026,
    60138,
    64250
};
const sep = "-";
event bro_init() {
    Log::create_stream(JA3::LOG,[$columns=TLSFPStorage, $path="tlsfp"]);
}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
{
if ( ! c?$tlsfp )
    c$tlsfp=TLSFPStorage();
    if ( is_orig == T ) {
        if ( code in grease ) {
            next;
        }
        if ( c$tlsfp$extensions == "" ) {
            c$tlsfp$extensions = cat(code);
        }
        else {
            c$tlsfp$extensions = string_cat(c$tlsfp$extensions, sep,cat(code));
        }
    }
}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec)
{
if ( !c?$tlsfp )
    c$tlsfp=TLSFPStorage();
    if ( is_orig == T ) {
        for ( i in point_formats ) {
            if ( point_formats[i] in grease ) {
            next;
            }
            if ( c$tlsfp$ec_point_fmt == "" ) {
            c$tlsfp$ec_point_fmt += cat(point_formats[i]);
            }
            else {
            c$tlsfp$ec_point_fmt += string_cat(sep,cat(point_formats[i]));
            }
        }
    }
}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
{
    if ( !c?$tlsfp )
    c$tlsfp=TLSFPStorage();
    if ( is_orig == T  ) {
        for ( i in curves ) {
            if ( curves[i] in grease ) {
            next;
            }
            if ( c$tlsfp$e_curves == "" ) {
                c$tlsfp$e_curves += cat(curves[i]);
            }
            else {
                c$tlsfp$e_curves += string_cat(sep,cat(curves[i]));
            }
        }
    }
}

@if ( Version::at_least("2.6") || ( Version::number == 20500 && Version::info$commit >= 944 ) )
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=1
@else
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=1
@endif
{
    if ( !c?$tlsfp )
    c$tlsfp=TLSFPStorage();
    c$tlsfp$client_version = version;
    for ( i in ciphers ) {
        if ( ciphers[i] in grease ) {
            next;
        }
        if ( c$tlsfp$client_ciphers == "" ) { 
            c$tlsfp$client_ciphers += cat(ciphers[i]);
        }
        else {
            c$tlsfp$client_ciphers += string_cat(sep,cat(ciphers[i]));
        }
    }
    local sep2 = ",";
    local ja3_string = string_cat(cat(c$tlsfp$client_version),sep2,c$tlsfp$client_ciphers,sep2,c$tlsfp$extensions,sep2,c$tlsfp$e_curves,sep2,c$tlsfp$ec_point_fmt);
    local tlsfp_1 = md5_hash(ja3_string);
    c$ssl$ja3 = tlsfp_1;

# Delcaration of JA3 Lookup table
local ja3_lookup_table : table[string] of string;

# Initialize lookup table
# Table last updated 9 May 2019 By Bryant Treacle
ja3_lookup_table["e4adf57bf4a7a2dc08e9495f1b05c0ea"]="Adium 1.5.10 (b)";
ja3_lookup_table["61d50e7771aee7f2f4b89a7200b4d45e"]="AcroCEF";
ja3_lookup_table["49a6cf42956937669a01438f26e7c609"]="AIM";
ja3_lookup_table["d5169d6e19447685bf6f1af8c055d94d"]="AirCanada Android App";
ja3_lookup_table["0bb402a703d08a608bf82763b1b63313"]="AirCanada Android App";
ja3_lookup_table["561145462cfc7de1d6a97e93d3264786"]="Airmail 3";
ja3_lookup_table["f6fd83a21f9f3c5f9ff7b5c63bbc179d"]="Alation Compose";
ja3_lookup_table["6003b52942a2e1e1ea72d802d153ec08"]="Amazon Music";
ja3_lookup_table["eb149984fc9c44d85ed7f12c90d818be"]="Amazon Music,Dreamweaver,Spotify";
ja3_lookup_table["662fdc668dd6af994a0f903dbcf25d66"]="Android App";
ja3_lookup_table["515601c4141e718865697050a7a1765f"]="Android Google API Access";
ja3_lookup_table["855953256ecc8e2b6d2360aff8e5d337"]="Android Webkit Thing";
ja3_lookup_table["99d8afeec9a4422120336ad720a5d692"]="Android Webkit Thing";
ja3_lookup_table["85bb8aa8e5ba373906348831bdbed41a"]="Android Webkit Thing";
ja3_lookup_table["5331a12866e19199b363f6e903381498"]="Android Webkit Thing";
ja3_lookup_table["5331a12866e19199b363f6e903381498"]="Android Webkit Thing";
ja3_lookup_table["25b72c88f837567856118febcca761e0"]="Android Webkit Thing";
ja3_lookup_table["8e3f1bf87bc652a20de63bfd4952b16a"]="AnypointStudio";
ja3_lookup_table["d4693422c5ce1565377aca25940ad80c"]="Apple Push Notification System, apple.WebKit.Networking,CalendarAgent,Go for Gmail";
ja3_lookup_table["69b2859aec70e8934229873fe53902fd"]="Apple Spotlight";
ja3_lookup_table["6b9b64bbe95ea112d02c8812fc2e7ef0"]="Apple Spotlight";
ja3_lookup_table["e5e4c0eeb02fdcf30af8235b4de07780"]="Apple Spotlight";
ja3_lookup_table["3e404f1e1b5a79e614d7543a79f3a1da"]="Apple Spotlight Search (OSX)";
ja3_lookup_table["97827640b0c15c83379b7d71a3c2c5b4"]="Apple SpotlightNetHelper (OSX)";
ja3_lookup_table["47e42b00af27b87721e526ff85fd2310"]="Apple usbmuxd iOS socket multiplexer";
ja3_lookup_table["5507277945374659a5b4572e1b6d9b9f"]="apple.geod";
ja3_lookup_table["f753495f2eab5155c61b760c838018f8"]="apple.geod";
ja3_lookup_table["ba40fea2b2638908a3b3b482ac78d729"]="apple.geod,parsecd,apple.photomoments";
ja3_lookup_table["474e73aea21d1e0910f25c3e6c178535"]="apple.WebKit.Networking";
ja3_lookup_table["eeeb5e7485f5e10cbc39db4cfb69b264"]="apple.WebKit.Networking";
ja3_lookup_table["63de2b6188d5694e79b678f585b13264"]="apple.WebKit.Networking,Chatter,FieldServiceApp,socialstudio";
ja3_lookup_table["7b343af1092863fdd822d6f10645abfb"]="apple.WebKit.Networking,itunesstored";
ja3_lookup_table["a312f9162a08eeedf7feb7a13cd7e9bb"]="apple.WebKit.Networking,Spotify,WhatsApp,Skype,iTunes";
ja3_lookup_table["b677934e592ece9e09805bf36cd68d8a"]="AppleWebKit/533.1 (KHTML like Gecko) Version/4.0 Mobile Safari/533.1";
ja3_lookup_table["1a6ef47ab8325fbb42c447048cea9167"]="AppleWebKit/533.1 (KHTML like Gecko) Version/4.0 Mobile Safari/533.1";
ja3_lookup_table["e1e03b911a28815836d79c5cdd900a20"]="AppleWebKit/534.30";
ja3_lookup_table["ef323f542a99ab12d6b5348bf039b7b4"]="AppleWebKit/534.30 (KHTML like Gecko) Version/4.0 Safari & Safari Mobile/534.30, AppleWebKit/534.30";
ja3_lookup_table["04e1f90d8719caabafb76d4a7b13c984"]="AppleWebKit/534.46 Mobile/9A334";
ja3_lookup_table["dc08cf4510f70bf16d4106ee22f89197"]="AppleWebKit/534.46, iOS AppleWebKit/534.46";
ja3_lookup_table["4049550d5f57eae67d958440bdc133e4"]="AppleWebKit/535 & Ubuntu Product Search";
ja3_lookup_table["eaa8a172289b09a6789a415d1faac4c9"]="AppleWebKit/600.7.12";
ja3_lookup_table["ef75a13be2ed7a82f16eefe6e84bc375"]="AppleWebKit/600.7.12 or 600.1.4";
ja3_lookup_table["c5c11e6105c56fd29cc72c3ac7a2b78b"]="AT&T Connect";
ja3_lookup_table["42215ee83bbf3a857a72ef42213cfbd6"]="Atlassian SourceTree (git library?) (Tested v1.6.21.0)";
ja3_lookup_table["1c8a17e58c20b49e3786fc61e0533e50"]="Atlassian SourceTree (Tested v1.6.21.0)";
ja3_lookup_table["4e5e5d9fbc43697be755696191fe649a"]="atom.io #1";
ja3_lookup_table["c94858c6eb06de179493b3fac847143e"]="atom.io #2";
ja3_lookup_table["58360f4f663a0f5657f415ac2f47fe1b"]="Aviator (Mystery 3rd) (37.0.2062.99) (OS X)";
ja3_lookup_table["5149f53b5554a31116f9d86237552ee3"]="Aviator Updates";
ja3_lookup_table["fa030dbcb2e3c7141d3c2803780ee8db"]="Battle.net,Dropbox";
ja3_lookup_table["0ef9ca1c10d3f186f5786e1ef3461a46"]="bitgo,ShapeShift";
ja3_lookup_table["b5d42ca0e68a39d5c0a294134a21f020"]="Blackberry";
ja3_lookup_table["add211c763889c665ae4ab675165cbc4"]="BlackBerry Browser (Tested BB10)";
ja3_lookup_table["a921515f014005af03fc1e2c4c9e66ce"]="BlackBerry Mail Client";
ja3_lookup_table["4692263d4130929ae222ef50816527ca"]="Blackberry Messenger (Android) 2";
ja3_lookup_table["32b0ae286d1612c82cad93b4880ee512"]="Blackbery Messenger (Android)";
ja3_lookup_table["5182f54f9c6e99d117d9dde3fa2b4cff"]="BlueCoat Proxy, Malware Test FP: zeuspandabanker-malspam-traffic";
ja3_lookup_table["cdec81515ccc75a5aa41eb3db22226e6"]="BlueJeans,CEPHtmlEngine";
ja3_lookup_table["5c1c89f930122bccc7a97d52f73bea2c"]="BOT: Ahrefs, hola_svc";
ja3_lookup_table["a1cb2295baf199acf82d11ba4553b4a8"]="BOT: GoogleBot";
ja3_lookup_table["706567223fbf37d112fba2d95b8ecac3"]="BOT: Qwant";
ja3_lookup_table["a4dc1c39a68bffec1cc7767472ac85a8"]="Browsershots";
ja3_lookup_table["01aead19a1b1780978f732e056b183a6"]="BrowserShots Script";
ja3_lookup_table["c3ca411515180e79c765dc2c3c8cea88"]="BurpSuite Free (1.6.01)";
ja3_lookup_table["93fbcdadc1bf98ff0e3c03e7f921edd1"]="BurpSuite Free (1.6.01)";
ja3_lookup_table["34f8cac266d07bfc6bd3966e99b54d00"]="BurpSuite Free (tested: 1.6.32 Kali)";
ja3_lookup_table["15617351d807aa3145547d0ad0c976cc"]="BurpSuite Free (tested: 1.6.32 Kali)";
ja3_lookup_table["8c5a50f1e833ed581e9cfc690814719a"]="BurpSuite Free (Tested: 1.7.03 on Windows 10), eclipse,JavaApplicationStub,idea";
ja3_lookup_table["17a40616b856ec472714cd144471e0e0"]="Candy Crush (testing iOS 8.3)";
ja3_lookup_table["424008725394c634a4616b8b1f2828a5"]="Charles,java,eclipse";
ja3_lookup_table["64bb259b446fe13f66bcd62d1f0d33df"]="Choqok 1.5 (KDE 4.14.18 Qt 4.8.6 on OpenSUSE 42.1)";
ja3_lookup_table["bec8267042d5885aa3acc07b4409cafc"]="Chrome (iOS)";
ja3_lookup_table["d54a0979516e607a1166e6efd157301c"]="Chrome (Possible 41.x)";
ja3_lookup_table["ac67a2d0e3bd59459c32c996b5985979"]="Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #1";
ja3_lookup_table["34dfce2bb848da7c5dafa4d475f0ba41"]="Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #2";
ja3_lookup_table["937edefedb6fe13f26d1a425ef1c15a5"]="Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #3";
ja3_lookup_table["a342d14afad3a448029ec808295ccce9"]="Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #4";
ja3_lookup_table["71e74faaed87acd177bd3b47a543f476"]="Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #5";
ja3_lookup_table["1d64ab25ad6f7258581d43077147b9b1"]="Chrome (tested: Version 46.0.2490.86 (64-bit) - OS X)";
ja3_lookup_table["230018e44608686b64907360b6def678"]="Chrome (tested: Version 46.0.2490.86 (64-bit) - OS X)";
ja3_lookup_table["dea05e8c68dfeb28003f21d22efc0aba"]="Chrome (tested: Version 46.0.2490.86 (64-bit) - OS X)";
ja3_lookup_table["62351d5ea3cd4f21f697965b10a9bbbe"]="Chrome 10, Chrome 10.0.648.82 (Chromium Portable 9.0)";
ja3_lookup_table["a9da823fe77cd3df081644249edbf395"]="Chrome 11 - 18, Chrome 11.0.696.16 - 18.0.1025.33 Chrome 11.0.696.16 (Chromium Portable 9.2)";
ja3_lookup_table["df4a50323dfcaf1789f72e4946a7be44"]="Chrome 19 - 20, Chrome 19.0.1084.15 - 20.0.1132.57, Chrome 21.0.1180.89, Chrome 22.0.1229.96 - 23.0.1271.64 Safari/537.11";
ja3_lookup_table["3c8cb61208e191af38b1fbef4eacd502"]="Chrome 22.0.1201.0, Chrome/22.0.1229.96";
ja3_lookup_table["1ef061c02d85b7e2654e11a9959096f4"]="Chrome 24.0.1312.57 - 28.0.1500.72 Safari/537.36";
ja3_lookup_table["89d37026246d4888e78e69af4f8d1147"]="Chrome 26.0.1410.43-27.0.1453.110 Safari/537.31";
ja3_lookup_table["206ee819879457f7536d2614695a5029"]="Chrome 29.0.1547.0";
ja3_lookup_table["bbc3992faa92affc0d835717ea557e99"]="Chrome 29.0.1547.62";
ja3_lookup_table["76d36fc79db002baa1b5e741fcd863bb"]="Chrome 29.0.1547.62";
ja3_lookup_table["dc3eaee99a9221345698f8a8b2f4fc3f"]="Chrome 30.0.0.0";
ja3_lookup_table["53c7ed581cbaf36951559878fcec4559"]="Chrome 30.0.1599.101";
ja3_lookup_table["fb8a6d2441ee9eaee8b560d48a8f59df"]="Chrome 31.0.1650.57 & 32.0.1700.76 Safari/537.36";
ja3_lookup_table["f7c4dc1d9595c27369a183a5df9f7b52"]="Chrome 31.0.1650.63";
ja3_lookup_table["16d7ebc398d772ef9969d2ed2a15f4c0"]="Chrome 33.0.1750.117";
ja3_lookup_table["f3136cf565acf70dd2f98ca652f43780"]="Chrome 33.0.1750.117";
ja3_lookup_table["af0ae1083ab10ac957e394c2e7ec4634"]="Chrome 33.0.1750.154";
ja3_lookup_table["ef3364da4d76c98a669cb828f2e5283a"]="Chrome 34.0.1847.116 & 35.0.1916.114 Safari/537.36";
ja3_lookup_table["4807d61f519249470ebed0b633e707cf"]="Chrome 34.0.1847.116 & 35.0.1916.114 Safari/537.36";
ja3_lookup_table["52be6e88840d2211a243d9356550c4a5"]="Chrome 36.0.1985.125 - 40.0.2214.93 Safari/537.36";
ja3_lookup_table["5b348680dec77f585cfe82513213ac3a"]="Chrome 36.0.1985.125 & 37.0.2062.102 Safari/537.36";
ja3_lookup_table["a167568462b993d5787488ece82a439a"]="Chrome 37.0.0.0";
ja3_lookup_table["5f775bbfc50459e900d464ca1cecd136"]="Chrome 37.0.0.0 Safari & Mobile Safari/537.36";
ja3_lookup_table["98652faa7e0a4d85f91e37aa6b8c0135"]="Chrome 37.0.2062.120";
ja3_lookup_table["8b8322bad90e8bfbd66e664839b7a037"]="Chrome 41.0.2272.89";
ja3_lookup_table["aa9074aa1ff31c65d01c35b9764762b6"]="Chrome 42.0.2311.135";
ja3_lookup_table["de0963bc1f3a0f70096232b272774025"]="Chrome 42.0.2311.135";
ja3_lookup_table["3bb36ec17fef5d3da04ceeb6287314c6"]="Chrome 43.0.2357.132 & 45.02454.94";
ja3_lookup_table["cd3f72760dfd5575b91213a8016c596b"]="Chrome 48.0.2564.116";
ja3_lookup_table["5406c4a87aa6cbcb7fc469fee526a206"]="Chrome 48.0.2564.97";
ja3_lookup_table["503fe06db7ef09b2cbd771c4e784c686"]="Chrome 49.0.2623.75";
ja3_lookup_table["bd4267e1672f9df843ada7c963490a0d"]="Chrome 50.0.2661.102 1";
ja3_lookup_table["caeb3b546fc7469776d51f1f54a792ca"]="Chrome 50.0.2661.102 2";
ja3_lookup_table["aa84deda2a937ad225ef94161887b0cb"]="Chrome 51.0.2704.106 (test)";
ja3_lookup_table["473e8bad0e8e1572197be80faa1795c3"]="Chrome 51.0.2704.84 1";
ja3_lookup_table["e0b0e6c934c686fd18a5727648b3ed4f"]="Chrome 51.0.2704.84 2";
ja3_lookup_table["7ddfe8d6f8b51a90d10ab3fe2587c581"]="Chrome 51.0.2704.84 3";
ja3_lookup_table["bc76a4185cc9bd4c72471620e552618c"]="Chrome 51.0.2704.84 4";
ja3_lookup_table["8e3eea71cb5a932031d90cc0fba581bc"]="Chrome 51.0.2704.84 5";
ja3_lookup_table["653924bcb1d6fd09a048a4978574e2c5"]="Chrome 51.0.2704.84 6";
ja3_lookup_table["1ef652ecfb8e60e771a4710166afc262"]="Chrome 51.0.2704.84 7";
ja3_lookup_table["66918128f1b9b03303d77c6f2eefd128"]="Chrome 74.0.3729.131 (Official Build) (64-bit)";
ja3_lookup_table["a7f2d0376cdcfde3117bf6a8359b2ab8"]="Chrome Version 49.0.2623,87 (64-bit) Linux";
ja3_lookup_table["8a8159e6abf9fe493ca87efc38855149"]="Chrome Version 49.0.2623,87 (64-bit) Linux";
ja3_lookup_table["e330bca99c8a5256ae126a55c4c725c5"]="Chrome Version 57.0.2987.110 (64-bit) Linux";
ja3_lookup_table["d551fafc4f40f1dec2bb45980bfa9492"]="Chrome Version 57.0.2987.110 (64-bit) Linux";
ja3_lookup_table["bc6c386f480ee97b9d9e52d472b772d8"]="Chrome Version 60/61.0.3163, Google Chrome";
ja3_lookup_table["94c485bca29d5392be53f2b8cf7f4304"]="Chrome Version 60/61.0.3163, Malware Test FP: eitest-campaign-hoeflertext-popup-traffic";
ja3_lookup_table["d3b972883dfbd24fd20fc200ad8ab22a"]="Chrome Version 61.0.3163,100(64-bit) Win10";
ja3_lookup_table["62d8823f52dd8e1ba75a9a83e8748313"]="Chrome WebSockets (48.xxxx)";
ja3_lookup_table["cafd1f84716def1a414c688943b99faf"]="Chrome WebSockets (48.xxxx) - also TextSecure Desktop";
ja3_lookup_table["c405bbbe31c0e53ac4c8448355b2af5b"]="Chrome/30.0.1599.101";
ja3_lookup_table["2c3221f495d5e4debbb34935e1717703"]="Chrome/41.0.2272.89";
ja3_lookup_table["248bdbc3873396b05198a7e001fbd49a"]="Chrome/49.0.2623.112 WinXP";
ja3_lookup_table["83e04bc58d402f9633983cbf22724b02"]="Chrome/56.0.2924.87 Linux, Charles,Google Play Music Desktop Player,Postman,Slack,and other desktop programs";
ja3_lookup_table["9811c1bb9f0f6835d5c13a831cca4173"]="Chrome/59.0.3071.115 Win10, node.js";
ja3_lookup_table["def8761e4bcaaf91d99801a22ac6f6d4"]="Chrome/60.0.3112.113 Win10, Chromium";
ja3_lookup_table["be9f1360cf52dc1f61ae025252f192a3"]="Chromium";
ja3_lookup_table["fc5cb0985a5f5e295163cc8ffff8a6e1"]="Chromium";
ja3_lookup_table["e7d46c98b078477c4324031e0d3b22f5"]="Cisco AnyConnect Secure Mobility Client";
ja3_lookup_table["ed36017db541879619c399c95e22067d"]="Cisco AnyConnect Secure Mobility Client";
ja3_lookup_table["7f340e6caa1fa4c979df919227160ff6"]="Cisco AnyConnect Secure Mobility Client (3.1.09013)";
ja3_lookup_table["203157ed9f587f0cfd265061bf309823"]="Citrix Receiver 4.4.0.8014";
ja3_lookup_table["5ee1a653fb824db7182714897fd3b5df"]="Citrix Viewer";
ja3_lookup_table["a9d17f74e55dd53fcf7c234f8a240919"]="Covenant Eyes";
ja3_lookup_table["111da7c75fee7fe934b35a8d88eb350a"]="CRAWLER: facebookexternalhit/1.1";
ja3_lookup_table["c882d9444412c00e71b643f3f54145ff"]="Creative Cloud";
ja3_lookup_table["bc0608d33dc64506b42f7f5f87958f37"]="cscan";
ja3_lookup_table["f672d8f0e827ca1e704a9489b14dd316"]="curl";
ja3_lookup_table["764b8952983230b0ac23dbd3741d2bb0"]="curl (tested: 7.22.0 on Linux)";
ja3_lookup_table["9f198208a855994e1b8ec82c892b7d37"]="curl (tested: 7.43.0 OS X)";
ja3_lookup_table["c458ae71119005c8bc26d38a215af68f"]="curl 7.35.0 (tested Ubuntu 14.x openssl 1.0.1f)";
ja3_lookup_table["e14d427fab707af91e4bbd0bf03076f8"]="curl 7.37.0 / links 2.8 / git 2.6.6 (openSUSE Leap 42.1)";
ja3_lookup_table["e3891da2a758d67ba921e5eec0b9707d"]="curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.16.2.3 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2";
ja3_lookup_table["0217dc3bd88c696cc15374db0d848de4"]="Dashlane";
ja3_lookup_table["f7baf7d9da27449e823a4003e14cd623"]="Debian APT-CURL/1.0 (1.2.15)";
ja3_lookup_table["ec2e8760003621ca668b5f03e616cd57"]="Debian APT-CURL/1.0 (1.2.20+)";
ja3_lookup_table["4fcd1770545298cc119865aeba81daba"]="Deezer";
ja3_lookup_table["36bc8c7e10647bbfea3f740e7f05c0f1"]="Dropbox";
ja3_lookup_table["054c9f9d304b7a2add3d6fa75bc20ae4"]="Dropbox";
ja3_lookup_table["ede63467191e9a12300e252c41ca9004"]="Dropbox (installer?)";
ja3_lookup_table["653d342bee5001569662198a672746af"]="DropBox (tested: 3.12.5 - Ubuntu 14.04TS & Win 10)";
ja3_lookup_table["482a11a20da1629b77aaadf640478d13"]="Dropbox (Win 8.1)";
ja3_lookup_table["21ed4c7ee1daeb84c72199ceaf119b24"]="Dropbox Client";
ja3_lookup_table["f8e42933ba5b3990858ba621489047e3"]="Dropbox Client";
ja3_lookup_table["30b168d81e38d9a55c474c1e30eaf9f9"]="Dropbox Client";
ja3_lookup_table["2f8363419a9fb80ad46b380778d8eaf1"]="Dropbox Setup (tested: 3.10.11 on Win 8.x)";
ja3_lookup_table["c1e8322501b4d56d484b50bd7273e798"]="Dropbox Splash Pages (Win 10)";
ja3_lookup_table["6c141f98cd79d8b505123e555c1c3119"]="Dropbox Windows";
ja3_lookup_table["4c40bf8baa7c301c5dba8a20bc4119e2"]="Dynalist,Postman,Google Chrome,Franz,GOG Galaxy";
ja3_lookup_table["0411bbb5ff27ad46e1874a7a8beedacb"]="eclipse";
ja3_lookup_table["4990c9da08f44a01ecd7ddc3837caf25"]="eclipse";
ja3_lookup_table["fa106fe5beec443af7e211ef8902e7e0"]="eclipse";
ja3_lookup_table["d74778f454e2b047e030b291b94dd698"]="eclipse,java";
ja3_lookup_table["187dfde7edc8ceddccd3deeccc21daeb"]="eclipse,java,studio,STS, Malware Test FP: java-based-rat-malspam-traffic";
ja3_lookup_table["576a1288426703ae0008c42f95499690"]="Facebook iOS";
ja3_lookup_table["f22bdd57e3a52de86cda40da2d84e83b"]="Feedly/1.0, java,eclipse,Cyberduck";
ja3_lookup_table["a698fe6c52d210e3376bb6667729d4d2"]="fetchmail 6.3.26 (openSUSE Leap 42.1)";
ja3_lookup_table["1fbe5382f9d8430fe921df747c46d95f"]="FieldServiceApp,socialstudio";
ja3_lookup_table["0a81538cf247c104edb677bdb8902ed5"]="firefox";
ja3_lookup_table["0b6592fd91d4843c823b75e49b43838d"]="firefox";
ja3_lookup_table["1c15aca4a38bad90f9c40678f6aface9"]="firefox";
ja3_lookup_table["5163bc7c08f57077bc652ec370459c2f"]="firefox";
ja3_lookup_table["a88f1426c4603f2a8cd8bb41e875cb75"]="firefox";
ja3_lookup_table["b03910cc6de801d2fcfa0c3b9f397df4"]="firefox";
ja3_lookup_table["bfcc1a3891601edb4f137ab7ab25b840"]="firefox";
ja3_lookup_table["f15797a734d0b4f171a86fd35c9a5e43"]="firefox";
ja3_lookup_table["3d99dda4f6992b35fdb16d7ce1b6ccba"]="Firefox 24.0 Iceweasel24.3.0";
ja3_lookup_table["c57914fadb301a73e712378023b4b177"]="Firefox 25.0";
ja3_lookup_table["755cdaa3496eb8728247a639dee17aad"]="Firefox 26.0, Firefox/26.0";
ja3_lookup_table["ff9223b5c9a5d44a8a423833751fa158"]="Firefox 27.0";
ja3_lookup_table["df9bedd5713fe0cc2e9184d7c16a5913"]="Firefox 3.0.19";
ja3_lookup_table["4a9bd55341e1ffe6fedb06ad4d3010a0"]="Firefox 3.5 - 3.6, Firefox 3.5.19 3.6.27 SeaMonkey 2.0.14";
ja3_lookup_table["2872afed8370401ec6fe92acb53e5301"]="FireFox 40.0.3 (tested Windows 8), Firefox/37.0";
ja3_lookup_table["46129449560e5731dc9c5106f111a3db"]="Firefox 46.0";
ja3_lookup_table["d06b3234356cb3df0983fc8dd02ece68"]="Firefox 46.0";
ja3_lookup_table["05ece02fb23acf2efbfff54ce4099a45"]="Firefox 47.0 2";
ja3_lookup_table["aa907c2c4720b6f54cd8b67a14cef0a3"]="Firefox 47.x 1 / FireFox 47.x (Windows 7SP1)";
ja3_lookup_table["f586111542f330901d9a3885a9c821b5"]="FireFox 49 (dev edition)";
ja3_lookup_table["1996e434b11323df4e87f8fe0e702209"]="FireFox 49 (TLSv1.3 enabled - websockets)";
ja3_lookup_table["8ed0a2cdcad81fc29313910eb94941d8"]="FireFox 49 (TLSv1.3 enabled)";
ja3_lookup_table["8b18c5b0c54cba1ffb2438fe24792b63"]="Firefox 49.0a2 Developer TLS 1.3 enabled";
ja3_lookup_table["b20b44b18b853ef29ab773e921b03422"]="Firefox 63.0";
ja3_lookup_table["043a5d2d936910298e36e34acd8da818"]="Firefox Quantum 60.6.1 (CentOS Linux)";
ja3_lookup_table["55f2bd38d462d74fb6bb72d3630aae16"]="Firefox/10.0.11esrpre Iceape/2.7.12";
ja3_lookup_table["85c420ab089dac5025034444789a8fb5"]="Firefox/13.0-25.0, Malware Test FP: angler-ek-traffic-02";
ja3_lookup_table["847b0c334fd0f6f85457054fabff3145"]="Firefox/14.0.1 Linux";
ja3_lookup_table["e98db583389531a37f2fe8d251f0f7ae"]="Firefox/25.0";
ja3_lookup_table["cc9bcf019b339c01d200515d1cb39092"]="Firefox/27.0-32.0, IceWeasel 31.8.0";
ja3_lookup_table["45d22e6403f053bfb2cc223755588533"]="Firefox/28.0-30.0";
ja3_lookup_table["ce694315cbb81ce95e6ae4ae8cbafde6"]="Firefox/31 Linux, firefox";
ja3_lookup_table["8df37d4e7430e2d9a291ae9ee500a1a9"]="Firefox/32.0";
ja3_lookup_table["c5392af25feaf95cfefe858abd01c86b"]="Firefox/33.0";
ja3_lookup_table["5ba6ed04b246c96c6839e0268a8b826f"]="Firefox/33.0";
ja3_lookup_table["ab834ac5135f2204d473878821979cea"]="Firefox/34.0-35.00";
ja3_lookup_table["9250f97ba65d86e7b0e60164c820d91a"]="Firefox/34.0-35.00";
ja3_lookup_table["514058a66606ae870bcc670e95ca7e68"]="Firefox/37.0, Google Chrome 45.0.2454.85 or FireFox 41-42";
ja3_lookup_table["edf844351bc867631b5ebceda318669b"]="Firefox/38 Linux";
ja3_lookup_table["05af1f5ca1b87cc9cc9b25185115607d"]="Firefox/40.1 Windows 7";
ja3_lookup_table["07b4162d4db57554961824a21c4a0fde"]="Firefox/45.0 Linux, firefox,thunderbird";
ja3_lookup_table["61d0d709fe7ac199ef4b2c52bc8cef75"]="Firefox/51.0 Windows 10, firefox,thunderbird";
ja3_lookup_table["ca0f3f4c08cbd372720beb1af7d2721f"]="Firefox/52";
ja3_lookup_table["4e66f5ad78f3d9ad8d5c7c88d138db43"]="Firefox/52 Linux";
ja3_lookup_table["1885aa9927f99ed538ed895d9335995c"]="Firefox/55 Windows 10";
ja3_lookup_table["0ffee3ba8e615ad22535e7f771690a28"]="Firefox/55/56 Mac/Win/Linux, firefox, Malware Test FP: fake-font-update-for-firefox";
ja3_lookup_table["be1a7de97ea176604a3c70622189d78d"]="Firefox/56.0 Windows 10";
ja3_lookup_table["2aef69b4ba1938c3a400de4188743185"]="Firefox/6.0.1 - 12.0";
ja3_lookup_table["504ecb2d3e5e83a179316f098dadbaeb"]="Flux";
ja3_lookup_table["8498fe4268764dbf926a38283e9d3d8f"]="Franz,Google Chrome,Kiwi,Spotify,nwjs,Slack";
ja3_lookup_table["900c1fa84b4ea86537e1d148ee16eae8"]="Fuze";
ja3_lookup_table["107144b88827da5da9ed42d8776ccdc5"]="geod";
ja3_lookup_table["c46941d4de99445aef6b497679474cf4"]="geod";
ja3_lookup_table["3e765b7a69050906e5e48d020921b98e"]="git commandline (tested: 1.9. Linux)";
ja3_lookup_table["d0df7f7c9ca173059b2cd17ce5c2e5cc"]="Git-Bash (Tested v2.6.0) / curl 7.47.1 (cygwin)";
ja3_lookup_table["f8c50bbee59c526ca66da05f3dc4b735"]="GitHub Desktop (tested build 216 on OSX)";
ja3_lookup_table["a3b2fe29619fdcb7a9422b8fddb37a67"]="GMail SMTP Relay";
ja3_lookup_table["94b94048a438e77122fc4eee3a6a4a26"]="GNU Wget 1.16.1 built on darwin14.0.0";
ja3_lookup_table["0267b752d6a8b5fd195096b41ea5839c"]="GNUTLS Commandline";
ja3_lookup_table["f11b0fca6c063aa69d8d39e0d68b6178"]="golang (tested: 1.4.1)";
ja3_lookup_table["07ef3a7f5f8ffef08affb186284f2af4"]="Google Calendar Agent (Tested on OSX)";
ja3_lookup_table["002205d0f96c37c5e660b9f041363c11"]="Google Chrome";
ja3_lookup_table["073eede15b2a5a0302d823ecbd5ad15b"]="Google Chrome";
ja3_lookup_table["0b61c673ee71fe9ee725bd687c455809"]="Google Chrome";
ja3_lookup_table["6cd1b944f5885e2cfbe98a840b75eeb8"]="Google Chrome";
ja3_lookup_table["b4f4e6164f938870486578536fc1ffce"]="Google Chrome";
ja3_lookup_table["b8f81673c0e1d29908346f3bab892b9b"]="Google Chrome";
ja3_lookup_table["baaac9b6bf25ad098115c71c59d29e51"]="Google Chrome";
ja3_lookup_table["da949afd9bd6df820730f8f171584a71"]="Google Chrome";
ja3_lookup_table["f58966d34ff9488a83797b55c804724d"]="Google Chrome";
ja3_lookup_table["fd6314b03413399e4f23d1524d206692"]="Google Chrome";
ja3_lookup_table["abe568de919448adcd756aea9a136aea"]="Google Chrome (43.0.2357.130 64-bit OSX)";
ja3_lookup_table["400961c8161ba7661a7029d3f7e8bb95"]="Google Chrome (Android)";
ja3_lookup_table["072c0469aa4f2f597bb38bcc17095c51"]="Google Chrome (tested: 43.0.2357.130 64-bit OSX)";
ja3_lookup_table["c40b51e2a59425b6a2b500d569962a60"]="Google Chrome (tested: 43.0.2357.130 64-bit OSX)";
ja3_lookup_table["696cd0c8c241e19e3d6336c3d3d9e2e0"]="Google Chrome (tested: 43.0.2357.130 64-bit OSX)";
ja3_lookup_table["e8aabc4fe1fc8d47c648d37b2df7485f"]="Google Chrome 45.0.2454.101";
ja3_lookup_table["a9030ea4837810ce89fb8a3d39ca12ed"]="Google Chrome 46.0.2490.71";
ja3_lookup_table["7ea3e17d09294aee8425ae05588f0c66"]="Google Chrome 46.0.2490.71 m";
ja3_lookup_table["0e46737668fe75092919ee047a0b5945"]="Google Chrome Helper";
ja3_lookup_table["39fa85654105398ee7ef6a3a1c81d685"]="Google Chrome Helper";
ja3_lookup_table["4ba7b7022f5f5e1e500bb19199d8b1a4"]="Google Chrome Helper";
ja3_lookup_table["5498cef2cca704eb01cf2041cc1089c1"]="Google Chrome,Slack";
ja3_lookup_table["c1741dd3d2eec548df0bcd89e08fa431"]="Google Drive (tested: 1.26.0707.2863 - Win 8.x & Win 10)";
ja3_lookup_table["d27fb8deca6e3b9739db3fda2b229fe3"]="Google Drive File Stream";
ja3_lookup_table["ae340571b4fd0755c4a0821b18d8fa93"]="Google Earth";
ja3_lookup_table["b16614e71d26ba348c94bfc8e33b1767"]="Google Earth Linux 7.1.4.1529";
ja3_lookup_table["9af622c65a17a0bf90d6e9504be96a43"]="Google Mail server starttls connection";
ja3_lookup_table["f059212ce3de94b1e8253a7522cb1b44"]="Google Photos Backup";
ja3_lookup_table["50dfee94717e9640b1c384e5bd78e61e"]="GoogleBot";
ja3_lookup_table["fd10cc8cce9493a966c57249e074755f"]="gramblr";
ja3_lookup_table["e76ac6872939f6ebfdf75f1ea73b4daf"]="Great Firewall of China Probe (via pcaps from https://nymity.ch/active-probing/)";
ja3_lookup_table["d9b07b9095590f4ff910ceee7b6af88a"]="HipChat";
ja3_lookup_table["3e860202fc555b939e83e7a7ab518c38"]="hola_svc";
ja3_lookup_table["54328bd36c14bd82ddaa0c04b25ed9ad"]="hola_svc";
ja3_lookup_table["56ac3a0bef0824c49e4b569941937088"]="hola_svc";
ja3_lookup_table["8bd59c4b7f3193db80fd64318429bcec"]="hola_svc";
ja3_lookup_table["d1f9f9b224387d2597f02095fcec96d7"]="hola_svc";
ja3_lookup_table["ff1040ba1e3d235855ef0d7cd9237fdc"]="hola_svc";
ja3_lookup_table["a1ec6fd012b9ee6f84c50339c4205270"]="HTTRack";
ja3_lookup_table["5af143afdbf58ec11ab3b3d53dd4e5e3"]="IDSyncDaemon";
ja3_lookup_table["78273d33877a36c0c30e3fb7578ee9e7"]="IE 11";
ja3_lookup_table["4cafc7a0acf83a49317ca199b2f25c82"]="IE 11";
ja3_lookup_table["fee8ec956f324c71e58a8c0baf7223ef"]="IE 11 Win10";
ja3_lookup_table["a61299f9b501adcf680b9275d79d4ac6"]="In all the malware samples - Java updater perhaps, java";
ja3_lookup_table["d06acbe8ac31e753f40600a9d6717cba"]="Inbox OSX";
ja3_lookup_table["3ca5d63fa122552463772d3e87d276f2"]="inoreader.com-like FeedFetcher-Google, inoreader.com ";
ja3_lookup_table["a6776199188c09f5124b46b895772fa2"]="Internet Explorer 11 .0.9600.1731.(Win 8.1)";
ja3_lookup_table["a264c0bb146b2fade4410bcd61744b69"]="Internet Explorer 11.0.9600.17959";
ja3_lookup_table["d54b3eb800cbeccf99fd5d5cdcd7b5b5"]="Internet Explorer 11.0.9600.18349 / TeamViewer 10.0.47484P / Notepad++ Update Check / Softperfect Network Scanner Update Check / Wireshark 2.0.4 Update Check, ";
ja3_lookup_table["06d930b072bf052b10d0a9eea1554f60"]="iOS AppleWebKit/536.26";
ja3_lookup_table["99204897b101b15f87e9b07f67453f4e"]="iOS Mail App (tested: iOS 9.3.3)";
ja3_lookup_table["a9aecaa66ad9c6cfe1c361da31768506"]="iPad; CPU OS 9_3_5 Safari 601.1, Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["7e72698146290dd68239f788a452e7d8"]="iPhone OS 10_3_3 Safari 602.1, Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["c6ecc5ba2a6ab724a7430fa4890d957d"]="iTunes/iBooks #1";
ja3_lookup_table["c07295da5465d5705a38f044e53ef7c4"]="iTunes/iBooks #2";
ja3_lookup_table["093081b45872912be9a1f2a8163fe041"]="java";
ja3_lookup_table["2080bf56cb87e64303e27fcd781e7efd"]="java";
ja3_lookup_table["225a24b45f0f1adbc2e245d4624c6e08"]="java";
ja3_lookup_table["3afe1fb5976d0999abe833b14b7d6485"]="java";
ja3_lookup_table["3b844830bfbb12eb5d2f8dc281d349a9"]="java";
ja3_lookup_table["550628650380ff418de25d3d890e836e"]="java";
ja3_lookup_table["5b270b309ad8c6478586a15dece20a88"]="java";
ja3_lookup_table["5d7abe53ae15b4272a34f10431e06bf3"]="java";
ja3_lookup_table["7c7a68b96d2aab15d678497a12119f4f"]="java";
ja3_lookup_table["88afa0dea1608e28f50acbad32d7f195"]="java";
ja3_lookup_table["8ce6933b8c12ce931ca238e9420cc5dd"]="java";
ja3_lookup_table["a9fead344bf3ac09f62df3cd9b22c268"]="java";
ja3_lookup_table["2db6873021f2a95daa7de0d93a1d1bf2"]="Java 8U91 Update Check, Windows Java Plugin (tested: v8 Update 60), BurpSuite Free (Tested: 1.7.03 on Windows 10), java,studio,eclipse";
ja3_lookup_table["51a7ad14509fd614c7bb3a50c4982b8c"]="java, Malware Test FP: sweet-orange-ek-traffic";
ja3_lookup_table["028563cffc7a3a2e32090aee0294d636"]="java,eclipse,STS";
ja3_lookup_table["5f9b53f0d39dc9d940a3b5568fe5f0bb"]="java,JavaApplicationStub";
ja3_lookup_table["c376061f96329e1020865a1dc726927d"]="JavaApplicationStub";
ja3_lookup_table["ced7418dee422dd70d2a6f42bb042432"]="K9 Mail (Android)";
ja3_lookup_table["e516ad69a423f8e0407307aa7bfd6344"]="Kindle,stack,nextcloud";
ja3_lookup_table["8194818a46f5533268472f2167ffec70"]="Konqueror 4.14.18 (openSUSE Leap 42.1) 2";
ja3_lookup_table["78253eb48a1431a4bbbe6bb4358464ac"]="Konqueror 4.14.18 / Kmail 4.14.18 (openSUSE Leap 42.1) 1";
ja3_lookup_table["0e0b798d0208ad365eec733b29da92a6"]="Konqueror 4.8, OpenSSL s_client (tested: 1.0.1f - Ubuntu 14.04TS)";
ja3_lookup_table["3959d0a1344896e9fb5c0564ca0a2956"]="LeagueClientUx";
ja3_lookup_table["0fe51fa93812c2ebb50a655222a57bf2"]="LINE Messaging";
ja3_lookup_table["2e094913d88f0ad8dc69447cb7d2ce65"]="LINE Messaging";
ja3_lookup_table["193349d34561d1d5d1a270172eb2d97e"]="LogMeIn Client";
ja3_lookup_table["0cbbafcdaf63cbf1e490c4a2d903f24b"]="Mail app iOS";
ja3_lookup_table["92579701f145605e9edc0b01a901c6d5"]="Malware Test FP:  usps-malspam-js-file-post-infection-traffic";
ja3_lookup_table["96eba628dcb2b47607192ba74a3b55ba"]="Malware Test FP: angler-ek-traffic-01";
ja3_lookup_table["d55e755245ac118f2b1847c1c57b5e03"]="Malware Test FP: angler-ek-traffic-02";
ja3_lookup_table["4f635262ad3fb6e634daee798082c788"]="Malware Test FP: boleto-malspam-infection-traffic";
ja3_lookup_table["e9273590c7875d6367325f8714890790"]="Malware Test FP: boleto-malspam-traffic";
ja3_lookup_table["c201b92f8b483fa388be174d6689f534"]="Malware Test FP: dhl-malspam-traffic";
ja3_lookup_table["85bedfc1914da556aab4518390798003"]="Malware Test FP: dridex-infection-traffic";
ja3_lookup_table["67f762b0ffe3aad00dfdb0e4b1acd8b5"]="Malware Test FP: dyre-phishing-run-traffic";
ja3_lookup_table["ff94b48f555edc2f0a4c8256eb0d81de"]="Malware Test FP: eitest-angler-ek-third-run";
ja3_lookup_table["098f55e27d8c4b0a590102cbdb3a5f3a"]="Malware Test FP: eitest-hoeflertext-chrome-popup-traffic-4-of-6";
ja3_lookup_table["3b483d0b34894548b602e8d18cdc24c5"]="Malware Test FP: eitest-rig-ek, ransomware-after-southcoastdrones.com.au";
ja3_lookup_table["2d44457ca7a1e0e754664c8469ce62a8"]="Malware Test FP: eitest-rig-ek-second-example";
ja3_lookup_table["2d8794cb7b52b777bee2695e79c15760"]="Malware Test FP: eitest-rig-ek-traffic, cryptowall-phishing-malware";
ja3_lookup_table["df8bfc363eeba63ab938cb2190ccd7b7"]="Malware Test FP: eitest-rig-ek-traffic, dridex-malspam-traffic-example";
ja3_lookup_table["1074895078955b2db60423ed2bf8ac23"]="Malware Test FP: eitest-rig-ek-traffic, traffic-from-portuguese-malspam-attachment";
ja3_lookup_table["df5c30e670dba99f9270ed36060cf054"]="Malware Test FP: fake-font-update-for-firefox";
ja3_lookup_table["a0e9f5d64349fb13191bc781f81f42e1"]="Malware Test FP: fake-font-update-for-firefox";
ja3_lookup_table["2efb07037a97b06201ab4fe7ec0c326e"]="Malware Test FP: fake-font-update-for-firefox";
ja3_lookup_table["c1fbfd09bd0bab610be60dd6819688f4"]="Malware Test FP: fiesta-ek-infection-traffic";
ja3_lookup_table["e7d705a3286e19ea42f587b344ee6865"]="Malware Test FP: malspam-traffic";
ja3_lookup_table["243a279e5aaae8841edf46d00c05195e"]="Malware Test FP: malspam-traffic";
ja3_lookup_table["bafc6b01eae6f4350f5db6805ace208e"]="Malware Test FP: mordor-from-seahomevb.top";
ja3_lookup_table["e107ef8ec0296e17c3f82de949b4066c"]="Malware Test FP: neutrino-traffic";
ja3_lookup_table["aeae3901ecde8396b2f5648c02aeb37f"]="Malware Test FP: neutrino-traffic";
ja3_lookup_table["51b5c918558a4bfb50ce1ab1d5fddff7"]="Malware Test FP: neutrino-traffic";
ja3_lookup_table["fd6bbdf835788b3c7d33372127470a06"]="Malware Test FP: neutrino-traffic";
ja3_lookup_table["a7dfa1673bb090cab6b6658861f43473"]="Malware Test FP: neutrino-traffic";
ja3_lookup_table["852e7534b3f722d893a7750afb5ecdcc"]="Malware Test FP: neutrino-traffic";
ja3_lookup_table["1be3ecebe5aa9d3654e6e703d81f6928"]="Malware Test FP: nuclear-ek-traffic, malspam-traffic";
ja3_lookup_table["fd2273056f386e0ba8004e897c337037"]="Malware Test FP: nuclear-ek-traffic, malspam-traffic";
ja3_lookup_table["1848357994c2851c809cb01bae7d631c"]="Malware Test FP: rig-ek-traffic";
ja3_lookup_table["6734f37431670b3ab4292b8f60f29984"]="Malware Test FP: trickbot-infection-from-usdata.estoreseller.com";
ja3_lookup_table["294b2f1dc22c6e6c3231d2fe311d504b"]="Malware Test FP: trickbot-malspam-traffic";
ja3_lookup_table["6f702efe6480d2a1c9f85b73b8a4794a"]="Malware Test FP: usps-malspam-js-file-post-infection-traffic";
ja3_lookup_table["3fab5d0fe3b2408c8b2251b46d3895de"]="Malware Test FP: usps-malspam-js-file-post-infection-traffic";
ja3_lookup_table["a34e8a810b5f390fc7aa5ed711fa6993"]="Malware: Gootkit";
ja3_lookup_table["c6e36d272db78ba559429e3d845606d1"]="Malware: Gootkit";
ja3_lookup_table["84a315236aceb31ad56f5647dc64f793"]="Malware: https://www.virustotal.com/en/file/802d683b596d7ce7ae373b15fa4a8e8c2a237bd15bc8ef655fbd2c41239fa2c8/analysis/1433178940/";
ja3_lookup_table["73fab4ba757fdd5aac4729eb20f07c04"]="Malware: https://www.virustotal.com/file/07853289247c4c932ddfbf4c215b4e86240fab6661a6d6a85ac8ee37fe92b9be/analysis/1433596684/o";
ja3_lookup_table["4954bf2b5e6592b390a89d3b1dbe550a"]="Malware: https://www.virustotal.com/file/bbb3fbd2e8289d04733f8f005dc6410b050bee193a12ddf2f819141834e9c8fa/analysis/1433054369/";
ja3_lookup_table["45c2897e06c4979bd3b8e512523590d7"]="Malware: https://www.virustotal.com/file/bbb3fbd2e8289d04733f8f005dc6410b050bee193a12ddf2f819141834e9c8fa/analysis/1433054369/o";
ja3_lookup_table["b50f81ae37fb467713e167137cf14540"]="Malware: TBot / Skynet Tor Botnet";
ja3_lookup_table["b9103d9d134e0c59cafbe4ae0a8299a8"]="Malware: Unknown traffic associated with Dridex";
ja3_lookup_table["fc5574de96793b73355ca9e555748225"]="Marble (KDE 5.21.0 QT 5.5.1 openSUSE Leap 42.1)";
ja3_lookup_table["d732ca39155f38942f90e9fc2b0f97f7"]="Maxthon";
ja3_lookup_table["c9dbeed362a32f9a50a26f4d9b32bbd8"]="Messenger,Jumpshare";
ja3_lookup_table["16f17c896273d1d098314a02e87dd4cb"]="Metaploit http scanner (tested: 4.11.5 Kali)";
ja3_lookup_table["950ccdd64d360a7b24c70678ac116a44"]="Metasploit CCS Scanner";
ja3_lookup_table["ee031b874122d97ab269e0d8740be31a"]="Metasploit HeartBleed Scanner";
ja3_lookup_table["6825b330bf9de50ccc8745553cb61b2f"]="Metasploit SSL Scanner";
ja3_lookup_table["10ee8d30a5d01c042afd7b2b205facc4"]="Microsoft Edge 42.17134.1.0";
ja3_lookup_table["bedb7e0ff43a24272eb0a41993c65faf"]="Microsoft Smartscreen";
ja3_lookup_table["bff2c7b5c666331bfe9afacefd1bdb51"]="Microsoft Updater (Windows 7SP1) / TeamViewer 11.0.56083P, Malware Test FP: eitest-angler-ek-third-run";
ja3_lookup_table["48cf5fb702315efbfc88ee3c8c94c6cb"]="Microsoft Windows Socket (Tested: Windows 10)";
ja3_lookup_table["4d01f8b1afc22e138127611b62f1e6ec"]="mitmproxy";
ja3_lookup_table["8ef6a005eae3d51b652ffe41984f8869"]="mitmproxy";
ja3_lookup_table["11e1137464a4343105031631d470cd92"]="mj12bot.com";
ja3_lookup_table["87c6dda19108d68e526a72d9ae09fb9e"]="Mobile Safari/537.35+ BB10";
ja3_lookup_table["6acb250ada693067812c3335705dae79"]="mono-sgen,Syncplicity,Axure RP 8,Amazon Drive";
ja3_lookup_table["d65ddade944f9acfe4052b2c9435eb85"]="Mozilla Sync Services (Android)";
ja3_lookup_table["c2116e5bb14394aafbefe12ade9bd8ab"]="Mozilla Thunderbird (tested: 31.5.0)";
ja3_lookup_table["6fd163150b060dd7d07add280f42f4ed"]="Mozilla Thunderbird (tested: 38.3.0), ThunderBird (v38.0.1 OS X)";
ja3_lookup_table["de350869b8c85de67a350c8d186f11e6"]="Mozilla/4.0 (compatible; MSIE 6.0 or MSIE 7.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)";
ja3_lookup_table["8d2e46c9e2b1ee9b1503cab4905cb3e0"]="MS Edge";
ja3_lookup_table["888ecd3b5821a497195932b0338f2f12"]="MS Edge";
ja3_lookup_table["5bf43fbca3454853c26df6d996954aca"]="MS Edge";
ja3_lookup_table["f66b0314f269695fe3528ef39a27c158"]="MS Office Components";
ja3_lookup_table["7b3b37883b5e80065b35f27888ed2b04"]="MSIE 10.0 Trident/6.0)";
ja3_lookup_table["2201d8e006f8f005a6b415f61e677532"]="MSIE 10.0 Trident/6.0, Malware Test FP: blackhole-ek-traffic, sweet-orange-ek-post-infection-traffic, sweet-orange-ek-traffic, styx-ek-traffic";
ja3_lookup_table["2baf01616e930d378df97576e2686df3"]="MSIE 8.0 & 9.0 Trident/5.0)";
ja3_lookup_table["6761a36cfa692fcd3bc7d570b23cc168"]="mutt";
ja3_lookup_table["dc7c914e1817944435dd6b82a8495fbb"]="mutt (tested: 1.5.23 OSX)";
ja3_lookup_table["146c6a6537ba4cc22d874bf8ff346144"]="NetFlix App on AppleTV (possibly others also)";
ja3_lookup_table["f4262963691a8f123d4434c7308ad7fe"]="Nikto (tested 2.1.6 - Kali)";
ja3_lookup_table["5eeeafdbc41e5ca7b81c92dbefa03ab7"]="Nikto (tested 2.1.6 - Kali)";
ja3_lookup_table["a563bb123396e545f5704a9a2d16bcb0"]="Nikto (tested v2.1.6)";
ja3_lookup_table["641df9d6dbe7fdb74f70c8ad93def8cc"]="node.js";
ja3_lookup_table["106ecbd3d14b4dc6e413494263720afe"]="node.js,Postman,WhatsApp";
ja3_lookup_table["3ee4aaac7147ff2b80ada31686db660c"]="node-webkit,Kindle";
ja3_lookup_table["4025f224557638ee81afc4f272fd7577"]="NVIDEA GeForce Experience, Windows Diagnostic and Telemetry (also Security Essentials and Microsoft Defender) (Tested Win7)";
ja3_lookup_table["49de9b1c7e60bd3b8e1d4f7a49ba362e"]="nwjs,Chromium";
ja3_lookup_table["388a4049af7e631f8d36eb0f909de65a"]="One Drive";
ja3_lookup_table["a35c1457421bcfaf5edaccb910bfea1d"]="OpenConnect version v7.01";
ja3_lookup_table["07aa6d7cac645c8845d6e96503f7d985"]="OpenConnect version v7.06 / wget 1.17.1-1 (cygwin)";
ja3_lookup_table["6fffa2be612102d25dbed5f433b8238c"]="openssl s_client / msmtp 1.6.2 (openSUSE Leap 42.1)";
ja3_lookup_table["4e6f7f036fb2b05a50ee8a686b1176a6"]="Opera 10.53 10.60 11.61 11.64 12.02, Presto 2.5.24 2.6.30 2.10.229 2.10.289";
ja3_lookup_table["ceee08c3603b53be80c8afdc98babdd6"]="Opera 11.11 11.52, Presto 2.8.131 2.9.168";
ja3_lookup_table["561271bdcbfe68504ce78b38c957eef0"]="Opera 12.14 - 12.16, Presto 2.12.388";
ja3_lookup_table["8b475d6105c72827a234fbd47e25b0a3"]="Opera/9.80 (X11; Linux x86_64; U; en) Presto/2.6.30 Version/10.60";
ja3_lookup_table["44f37c3ceccb551271bfe0ba6d39426c"]="Opera/9.80 Presto/2.10.229 Version/11.62";
ja3_lookup_table["a16170ff03466c8ee703dd71feda9bfe"]="Opera/9.80 Presto/2.10.289 & Presto/2.10.229";
ja3_lookup_table["b237ac4bcc16c142168df03a871677bd"]="Opera/9.80 Presto/2.10.289 Version/12.00";
ja3_lookup_table["07715901e2c6fe4c45e7c42587847d5d"]="Opera/9.80 Presto/2.12.388";
ja3_lookup_table["329ff4616732b84de926caa7fd6777b0"]="Opera/9.80 Presto/2.12.388";
ja3_lookup_table["43bb6a18756587426681e4964e5ea4bf"]="OS X WebSockets";
ja3_lookup_table["3b6da2971936ac24457616e8ad46f362"]="osc (python openSUSE Leap 42.1) 1";
ja3_lookup_table["95baa3d2068d8c8da71990a353cf8453"]="osc (python openSUSE Leap 42.1) 2";
ja3_lookup_table["53eb89fe6147474039c1162e4d9d3dc0"]="Outlook 2007 (Win 8.1)";
ja3_lookup_table["38cbe70b308f42da7c9980c0e1c89656"]="p4v,owncloud";
ja3_lookup_table["d82cbe0b93f2b02d490a14f6bc1d421a"]="PaleMoon Browser; PaleMoon/27.4.2";
ja3_lookup_table["62448833d8230241227c03b7d441e31b"]="parsecd,apple.geod,apple.photomoments,photoanalysisd,FreedomProxy";
ja3_lookup_table["16765fe48127809dc0ca406769c9391e"]="php script (tested 5.5.27)";
ja3_lookup_table["b74f9ecf158e0575101c16c5265a85b0"]="Pidgin (tested 2.10.11)";
ja3_lookup_table["6ea7cfa450ce959818178b420f59fec4"]="Pocket/Slack/Duo (Android)";
ja3_lookup_table["9e41b6bf545347abccf0dc8fd76083a5"]="Polycom IP Phone Directory Lookup";
ja3_lookup_table["e846898acc767ebeb2b4388e58a968d4"]="postbox-bin";
ja3_lookup_table["26fa3da4032424ab61dc9be62c8e3ed0"]="Postfix with StartTLS";
ja3_lookup_table["ef48bf8b2ccaab35642fd0a9f1bbe831"]="PubNub data stream #1 & Apteligent";
ja3_lookup_table["8cc24a6ff485c62e3eb213d2ca61cf12"]="PubNub data stream #2";
ja3_lookup_table["12ad03cb3faa2748e92c9a38faab949f"]="Pusherapp API";
ja3_lookup_table["ba502b2f5d64ac3d1d54646c0d6dd4dc"]="py2app application (including box.net & google drive clients)";
ja3_lookup_table["c398c55518355639c5a866c15784f969"]="Python Requests Library 2.4.3";
ja3_lookup_table["1a9fb04aa1b4439666672be8661f9386"]="python-requests/2.7.0 CPython/2.6.6 Linux/2.6.32-504.23.4.el6.x86_64";
ja3_lookup_table["a7823092705a5e91ce2b7f561b6e5b98"]="Qsync Client";
ja3_lookup_table["c22dea495cef869edbeb3458adaf497f"]="Rapid7 Nexpose";
ja3_lookup_table["c048d9f26a79e11ca7276499ef24daf3"]="RescueTime,Plantronics Hub";
ja3_lookup_table["7743db23afb26f18d632420e6c36e076"]="RingCentral App (unknown platform)";
ja3_lookup_table["90f755509cba37094eb66be02335b932"]="RingCentral App (unknown platform) #2";
ja3_lookup_table["35c0a31c481927f022a3b530255ac080"]="RSiteAuditor";
ja3_lookup_table["d219efd07cbb8fbe547e6a5335843f0f"]="ruby";
ja3_lookup_table["688b34ca00a291ece0bc07b264b1344c"]="ruby script (tested: 2.0.0p481)";
ja3_lookup_table["c36fb08942cf19508c08d96af22d4ffc"]="Safari";
ja3_lookup_table["cbcd1d81f242de31fd683d5acbc70dca"]="Safari 525 - 533 534.57.2, Safari 525.21 525.29 531.22.7 533.21.1 534.57.2 / Adobe Reader DC 15.x Updater, Malware Test FP: eitest-angler-ek-traffic";
ja3_lookup_table["4c551900711d12c864cfe2f95e1c98c2"]="Safari 534.34";
ja3_lookup_table["30701f5050d504c31805594fb5c083b8"]="Safari 534.34, rekonq1.1 Arora0.11.0";
ja3_lookup_table["41ba55231de6643721fbe2ae25fab85d"]="Safari 534.34, Safari/537.21";
ja3_lookup_table["fb1d89e16f4dd558ad99011070785cce"]="Safari 534.59.8";
ja3_lookup_table["e2a482fbb281f7662f12ff6cc871cfe7"]="Safari 536.30.1";
ja3_lookup_table["cc5925c4720edb550491a12a35c15d4d"]="Safari 537.71";
ja3_lookup_table["88770e3ad9e9d85b2e463be2b5c5a026"]="Safari 537.78.2";
ja3_lookup_table["77310efe11f1943306ee317cf02150b7"]="Safari/534.57.2, hola_svc";
ja3_lookup_table["c07cb55f88702033a8f52c046d23e0b2"]="Safari/604.1.38 Macintosh, Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["3e4e87dda5a3162306609b7e330441d2"]="Safari/604.3.1 Macintosh, apple.WebKit.Networking,itunesstored";
ja3_lookup_table["844166382cc98d98595e6778c470f5d5"]="Salesforce Files";
ja3_lookup_table["9a35e493f961ac377f948690b5334a9c"]="SCANNER: hoax Firefox/40.1";
ja3_lookup_table["ce5f3254611a8c095a3d821d44539877"]="SCANNER: wordpress wp-login Firefox/40.1";
ja3_lookup_table["d8844f000e5571807e9094e0fcd795fe"]="SCRAPER: DotBot";
ja3_lookup_table["05e15a226e00230c416a8cdefeb483c7 "]="SCRAPER: yandex.ru based Mozilla 4.0; MSIE 8.0; Windows NT 5.1;";
ja3_lookup_table["6cc3c7debc31952d05ecaacb6021925f"]="SeznamBot/3.2";
ja3_lookup_table["fa8b8ed07b1dd0e4a262bd44d31251ec"]="ShadowServer Scanner 1";
ja3_lookup_table["c05809230e9f7a6bf627a48b72dc4e1c"]="ShadowServer Scanner 2";
ja3_lookup_table["0ad94fcb7d3a2c56679fbd004f6b12cd"]="ShadowServer Scanner 3";
ja3_lookup_table["0b63812a99e66c82a20d30c3b9ba6e06"]="Shodan";
ja3_lookup_table["f59a024cf47fdb835053ebf144189a47"]="Shodan";
ja3_lookup_table["302579fd4ba13eca27932664f66725ad"]="Shodan";
ja3_lookup_table["109dbd9238634b21363c3d62793c029c"]="Shodan";
ja3_lookup_table["0add6ceb611a7613f97329af3b6828d9"]="Shodan";
ja3_lookup_table["badc09d74edf43c0204c4827a038c2fa"]="Shodan";
ja3_lookup_table["f8f522671d2d2eba5803e6c002760c05"]="Shodan";
ja3_lookup_table["11e49581344c117df2c9ceb46e5594c4"]="Shodan";
ja3_lookup_table["9d5869f950eeca2e39196c61fdf510c8"]="Shodan, mutt (tested: 1.5.23 - OS X)";
ja3_lookup_table["3fcc12d9ee1f75a0212d1d16f7b9f8ad"]="Shodan, mutt (tested: 1.6.2 OS X)";
ja3_lookup_table["7dde4e4f0dceb29f711fb34b4bdbf420"]="Signal (tested: 3.16.0 - Android)";
ja3_lookup_table["07931ada5b9dd93ec706e772ee60782d"]="Signal Chrome App";
ja3_lookup_table["cfb6d1c72d09d4eaa4c7d2c0b1ecbce7"]="SkipFish (tested: v2.10b kali)";
ja3_lookup_table["49a341a21f4fd4ac63b027ff2b1a331f"]="Skype";
ja3_lookup_table["7a75198d3e18354a6763860d331ff46a"]="Skype (additional Win 10)";
ja3_lookup_table["06207a1730b5deeb207b0556e102ded2"]="Skype (multiple platforms)";
ja3_lookup_table["5ef08bc989a9fcc18d5011f07d953c14"]="Skype (tested 7.18(341) on OSX)";
ja3_lookup_table["3d72e4827837391cd5b6f5c6b2d5b1e1"]="Slack";
ja3_lookup_table["cdd8179dc9c0e4802f557b62bae73d43"]="Slack";
ja3_lookup_table["a5aa6e939e4770e3b8ac38ce414fd0d5"]="Slack";
ja3_lookup_table["c8ada45922a3e7857e4bfd4fc13e8f64"]="Slack Desktop App";
ja3_lookup_table["22cca8ed59288f4984724f0ee03484ea"]="Slackbot Link Expander";
ja3_lookup_table["116ffc8889873efad60457cd55eaf543"]="Spark";
ja3_lookup_table["f51156bcd5033603e750c8bd4db254e3"]="SpiderOak (tested: 6.0.1)";
ja3_lookup_table["8db4b0f8e9dd8f2fff38ee7c5a1e4496"]="SpotlightNetHelper,Safari";
ja3_lookup_table["1ab5d0f756e0692a975fda9a6474969f"]="sqlmap (tested: v1.0.7.0 OS X)";
ja3_lookup_table["615788655a0e65b71e47c3ebe2302564"]="sqlmap (tested: v1.0-dev kali)";
ja3_lookup_table["24339ea346521d98a8c50fd3713090c9"]="SSLPing Scanner 1";
ja3_lookup_table["ad5d6f490f3819dc60b2a2fbe5bd1cba"]="SSLPing Scanner 2";
ja3_lookup_table["1e9557c377f8ff50b80b7f87b60b1054"]="SSLPing Scanner 3";
ja3_lookup_table["c3c59ec21835721c92571e7742fadb88"]="SSLPing Scanner 4";
ja3_lookup_table["39cf5b7a13a764494de562add874f016"]="Steam OSX";
ja3_lookup_table["cab4a6a0c7ac91c2bd9e93cb0507ad4e"]="Synology DDNS Beacon";
ja3_lookup_table["2d3854d1cbcdceece83eabd85bdcc056"]="Tableau";
ja3_lookup_table["a585c632a2b49be1256881fb0c16c864"]="Tableau";
ja3_lookup_table["cd7c06b9459c9cfd4af2dba5696ea930"]="Tableau";
ja3_lookup_table["24993abb75ddda7eaf0709395e47ab4e"]="Tenable Passive Vulnerability Scanner Plugin Updater";
ja3_lookup_table["74927e242d6c3febf8cb9cab10a7f889"]="Test FP: Dridex Malware";
ja3_lookup_table["f3603b5b21cdb30f2a089b78fc2dde0d"]="Test FP: Nuclear Exploit Kit";
ja3_lookup_table["4d7a28d6f2263ed61de88ca66eb011e3"]="Test FP: Nuclear Exploit Kit";
ja3_lookup_table["38aea89b122f799954cf3f4e8878498b"]="Test FP: Tweetdeck maybe Webkit";
ja3_lookup_table["97d3b9036d5a4d7f1fe33fe730f38231"]="TextSecure Name Lookup (Tested: Android)";
ja3_lookup_table["207409c2b30e670ca50e1eac016a4831"]="ThunderBird (v17.0 OS X)";
ja3_lookup_table["4623da8b4586a8a4b86e31d689aa0c15"]="ThunderBird (v38.0.1 OS X), Thunderbird 38.7.0 (openSUSE Leap 42.1)";
ja3_lookup_table["0ed768d6e3bc66af60d31315afd423f2"]="Tor Browser (tested: 5.0.1f - May clash with FF38)";
ja3_lookup_table["8c9a7fe81ba61dab1454e08f42f0a004"]="Tor Browser (v4.5.3 OS X - based on FF 31.8.0)";
ja3_lookup_table["5b3eee2766b876e623ba05508d269830"]="Tor Relay Traffic (tested 0.2.7.6)";
ja3_lookup_table["79f0842a32b359d1b683c569bd07f23b"]="Tor Relay Traffic (tested 0.2.7.6), Tor Uplink (via Tails distro)";
ja3_lookup_table["3b8f3ace50a7c7cd5205af210f17bb70"]="tor uplink (tested 0.2.2.35)";
ja3_lookup_table["659007d8bae74d1053f6ca4a329d25a7"]="Tor uplink (tested: 0.2.6.10)";
ja3_lookup_table["aea96546ac042f29fed1e2203a9b4c3f"]="Trident/7.0";
ja3_lookup_table["2a458dd9c65afbcf591cd8c2a194b804"]="Trident/7.0, Malware Test FP: eitest-rig-ek-second-example";
ja3_lookup_table["df65746370dcabc9b4f370c6e14a8156"]="True Key";
ja3_lookup_table["edcf2fd479271286879efebd22bc8d16"]="Twitterbot/1.0";
ja3_lookup_table["b9b4d1f7283b5ddc59d0b8d15e386106"]="Ubuntu Software Center";
ja3_lookup_table["633e9558d4b25b46e8b1c49e10faaff4"]="Ubuntu Software Center";
ja3_lookup_table["ac206b75530d569a0a64cec378eb4b66"]="Ubuntu Web Socket #1";
ja3_lookup_table["94feb9008aeb393e76bac31b30af6ad0"]="Ubuntu Web Socket #2";
ja3_lookup_table["f1b7bbeb8b79cecd728c72bba350d173"]="Ubuntu Web Socket #3";
ja3_lookup_table["3f00755c412442e642f5572ed4f2eaf2"]="Ubuntu Web Socket #4";
ja3_lookup_table["9a1c3fed39b016b8d81cc77dae70f60f"]="UMich Scanner (can use: zgrab)";
ja3_lookup_table["0e580f864235348848418123f96bbaa0"]="UMich Scanner (can use: zgrab)";
ja3_lookup_table["dc76bc3a4e3bc38939dfd90d8b7214b7"]="UMich Scanner (can use: zgrab)";
ja3_lookup_table["37f691b063c10372135db21579643bf1"]="urlgrabber/3.10 yum/3.4.3";
ja3_lookup_table["84071ea96fc8a60c55fc8a405e214c0f"]="Used by many desktop apps,Quip,Spotify,GitHub Desktop";
ja3_lookup_table["40fd0a5e81ebdcf0ec82a4710a12dec1"]="Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["618ee2509ef52bf0b8216e1564eea909"]="Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["799135475da362592a4be9199d258726"]="Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["7b530a25af9016a9d12de5abc54d9e74"]="Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["c05de18b01a054f2f6900ffe96b3da7a"]="Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["e4d448cdfe06dc1243c1eb026c74ac9a"]="Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["f1c5cf087b959cec31bd6285407f689a"]="Used by many programs on OSX,apple.WebKit.Networking";
ja3_lookup_table["488b6b601cb141b062d4da7f524b4b22"]="Used by many programs,Python,PHP,Git,dotnet,Adobe";
ja3_lookup_table["f28d34ce9e732f644de2350027d74c3f"]="Used by many programs,Quip,Aura,Spotify,Chatty";
ja3_lookup_table["190dfb280fe3b541acc6a2e5f00690e6"]="Used by many programs,Quip,Spotify,Dropbox,GitHub Desktop,etc";
ja3_lookup_table["20dd18bdd3209ea718989030a6f93364"]="Used by many programs,Slack,Postman,Spotify,Google Chrome";
ja3_lookup_table["2d96ffb535c7c7a30cad924b9b9f2b52"]="Valve Steam Client #1";
ja3_lookup_table["ab1fa6468096ab057291aa381d5de2b7"]="Valve Steam Client #2";
ja3_lookup_table["e0224fc1c33658f2d3d963bfb0a76a85"]="Viber";
ja3_lookup_table["41e3681b7c8c915e33b1f80d275c19d5"]="VirtualBox Update Poll (tested 5.0.8 r103449)";
ja3_lookup_table["81fb3e51bf3f18c5755146c28d07431b"]="VLC";
ja3_lookup_table["cff90930827e8b0f4e5a6fcc17319954"]="VMWare Fusion / Workstation / Player Update Check 8.x-12.x";
ja3_lookup_table["a50a861119aceb0ccc74902e8fddb618"]="VMWare Update Check 6.x";
ja3_lookup_table["48e69b57de145720885af2894f2ab9e7"]="VMware vSphere Client (Tested v4.1.0)";
ja3_lookup_table["01319090aea981dde6fc8d6ae71ead54"]="vpnkit";
ja3_lookup_table["10a686de1c41107df06c21df245e24cd"]="w3af (tested: v1.6.54 Kali 1)";
ja3_lookup_table["f13e6d84b915e17f76fdf4ea8c959b4d"]="w3af (tested: v1.6.54 Kali 2)";
ja3_lookup_table["345b5717dae9006a8bcd4cb1a5f09891"]="w3af (tested: v1.6.54 Kali 3)";
ja3_lookup_table["74ebac04b642a0cab032dd46e8099fdc"]="w3c HTML Validator";
ja3_lookup_table["4056657a50a8a4e5cfac40ba48becfa2"]="w3c HTML Validator, java,eclipse";
ja3_lookup_table["975ef0826e8485f2335db71873cb34c6"]="w3m (tested: 0.5.3 OS X)";
ja3_lookup_table["6b4b535249a1dcd95e3b4b6e9e572e5e"]="w3m 0.5.3 (OS X version)";
ja3_lookup_table["575771dbc723df24b764ac0303c19d10"]="w3m 0.5.3 / lynx 3.2 / svn 1.8.10 (openSUSE Leap 42.1)";
ja3_lookup_table["0172e9e41a8940e6a809967e4835214a"]="Web";
ja3_lookup_table["58d97971a14d0520c5c56caa75470948"]="WebKit per Safari 9.0.1 (11601.2.7.2)";
ja3_lookup_table["9ef7a86952e78eeb83590ff4d82a5538"]="WebKit per Safari 9.0.1 (11601.2.7.2)";
ja3_lookup_table["8e1172bd5dcc4698928c7eb454a2c3de"]="WeeChat";
ja3_lookup_table["5f1d4c631ddedf942033c9ae919158b8"]="wget (tested GNU Wget 1.16.1 & 1.17 on OS X)";
ja3_lookup_table["70663c6da28b3b9ac281d7b31d6b97c3"]="wget 1.14 (openSUSE Leap 42.1)";
ja3_lookup_table["444434ebe3f52b8453c3803bff077ebd"]="Wii-U";
ja3_lookup_table["c8d1364bba308db5a4a20c65c58ffde1"]="Win default thing a la webkit";
ja3_lookup_table["123b8f4705d525caffa3f2b36447f481"]="Win10 Mail Client";
ja3_lookup_table["aee020803d10a4d39072817184c8eedc"]="Windows 10 Native Connection";
ja3_lookup_table["205200cdaac61b110838556b834070d1"]="Windows 10 WebSockets (inc Edge) #1";
ja3_lookup_table["a7b2f0639f58f97aec151e015be1f684"]="Windows 8.x Apps Store thing (unconfirmed)";
ja3_lookup_table["0d15924fe8f8950a3ec3a916e97c8498"]="Windows 8.x Builtin Mail Client";
ja3_lookup_table["a8ee937cf82bb0972fecc23d63c9cd82"]="Windows 8.x TLS Socket";
ja3_lookup_table["2c14bfb3f8a2067fbc88d8345e9f97f3"]="Windows Watson WCEI Telemetry Gather";
ja3_lookup_table["84607748f3887541dd60fe974a042c71"]="wineserver";
ja3_lookup_table["4c8ff2ddb1890482e5989b80e48b54d4"]="WPScan (tested: 2.9 Kali)";
ja3_lookup_table["de364c46b0dfc283b5e38c79ceae3f8f"]="Yahoo! Slurp Indexer";
ja3_lookup_table["1202a58b454f54a47d2c216567ebd4fb"]="Yahoo! Slurp Indexer";
ja3_lookup_table["d83881675de3f6aacbcc0b2bae6f8923"]="Yandex Bot, wget 1.18";
ja3_lookup_table["11404429d240670cc018bed04e918b6f"]="youtube-dl 2016.06.03 (openSUSE Leap 42.1)";
ja3_lookup_table["f8f5b71e02603b283e55b50d17ede861"]="Zite (Android) 1 - May collide with Chrome";
ja3_lookup_table["5ae88f37a16f1b054f2edff1c8730471"]="Zite (Android) 2 - May collide with Chome";
ja3_lookup_table["c2b4710c6888a5d47befe865c8e6fb19"]="ZwiftApp";

# Iterate through the lookup table and add ja3_desc field to record 
    if ( c$ssl$ja3 in ja3_lookup_table )
        c$ssl$ja3_desc = ja3_lookup_table[c$ssl$ja3];
    else
        c$ssl$ja3_desc = "UNKNOWN";

# LOG FIELD VALUES ##
#c$ssl$ja3_version = cat(c$tlsfp$client_version);
#c$ssl$ja3_ciphers = c$tlsfp$client_ciphers;
#c$ssl$ja3_extensions = c$tlsfp$extensions;
#c$ssl$ja3_ec = c$tlsfp$e_curves;
#c$ssl$ja3_ec_fmt = c$tlsfp$ec_point_fmt;
#
# FOR DEBUGGING ##
#print "JA3: "+tlsfp_1+" Fingerprint String: "+ja3_string;

}

