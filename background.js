// create Whois context menus

browser.contextMenus.create({
    id: "whois",
    title: "whois",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id: "domaintools whois",
    title: "Domain Tools",
    contexts:["selection", "link"],
    parentId: "whois",
    icons: {
        "16": "icons/icon/domaintools.png"
    }
});

// create IP address context menus

browser.contextMenus.create({
    id: "IP",
    title: "IP",
    contexts: ["selection", "link"]
})

browser.contextMenus.create({
    id: "IPv4",
    title: "IPv4",
    contexts:["selection", "link"],
    parentId:"IP"
});

browser.contextMenus.create({
    id:"abuseIPDB",
    title:"AbuseIPDB",
    contexts:["selection", "link"],
    parentId: "IPv4",
    icons: {
        "16": "icons/icon/abuseipdb.png"
    }
});

browser.contextMenus.create({
    id:"hackertarget IP",
    title:"HackerTarget",
    contexts:["selection", "link"],
    parentId: "IPv4",
    icons: {
        "16": "icons/icon/hackertarget.png"
    }
});

browser.contextMenus.create({
    id:"censys IP",
    title:"Censys",
    contexts:["selection", "link"],
    parentId: "IPv4",
    icons: {
        "16": "icons/icon/censys.png"
    }
});

browser.contextMenus.create({
    id:"shodan",
    title:"Shodan IP",
    contexts:["selection", "link"],
    parentId: "IPv4",
    icons: {
        "16": "icons/icon/shodan.png"
    }
});

browser.contextMenus.create({
    id:"fofa",
    title:"FOFA IP",
    contexts:["selection", "link"],
    parentId: "IPv4",
    icons:{
        "16": "icons/icon/fofa.png"
    }
});

browser.contextMenus.create({
    id:"virustotal",
    title:"VirusTotal IP",
    contexts:["selection", "link"],
    parentId: "IPv4",
    icons:{
        "16": "icons/icon/virustotal.png"
    }
});
browser.contextMenus.create({
    id: "greynoise",
    title: "Greynoise",
    contexts: ["selection", "link"],
    parentId: "IPv4",
    icons:{
        "16": "icons/icon/greynoise.png"
    }
});

browser.contextMenus.create({
    id: "dnslytics ip",
    title: "DNSlytics",
    contexts: ["selection", "link"],
    parentId: "IPv4",
    icons: {
        "16": "icons/icon/dnslytics.png"

    }
});

browser.contextMenus.create({
    id: "tor ip",
    title: "Tor Relay IP",
    contexts: ["selection", "link"],
    parentId: "IPv4",
    icons: {
        "16": "icons/icon/tor.ico"
    }
});


browser.contextMenus.create({
    id: "IPv6",
    title: "IPv6",
    contexts: ["selection", "link"],
    parentId: "IP"
});

browser.contextMenus.create({
    id: "dnslytics v6",
    title: "DNSlytics IPv6",
    contexts: ["selection", "link"],
    parentId: "IPv6",
    icons: {
        "16": "icons/icon/dnslytics.png"
    }
});

browser.contextMenus.create({
    id: "ultratools v6",
    title: "Ultratools v6",
    contexts: ["selection", "link"],
    parentId: "IPv6",
    icons: {
        "16": "icons/icon/ultratools.png"
    }
})


// create ASN search context menus
browser.contextMenus.create({
    id: "asn",
    title: "ASN",
    contexts: ["selection", "link"]
});

browser.contextMenus.create({
    id: "dnslytics asn",
    title: "DNSlytics ASN",
    contexts: ["selection", "link"],
    parentId: "asn",
    icons: {
        "16": "icons/icon/dnslytics.png"
    }
});



// create Domain search context menus

browser.contextMenus.create({
    id: "Domain",
    title: "Domain",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id:"censys Domain",
    title:"Censys",
    contexts:["selection", "link"],
    parentId: "Domain",
    icons: {
        "16": "icons/icon/censys.png"
    }
});

browser.contextMenus.create({
    id:"shodan Domain",
    title:"Shodan",
    contexts:["selection", "link"],
    parentId: "Domain",
    icons: {
        "16": "icons/icon/shodan.png"
    }
});

browser.contextMenus.create({
    id:"domainwatch",
    title:"DomainWatch",
    contexts:["selection", "link"],
    parentId: "Domain",
    icons: {
        "16": "icons/icon/domainwatch.png"
    }
});

browser.contextMenus.create({
    id:"virustotal Domain",
    title:"VirusTotal",
    contexts:["selection", "link"],
    parentId: "Domain",
    icons: {
        "16": "icons/icon/virustotal.png"
    }
});

browser.contextMenus.create({
    id: "tor domain",
    title: "Tor Relay domain",
    contexts: ["selection", "link"],
    parentId: "Domain",
    icons: {
        "16": "icons/icon/tor.ico"
    }
});

// create URL search context menus

browser.contextMenus.create({
    id: "URL",
    title: "URL",
    contexts: ["selection", "link"]
});

browser.contextMenus.create({
    id:"urlscan",
    title:"URLscan",
    contexts:["selection", "link"],
    parentId: "URL",
    icons: {
        "16": "icons/icon/urlscan.png"
   }
});
/*
browser.contextMenus.create({
    id:"virustotal URL",
    title:"VirusTotal",
    contexts:["selection", "link"],
    parentId: "URL"
});
*/
browser.contextMenus.create({
    id: "archive",
    title: "Wayback Machine",
    contexts: ["selection", "link"],
    parentId: "URL",
    icons: {
        "16": "icons/icon/archive.png"
    }
});


//create Vulnerability context menus
browser.contextMenus.create({
    id: "Vuln",
    title: "Vuln",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id: "fortiguard",
    title: "FortiGuard CVE",
    contexts:["selection", "link"],
    parentId: "Vuln",
    icons: {
        "16": "icons/icon/fortiguard.png"
    }
});

browser.contextMenus.create({
    id: "sploitus",
    title: "Sploitus",
    contexts:["selection", "link"],
    parentId: "Vuln",
    icons: {
        "16": "icons/icon/sploitus.png"
    }
});

browser.contextMenus.create({
    id: "vulmon",
    title:"Vulmon",
    contexts:["selection", "link"],
    parentId: "Vuln",
    icons: {
        "16": "icons/icon/vulmon.png"
    }
});

browser.contextMenus.create({
    id: "cxsecurity",
    title: "CXSecurity",
    contexts:["selection", "link" ],
    parentId: "Vuln",
    icons:{
        "16": "icons/icon/cxsecurity.png"
    }
});

browser.contextMenus.create({
    id: "vulncode",
    title: "Vulncode DB",
    contexts: ["selection", "link"],
    parentId: "Vuln",
    icons: {
        "16": "icons/icon/vulncode.png"  
    }
});

// Create Malicious Software Search context menus
browser.contextMenus.create({
    id: "hash",
    title: "Hashes",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id: "malshare",
    title: "Malshare",
    contexts:["selection", "link"],
    parentId: "hash",
    icons: {
        "16": "icons/icon/malshare.png"
    }
});

browser.contextMenus.create({
    id: "virustotal hash",
    title: "VirusTotal Hash",
    contexts: ["selection", "link"],
    parentId: "hash",
    icons:{
        "16": "icons/icon/virustotal.png"
    }   
})




//create SNS search context menus

browser.contextMenus.create({
    id: "social",
    title: "Social",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id:"twitter",
    title:"Twitter",
    contexts:["selection", "link"],
    parentId: "social",
    icons: {
        "16": "icons/icon/twitter.png"
    }
});

browser.contextMenus.create({
    id:"qiita",
    title:"Qiita",
    contexts:["selection", "link"],
    parentId: "social",
    icons: {
        "16": "icons/icon/qiita.png"
    }
});

browser.contextMenus.create({
    id:"github",
    title:"Github",
    contexts:["selection", "link"],
    parentId: "social",
    icons: {
        "16": "icons/icon/github.png"
    }
});


browser.contextMenus.create({
    id:"facebook",
    title:"FaceBook",
    contexts:["selection", "link"],
    parentId: "social",
    icons: {
        "16": "icons/icon/facebook.png"
    }
});

browser.contextMenus.create({
    id:"instagram",
    title:"Instagram",
    contexts:["selection", "link"],
    parentId: "social",
    icons: {
        "16": "icons/icon/instagram.png"
    }
});

browser.contextMenus.create({
    id:"linkedin",
    title:"LinkedIn",
    contexts:["selection", "link"],
    parentId: "social",
    icons: {
        "16": "icons/icon/linkedin.png"
    }
});

browser.contextMenus.create({
    id: "pinterest",
    title: "Pinterest",
    contexts:["selection", "link"],
    parentId: "social",
    icons: {
        "16": "icons/icon/pinterest.png"
    }
});


//create empty variables
var url = "";
var artifact = "";
var v6URI = "";



// when you click event listener function


browser.contextMenus.onClicked.addListener((info, tab) => {
    // strip leading and trailing spaces
    if (info.selectionText) {
        artifact = String(info.selectionText).trim();
        v6URI = encodeURIComponent(info.selectionText);
    } else if (info.linkUrl) {
        var link = new URL(info.linkUrl);
        artifact = link.host;
    } else if (info.srcUrl) {
        var src = new URL(info.srcUrl);
        artifact = src.host;
    }
    
switch (info.menuItemId){
    //whois
    case "domaintools whois":
        url = "https://whois.domaintools.com/"+artifact;
        break;
    //IPv4
    case "abuseIPDB":
        url = "https://www.abuseipdb.com/check/"+artifact;
        break;
    
    case "hackertarget IP":
        url = "https://api.hackertarget.com/reverseiplookup/?q="+artifact;
        break;
    
    case "censys IP":
        url = "https://censys.io/ipv4/"+artifact;
        break;
    
    case "shodan":
        url = "https://www.shodan.io/host/"+artifact;
        break;
    
    case "fofa":
        url = "https://fofa.so/result?qbase64="+window.btoa(artifact);
        break;

    case "virustotal":
        url = "https://virustotal.com/#/ip-address/"+artifact;
        break;

    case "greynoise":
        url = "https://viz.greynoise.io/ip/"+artifact;
        break;
    case "dnslytics ip":
        url = "https://dnslytics.com/ip/"+artifact;
        break;  

    case "tor relay ip":
        url = "https://metrics.torproject.org/rs.html#search/"+artifact;
        break;

    //IPv6

    case "dnslytics v6":
        url ="https://dnslytics.com/ipv6/"+artifact;
        break;
    
    case "ultratools v6":
        url ="https://www.ultratools.com/tools/ipv6InfoResult?ipAddress="+v6URI;
        break;

    //ASN
    case "dnslytics asn":
        url ="https://dnslytics.com/bgp/"+artifact;
        break;
    
        
    //Domain

    case "censys Domain":
        url = "https://censys.io/domain?q="+artifact;
        break;
    
    case "shodan Domain":
        url = "https://www.shodan.io/search?query="+artifact;
        break;

    case "domainwatch":
        url = "https://domainwat.ch/site/"+artifact;
        break;
    
    case "virustotal Domain":
        url = "https://virustotal.com/#/domain/"+artifact;
        break;

    case "tor relay domain":
        url ="https://metrics.torproject.org/rs.html#search/"+artifact;
        break;
    //URL

    case "urlscan":
        url = "https://urlscan.io/api/v1/search/?q=domain:"+artifact;
        break;
/*
    case "virustotal URL":
        url ="https://virustotal.com/#/home/url/"+artifact;
        break;
*/
    case "archive":
        url = "https://web.archive.org/web/*/"+artifact;
        break;


    //Vuln

    case "fortiguard":
        url = "https://fortiguard.com/search?q="+artifact+"&engine=3";
        break;

    case "sploitus":
        url = "https://sploitus.com/?query="+artifact+"#exploits";
        break;

    case "vulmon":
        url = "https://vulmon.com/searchpage?q="+artifact;
        break;
    
    case "cxsecurity":
        url = "https://cxsecurity.com/cveshow/"+artifact;
        break;

    case "vulncode":
        url = "https://www.vulncode-db.com/"+artifact;
        break;
    //hashes
    case "malshare":
        url = "https://malshare.com/search.php?query="+artifact;
        break;

    case "virustotal hash":
        url = "https://www.virustotal.com/gui/search/"+artifact;
        break;

    //SNS

    case "twitter":
        url = "https://twitter.com/"+artifact;
        break;

    case "qiita":
        url = "https://qiita.com/"+artifact;
        break;

    case "github":
        url = "https://github.com/"+artifact;
        break;

    case "facebook":
        url = "https://www.facebook.com/public/"+artifact;
        break;
    
    case "instagram":
        url = "https://www.instagram.com/"+artifact;
        break;

    case "linkedin":
        url = "https://www.linkedin.com/in/"+artifact;
        break;

    case "pinterest":
        url = "https://www.pinterest.jp/"+artifact;
        break;

}
browser.tabs.create({url: url});

navigator.clipboard.writeText(artifact);
});