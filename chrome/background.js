
// create Whois context menus

chrome.contextMenus.create({
    id: "whois",
    title: "whois",
    contexts:["selection", "link"]
});

chrome.contextMenus.create({
    id: "domaintools whois",
    title: "Domain Tools",
    contexts:["selection", "link"],
    parentId: "whois"
});

// create IP address context menus

chrome.contextMenus.create({
    id: "IP",
    title: "IP",
    contexts: ["selection", "link"]
});
//IPv4
chrome.contextMenus.create({
    id: "IPv4",
    title: "IPv4",
    contexts:["selection", "link"],
    parentId:"IP"
});

chrome.contextMenus.create({
    id:"abuseIPDB",
    title:"AbuseIPDB",
    contexts:["selection", "link"],
    parentId: "IPv4"
    });

chrome.contextMenus.create({
    id:"hackertarget IP",
    title:"HackerTarget",
    contexts:["selection", "link"],
    parentId: "IPv4"
});

chrome.contextMenus.create({
    id:"censys IP",
    title:"Censys",
    contexts:["selection", "link"],
    parentId: "IPv4"
});

chrome.contextMenus.create({
    id:"shodan",
    title:"Shodan IP",
    contexts:["selection", "link"],
    parentId: "IPv4"
});

chrome.contextMenus.create({
    id:"fofa",
    title:"FOFA IP",
    contexts:["selection", "link"],
    parentId: "IPv4"
});

chrome.contextMenus.create({
    id:"virustotal",
    title:"VirusTotal IP",
    contexts:["selection", "link"],
    parentId: "IPv4"
});
chrome.contextMenus.create({
    id: "greynoise",
    title: "Greynoise",
    contexts: ["selection", "link"],
    parentId: "IPv4"
});

chrome.contextMenus.create({
    id: "dnslytics ip",
    title: "DNSlytics",
    contexts: ["selection", "link"],
    parentId: "IPv4"
});

chrome.contextMenus.create({
    id: "tor ip",
    title: "Tor Relay IP",
    contexts: ["selection", "link"],
    parentId: "IPv4"
});

chrome.contextMenus.create({
    id: "threatcrowd ip",
    title: "ThreatCrowd IP",
    contexts: ["selection", "link"],
    parentId: "IPv4"
});

//IPv6
chrome.contextMenus.create({
    id: "IPv6",
    title: "IPv6",
    contexts: ["selection", "link"],
    parentId: "IP"
});

chrome.contextMenus.create({
    id: "dnslytics v6",
    title: "DNSlytics IPv6",
    contexts: ["selection", "link"],
    parentId: "IPv6"
});

chrome.contextMenus.create({
    id: "ultratools v6",
    title: "Ultratools v6",
    contexts: ["selection", "link"],
    parentId: "IPv6"
});


// create ASN search context menus
chrome.contextMenus.create({
    id: "asn",
    title: "ASN",
    contexts: ["selection", "link"]
});

chrome.contextMenus.create({
    id: "dnslytics asn",
    title: "DNSlytics ASN",
    contexts: ["selection", "link"],
    parentId: "asn"
});



// create Domain search context menus

chrome.contextMenus.create({
    id: "Domain",
    title: "Domain",
    contexts:["selection", "link"]
});

chrome.contextMenus.create({
    id:"censys Domain",
    title:"Censys",
    contexts:["selection", "link"],
    parentId: "Domain"
});

chrome.contextMenus.create({
    id:"shodan Domain",
    title:"Shodan",
    contexts:["selection", "link"],
    parentId: "Domain"
});

chrome.contextMenus.create({
    id:"domainwatch",
    title:"DomainWatch",
    contexts:["selection", "link"],
    parentId: "Domain"
});

chrome.contextMenus.create({
    id:"virustotal Domain",
    title:"VirusTotal",
    contexts:["selection", "link"],
    parentId: "Domain"
});

chrome.contextMenus.create({
    id: "tor domain",
    title: "Tor Relay domain",
    contexts: ["selection", "link"],
    parentId: "Domain"
});

chrome.contextMenus.create({
    id: "threatcrowd domain",
    title: "ThreatCrowd Domain",
    contexts: ["selection", "link"],
    parentId: "Domain"
});

// create SSL certificate search context menus

chrome.contextMenus.create({
    id: "certificate",
    title:"Certificate",
    contexts:["selection", "link"],
});

chrome.contextMenus.create({
    id:"crt.sh",
    title:"crt.sh",
    contexts:["selection","link"],
    parentId:"certificate"
});

chrome.contextMenus.create({
    id:"ssl-bl",
    title:"Abuse.ch SSLBL",
    contexts:["selection", "link"],
    parentId:"certificate"
});

// create URL search context menus

chrome.contextMenus.create({
    id: "URL",
    title: "URL",
    contexts: ["selection", "link"]
});

chrome.contextMenus.create({
    id:"urlscan",
    title:"URLscan",
    contexts:["selection", "link"],
    parentId: "URL"
});

chrome.contextMenus.create({
    id:"aguse",
    title:"aguse.jp",
    contexts:["selection","link"],
    parentId:"URL"
});

chrome.contextMenus.create({
    id:"check-host",
    title:"Check-Host",
    contexts:["selection","link"],
    parentId:"URL"
});
/*
chrome.contextMenus.create({
    id:"virustotal URL",
    title:"VirusTotal",
    contexts:["selection", "link"],
    parentId: "URL"
});
*/
chrome.contextMenus.create({
    id: "archive",
    title: "Wayback Machine",
    contexts: ["selection", "link"],
    parentId: "URL"
});

chrome.contextMenus.create({
    id:"url-haus",
    title:"URL Haus",
    contexts:["selection","link"],
    pranteId: "URL"
});


//create Vulnerability context menus
chrome.contextMenus.create({
    id: "Vuln",
    title: "Vuln",
    contexts:["selection"]
});

chrome.contextMenus.create({
    id: "fortiguard",
    title: "FortiGuard CVE",
    contexts:["selection"],
    parentId: "Vuln"
});

chrome.contextMenus.create({
    id: "sploitus",
    title: "Sploitus",
    contexts:["selection"],
    parentId: "Vuln"
});

chrome.contextMenus.create({
    id: "vulmon",
    title:"Vulmon",
    contexts:["selection"],
    parentId: "Vuln"
});

chrome.contextMenus.create({
    id: "cxsecurity",
    title: "CXSecurity",
    contexts:["selection"],
    parentId: "Vuln"
});

chrome.contextMenus.create({
    id: "vulncode",
    title: "Vulncode DB",
    contexts: ["selection"],
    parentId: "Vuln"
});

// Create Malicious Software Search context menus
chrome.contextMenus.create({
    id: "hash",
    title: "Hashes",
    contexts:["selection"]
});

chrome.contextMenus.create({
    id: "malshare",
    title: "Malshare",
    contexts:["selection"],
    parentId: "hash"
});

chrome.contextMenus.create({
    id: "virustotal hash",
    title: "VirusTotal Hash",
    contexts: ["selection"],
    parentId: "hash"
});




//create SNS search context menus

chrome.contextMenus.create({
    id: "social",
    title: "Social",
    contexts:["selection"]
});

chrome.contextMenus.create({
    id:"twitter",
    title:"Twitter",
    contexts:["selection"],
    parentId: "social"
});

chrome.contextMenus.create({
    id:"qiita",
    title:"Qiita",
    contexts:["selection"],
    parentId: "social"
});

chrome.contextMenus.create({
    id:"github",
    title:"Github",
    contexts:["selection"],
    parentId: "social"
});


chrome.contextMenus.create({
    id:"facebook",
    title:"FaceBook",
    contexts:["selection"],
    parentId: "social"
});

chrome.contextMenus.create({
    id:"instagram",
    title:"Instagram",
    contexts:["selection"],
    parentId: "social"
});

chrome.contextMenus.create({
    id:"linkedin",
    title:"LinkedIn",
    contexts:["selection"],
    parentId: "social"
});

chrome.contextMenus.create({
    id: "pinterest",
    title: "Pinterest",
    contexts:["selection"],
    parentId: "social"
});


//create empty variables
var url = "";
var artifact = "";
var v6URI = "";

/*
*source 
*https://github.com/mitchmoser/sputnik
*https://stackoverflow.com/questions/13899299/write-text-to-clipboard#18258178
*/
function copyStringToClipboard(str) {
    // Create new element
    var el = document.createElement("textarea");
    // Set value (string to be copied)
    el.value = str;
    // Set non-editable to avoid focus and move outside of view
    el.setAttribute("readonly", "");
    el.style = {position: "absolute", left: "-9999px"};
    document.body.appendChild(el);
    // Select text inside element
    el.select();
    // Copy text to clipboard
    document.execCommand("copy");
    // Remove temporary element
    document.body.removeChild(el);
    }

//refang function
function optimizeArtifact(artifact){
    while(artifact.includes("[.]")){
        artifact = artifact.replace("[.]",".");
    }
    if(artifact.includes("hxxp://")){
        artifact = artifact.replace("hxxp://","http://");
    }
    if(artifact.includes("hxxps://")){
        artifact = artifact.replace("hxxps://","https://");
    }
    if(artifact.includes("http[:]//")){
        artifact = artifact.replace("http[:]//","http://")
    }
    if(artifact.includes("https[:]//")){
        artifact = artifact.replace("https[:]//","https://")
    }
    return artifact;
};

// when you click artifact, kisten up event listener function
chrome.contextMenus.onClicked.addListener((info, tab) => {
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
    
    artifact = optimizeArtifact(artifact);

    copyStringToClipboard(artifact);

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

    case "tor ip":
        url = "https://metrics.torproject.org/rs.html#search/"+artifact;
        break;

    case "threatcrowd ip":
        url="https://www.threatcrowd.org/ip.php?ip="+artifact;
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
        url ="https://dnslytics.com/bgp/"+artifact.toLowerCase();
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

    case "tor domain":
        url ="https://metrics.torproject.org/rs.html#search/"+artifact;
        break;

    case "threatcrowd domain":
        url="https://www.threatcrowd.org/domain.php?domain="+artifact;
        break;

    // certificate
    
    case "crt.sh":
        url="https://crt.sh/?q="+artifact;
        break;

    case "ssl-bl":
        url ="https://sslbl.abuse.ch/ssl-certificates/sha1/"+artifact;
        break;

    //URL

    case "urlscan":
        url = "https://urlscan.io/api/v1/search/?q=domain:"+artifact;
        break;
    
    case "aguse":
        url = "https://www.aguse.jp/?url="+encodeURIComponent(artifact);
        break;

    case "check-host":
        url = "https://check-host.net/ip-info?host="+artifact;
        break;
/*  TODO convert URL to SHA256
    case "virustotal URL":
        url ="https://virustotal.com/#/home/url/"+artifact;
        break;
*/
    case "archive":
        url = "https://web.archive.org/web/*/"+artifact;
        break;
    
    case "url-haus":
        url = "https://urlhaus.abuse.ch/browse.php?search="+artifact;
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
    chrome.tabs.create({url: url});
});