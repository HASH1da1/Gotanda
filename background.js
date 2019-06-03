// create Whois context menus

browser.contextMenus.create({
    id: "whois",
    title: "whois",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id: "domaintools whois",
    title: "Domain Tools(e.g. hoge.com)",
    contexts:["selection", "link"],
    parentId: "whois"
});

// create IP address context menus

browser.contextMenus.create({
    id: "IP",
    title: "IP",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id:"abuseIPDB",
    title:"AbuseIPDB(e.g. x.x.x.x)",
    contexts:["selection", "link"],
    parentId: "IP"
});

browser.contextMenus.create({
    id:"hackertarget IP",
    title:"HackerTarget(e.g. x.x.x.x)",
    contexts:["selection", "link"],
    parentId: "IP"
});

browser.contextMenus.create({
    id:"censys IP",
    title:"Censys(e.g. x.x.x.x)",
    contexts:["selection", "link"],
    parentId: "IP"
});

browser.contextMenus.create({
    id:"shodan",
    title:"Shodan IP(e.g. x.x.x.x)",
    contexts:["selection", "link"],
    parentId: "IP"
});

browser.contextMenus.create({
    id:"fofa",
    title:"FOFA IP(e.g. x.x.x.x)",
    contexts:["selection", "link"],
    parentId: "IP"
});

browser.contextMenus.create({
    id:"virustotal",
    title:"VirusTotal IP(e.g. x.x.x.x)",
    contexts:["selection", "link"],
    parentId: "IP"
});



// create Domain search context menus

browser.contextMenus.create({
    id: "Domain",
    title: "Domain",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id:"censys Domain",
    title:"Censys(e.g hoge.com)",
    contexts:["selection", "link"],
    parentId: "Domain"
});

browser.contextMenus.create({
    id:"shodan Domain",
    title:"Shodan(e.g. hoge.com)",
    contexts:["selection", "link"],
    parentId: "Domain"
});

browser.contextMenus.create({
    id:"domainwatch",
    title:"DomainWatch(e.g hoge.com)",
    contexts:["selection", "link"],
    parentId: "Domain"
});

browser.contextMenus.create({
    id:"virustotal Domain",
    title:"VirusTotal(e.g. hoge.com)",
    contexts:["selection", "link"],
    parentId: "Domain"
});

// create URL search context menus

browser.contextMenus.create({
    id: "URL",
    title: "URL",
    contexts: ["selection", "link"]
});

browser.contextMenus.create({
    id:"urlscan",
    title:"URLscan(e.g. hxxp://hoge.com/)",
    contexts:["selection", "link"],
    parentId: "URL"
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
    title: "Wayback Machine(e.g. hxxp://hoge.com)",
    contexts: ["selection", "link"],
    parentId: "URL"
});


//create Vulnerability context menus
browser.contextMenus.create({
    id: "Vuln",
    title: "Vuln",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id: "fortiguard",
    title: "FortiGuard CVE(e.g. cve-20xx-xxx)",
    contexts:["selection", "link"],
    parentId: "Vuln"
});

browser.contextMenus.create({
    id: "sploitus",
    title: "Sploitus(e.g. cve-20xx-xxx,, service name)",
    contexts:["selection", "link"],
    parentId: "Vuln"
});

browser.contextMenus.create({
    id: "vulmon",
    title:"Vulmon(e.g. cve-20xx-xxx)",
    contexts:["selection", "link"],
    parentId: "Vuln"
});

// Create Malicious Software Search context menus
browser.contextMenus.create({
    id: "malware",
    title: "Malware",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id: "malshare",
    title: "Malshare(MD5)",
    contexts:["selection", "link"],
    parentId: "malware"
});




//create SNS search context menus

browser.contextMenus.create({
    id: "SNS",
    title: "SNS Account",
    contexts:["selection", "link"]
});

browser.contextMenus.create({
    id:"twitter",
    title:"Twitter",
    contexts:["selection", "link"],
    parentId: "SNS"
});

browser.contextMenus.create({
    id:"qiita",
    title:"Qiita",
    contexts:["selection", "link"],
    parentId: "SNS"
});

browser.contextMenus.create({
    id:"github",
    title:"Github",
    contexts:["selection", "link"],
    parentId: "SNS"
});


browser.contextMenus.create({
    id:"facebook",
    title:"FaceBook",
    contexts:["selection", "link"],
    parentId: "SNS"
});

browser.contextMenus.create({
    id:"instagram",
    title:"Instagram",
    contexts:["selection", "link"],
    parentId: "SNS"
});

browser.contextMenus.create({
    id:"linkedin",
    title:"LinkedIn",
    contexts:["selection", "link"],
    parentId: "SNS"
});

browser.contextMenus.create({
    id: "pinterest",
    title: "Pinterest",
    contexts:["selection", "link"],
    parentId: "SNS"
});


//create empty variables
var url = "";
var artifact = "";


// when you click event listener function


browser.contextMenus.onClicked.addListener((info, tab) => {
    // strip leading and trailing spaces
    if (info.selectionText) {
        artifact = String(info.selectionText).trim();
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
    //IP
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


    //Malware
    case "malshare":
        url = "https://malshare.com/search.php?query="+artifact;
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