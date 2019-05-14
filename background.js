// create IP address context menus

browser.contextMenus.create({
    id: "IP",
    title: "IP",
    contexts:["selection", "link", "image", "video", "audio"]
});

browser.contextMenus.create({
    id:"abuseIPDB",
    title:"AbuseIPDB",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "IP"
});

browser.contextMenus.create({
    id:"hackertarget IP",
    title:"HackerTarget",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "IP"
});

browser.contextMenus.create({
    id:"censys IP",
    title:"Censys",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "IP"
});

browser.contextMenus.create({
    id:"shodan",
    title:"Shodan IP",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "IP"
});

browser.contextMenus.create({
    id:"fofa",
    title:"FOFA IP",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "IP"
});

browser.contextMenus.create({
    id:"virustotal",
    title:"VirusTotal IP",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "IP"
});

// create Domain search context menus

browser.contextMenus.create({
    id: "Domain",
    title: "Domain",
    contexts:["selection", "link", "image", "video", "audio"]
});

browser.contextMenus.create({
    id:"censys Domain",
    title:"Censys",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "Domain"
});

browser.contextMenus.create({
    id:"shodan Domain",
    title:"Shodan",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "Domain"
});

browser.contextMenus.create({
    id:"domainwatch",
    title:"DomainWatch",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "Domain"
});

browser.contextMenus.create({
    id:"virustotal Domain",
    title:"VirusTotal",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "Domain"
});

// create URL search context menus

browser.contextMenus.create({
    id: "URL",
    title: "URL",
    contexts: ["selection", "link", "image", "video", "audio"]
});

browser.contextMenus.create({
    id:"urlscan",
    title:"URLscan",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "URL"
});

browser.contextMenus.create({
    id:"hackertarget",
    title:"HackerTarget",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "URL"
});

browser.contextMenus.create({
    id:"virustotal URL",
    title:"VirusTotal",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "URL"
});

//create SNS search context menus

browser.contextMenus.create({
    id: "SNS",
    title: "SNS",
    contexts:["selection", "link", "image", "video", "audio"]
});

browser.contextMenus.create({
    id:"twitter",
    title:"Twitter",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "SNS"
});

browser.contextMenus.create({
    id:"qiita",
    title:"Qiita",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "SNS"
});

browser.contextMenus.create({
    id:"github",
    title:"Github",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "SNS"
});


browser.contextMenus.create({
    id:"facebook",
    title:"FaceBook",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "SNS"
});

browser.contextMenus.create({
    id:"instagram",
    title:"Instagram",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "SNS"
});

browser.contextMenus.create({
    id:"linkedin",
    title:"LinkedIn",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "SNS"
});

browser.contextMenus.create({
    id:"jusyodepon",
    title:"住所でポン",
    contexts:["selection", "link", "image","video", "audio"],
    parentID: "SNS"
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
    //IP
    case "abuseIPDB":
        url = "https://www.abusipdb.com/check"+artifact;
        break;
    
    case "hackertarget IP":
        url = "https://api.hacketarget.com/reverseiplookup/?q="+artifatct;
        break;
    
    case "censys IP":
        url = "https://censys.io/ipv4/"+artifact;
        break;
    
    case "shodan":
        url = "https://www.shodan.io/host/"+artifact;
        break;
    
    case "fofa":
        url = "https://fofa.so/result?qbase64="+window.btoa(aritfact);
        break;

    case "virtutoal IP":
        url = "https://virustotal.com/#/ip-address/"+artifact;
        break;
    //Domain

    case "censys domain":
        url = "https://censys.io/domain?q="+artifact;
        break;
    
    case "shodan domain":
        url = "https://www.shodan.io/search?query="+artifact;
        break;

    case "domain watch":
        url = "https://domainwat.ch/site/"+artifact;
        break;
    
    case "virustotal domain":
        url = "https://virustotal.com/#/domain/"+artifact;
        break;
    //URL

    case "URL scan":
        url = "https://urlscan.io/";
        break;

    case "hacker target":
        url = "https://hackertarget.com/extract-links/";
        break;

    case "virustotal URL":
        url ="https://virustotal.com/#/home/url";
        break;

    //SNS

    case "twitter":
        url = "https://twitter.com/"+artifact;
        break;

    case "qiita":
        url = "hhtps://qiita.com/"+artifact;
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

    case "jusyodepon":
        url = "https://jpon.xyz/index.php?q="+artifact+"&path=2012";
        break;
}
browser.tabs.create({url: url});

navigator.clipboard.writeText(artifact);
});