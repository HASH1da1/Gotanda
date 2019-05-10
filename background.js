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
    id:"gitlab",
    title:"GitLab",
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