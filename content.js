browser.contextMenus.create({
    id: "copy link save as clipboard",
    title:"copy link to clipboard",
    contexts:["link"],
});
browser.contextMenus.onClicked.addListener((info, tab) => {
    if(info.menuItemId === "copy-link-to-clipboard"){
        const text = "This is text:" + info.linkUrl;
        const safeUrl = escapeHTML(info.linkUrl);
        const html = 'This is HTML: <a href="${safeUrl}">${safeUrl}</a>';
    }
})