// create context menus
/*
 * IP
 */

browser.contextMenus.create({
    id: "IP",
    title: "IP",
    contexts:["selection", "link", "image", "video", "audio"]
});

