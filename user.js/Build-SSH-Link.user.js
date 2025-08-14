// ==UserScript==
// @name         Build SSH Link
// @namespace    http://tampermonkey.net/
// @version      0.1
// @description  Build SSH link for huashengdun-webssh 
// @author       ǝɔ∀ǝdʎz∀ɹɔ 👽
// @match        https://ssh.vps.vc/*
// @match        https://ssh.hax.co.id/*
// @match        https://ssh-crazypeace.koyeb.app/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=koyeb.app
// @grant        none
// ==/UserScript==


(function() {
    'use strict';

    // Your code here...
    // 获取 form 元素
    var form = document.getElementById("connect");

    /////////////////////
    // 创建 `<button>` 元素
    var buildLinkBtn = document.createElement("button");

    // 设置 `<button>` 的属性
    buildLinkBtn.type="button";
    buildLinkBtn.className="btn btn-info";
    buildLinkBtn.innerHTML="buildSSHLink";
    buildLinkBtn.id="sshlinkBtnA";

    // 将 `<button>` 添加到 `<form>` 元素范围内部的尾部
    form.appendChild(buildLinkBtn);

    ////////////////////
    // 创建 `<div>` 元素
    var sshlinkdiv = document.createElement("div");

    // 设置 `<div>` 的属性
    sshlinkdiv.id = "sshlinkA";

    // 将 `<div>` 添加到 `<form>` 元素范围内部的尾部
    form.appendChild(sshlinkdiv);

    ////////////////////
    // 让按钮的click事件 调用 updateSSHlinkA 函数
    document.querySelector('#sshlinkBtnA').addEventListener("click", updateSSHlinkA);
})();

function updateSSHlinkA() {
    var thisPageProtocol = window.location.protocol;
    var thisPageUrl = window.location.host;

    var hostnamestr = document.getElementById("hostname").value;
    var portstr = document.getElementById("port").value;
    if (portstr == "") {
        portstr = "22"
    }
    var usrnamestr = document.getElementById("username").value;
    if (usrnamestr == "") {
        usrnamestr = "root"
    }
    var passwdstr = document.getElementById("password").value;
    var passwdstrAfterBase64 = window.btoa(passwdstr);

    var sshlinkstr;
    sshlinkstr = thisPageProtocol+"//"+thisPageUrl+"/?hostname="+hostnamestr+"&port="+portstr+"&username="+usrnamestr+"&password="+passwdstrAfterBase64;

    document.getElementById("sshlinkA").innerHTML = sshlinkstr;
}
