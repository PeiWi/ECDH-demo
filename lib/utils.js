function _base64ToArrayBuffer(base64) {
    var binary_string = atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

function _arrayBufferToBase64(ab) {
    const binaryStr = String.fromCharCode.apply(null, new Uint8Array(ab));
    const b64Str = btoa(binaryStr);

    return b64Str;
}

function generateRandomBytes(length) {
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    
    return array;
}

function createMd5Hash(deriveResult) {
    const wordArray = CryptoJS.enc.Base64.parse(deriveResult);
    const md5Hash = CryptoJS.MD5(wordArray);
    const ivHex = md5Hash.toString(CryptoJS.enc.Hex).substr(0, 32);
    const ivBytes = [];
    for (let i = 0; i < ivHex.length; i += 2) {
        ivBytes.push(parseInt(ivHex.substr(i, 2), 16));
    }
    const ivArrayBuffer = new Uint8Array(ivBytes).buffer;

    return ivArrayBuffer;
}

function getEnvironmentInfo() {
    return new Promise((resolve) => {
        const platformInfo = {
            os: navigator.platform,
            browser: whichBrowser(),
        };
        resolve(platformInfo);
    });
}

function whichBrowser() {
    const userAgent = navigator.userAgent;
    if (userAgent.includes('Firefox')) {
        return 'Firefox';
    } else if (userAgent.includes('Chrome') && !userAgent.includes('Edge')) {
        return 'Chrome';
    } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
        return 'Safari';
    } else if (userAgent.includes('Edge')) {
        return 'Edge';
    } else {
        return 'Unknown';
    }
}

export {
    _base64ToArrayBuffer,
    _arrayBufferToBase64,
    generateRandomBytes,
    getEnvironmentInfo,
    createMd5Hash
}
