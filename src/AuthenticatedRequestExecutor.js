"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthenticatedRequestExecutor = void 0;
var HttpsRequest_1 = require("./HttpsRequest");
var crypto = require("crypto");
var buffer = require("buffer");
var url = require("url");
var uuid_1 = require("uuid");
var AuthenticatedRequestExecutor = /** @class */ (function () {
    function AuthenticatedRequestExecutor(consumerKey, consumerSecret, token, tokenSecret, realm) {
        if (token === void 0) { token = ''; }
        if (tokenSecret === void 0) { tokenSecret = ''; }
        if (realm === void 0) { realm = ''; }
        this.usedNonce = new Set();
        this.nonceTimestamp = 0;
        this.oauthConsumerKey = consumerKey;
        this.oauthConsumerSecret = consumerSecret;
        this.oauthToken = token;
        this.oauthTokenSecret = tokenSecret;
        this.realm = realm;
    }
    AuthenticatedRequestExecutor.encodePercent = function (data) {
        var input = buffer.Buffer.from(data, 'utf-8');
        var output = "";
        for (var i = 0; i < input.length; i++) {
            var n = input[i];
            if ((0x30 <= n && n <= 0x39) || (0x41 <= n && n <= 0x5a) || (0x61 <= n && n <= 0x7a) || n == 0x2d || n == 0x2e || n == 0x5f || n == 0x7e) {
                output += Buffer.from([n]).toString('utf-8');
            }
            else {
                var s = n.toString(16).toUpperCase();
                if (s.length == 1)
                    s = '0' + 's';
                output += '%' + s;
            }
        }
        return output;
    };
    AuthenticatedRequestExecutor.prototype.makeBaseAuthorizationHeader = function () {
        var r = {};
        r['oauth_consumer_key'] = this.oauthConsumerKey;
        if (this.oauthToken.length > 0) {
            r['oauth_token'] = this.oauthToken;
        }
        if (this.realm.length > 0) {
            r['realm'] = this.realm;
        }
        r['oauth_signature_method'] = 'HMAC-SHA1';
        r['oauth_version'] = '1.0';
        r['oauth_nonce'] = this.generateNonce();
        r['oauth_timestamp'] = this.nonceTimestamp.toString();
        return r;
    };
    AuthenticatedRequestExecutor.currentTimestamp = function () {
        return Math.floor(Date.now() / 1000);
    };
    AuthenticatedRequestExecutor.prototype.generateNonce = function () {
        var t = AuthenticatedRequestExecutor.currentTimestamp();
        if (t != this.nonceTimestamp) {
            this.nonceTimestamp = t;
            this.usedNonce.clear();
        }
        while (true) {
            var r = uuid_1.v4();
            if (!this.usedNonce.has(r)) {
                this.usedNonce.add(r);
                return r;
            }
        }
    };
    AuthenticatedRequestExecutor.collectParameters = function (authorizationHeader, queries, requestBody) {
        var r = {};
        for (var e in queries) {
            r[e] = queries[e];
        }
        for (var e in requestBody) {
            r[e] = requestBody[e];
        }
        for (var e in authorizationHeader) {
            if (e != "realm" && e != "oauth_signature") {
                r[e] = authorizationHeader[e];
            }
        }
        return r;
    };
    AuthenticatedRequestExecutor.sortParameters = function (params) {
        var pe = [];
        for (var e in params) {
            pe.push([AuthenticatedRequestExecutor.encodePercent(e), AuthenticatedRequestExecutor.encodePercent(params[e])]);
        }
        pe.sort((function (a, b) {
            if (a[0] != b[0]) {
                return a[0] > b[0] ? 1 : -1;
            }
            else if (a[1] != b[1]) {
                return a[1] > b[1] ? 1 : -1;
            }
            else {
                return 0;
            }
        }));
        return pe;
    };
    AuthenticatedRequestExecutor.makeNormalizedParameters = function (authorizationHeader, queries, requestBody) {
        var p = AuthenticatedRequestExecutor.collectParameters(authorizationHeader, queries, requestBody);
        var pe = this.sortParameters(p);
        var r = "";
        for (var e in pe) {
            r += pe[e][0] + '=' + pe[e][1] + '&';
        }
        return r.substr(0, r.length - 1);
    };
    AuthenticatedRequestExecutor.makeBaseStringUri = function (uri) {
        var u = new url.URL(uri);
        var proto = u.protocol.toLowerCase();
        if (proto != "http:" && proto != "https:") {
            throw "Invalid URL: " + proto;
        }
        return proto + "//" + u.hostname.toLowerCase() + u.port + u.pathname;
    };
    AuthenticatedRequestExecutor.makeSignatureBaseString = function (method, uri, authorizationHeader, queries, requestBody) {
        return method + '&' +
            AuthenticatedRequestExecutor.encodePercent(AuthenticatedRequestExecutor.makeBaseStringUri(uri)) + '&' +
            AuthenticatedRequestExecutor.encodePercent(AuthenticatedRequestExecutor.makeNormalizedParameters(authorizationHeader, queries, requestBody));
    };
    AuthenticatedRequestExecutor.computeHmacSha1 = function (value, key) {
        return new Promise(function (resolve, reject) {
            var hmac = crypto.createHmac('sha1', key);
            hmac.update(value);
            hmac.on('error', function (err) {
                reject(err);
            });
            resolve(hmac.digest('base64'));
        });
    };
    AuthenticatedRequestExecutor.prototype.makeSignatureKey = function () {
        return AuthenticatedRequestExecutor.encodePercent(this.oauthConsumerSecret) + '&' + AuthenticatedRequestExecutor.encodePercent(this.oauthTokenSecret);
    };
    AuthenticatedRequestExecutor.prototype.makeSignature = function (method, uri, authorizationHeader, queries, requestBody) {
        return __awaiter(this, void 0, void 0, function () {
            var bs, sk;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        bs = AuthenticatedRequestExecutor.makeSignatureBaseString(method, uri, authorizationHeader, queries, requestBody);
                        sk = this.makeSignatureKey();
                        return [4 /*yield*/, AuthenticatedRequestExecutor.computeHmacSha1(bs, sk)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    AuthenticatedRequestExecutor.prototype.makeAuthorizationHeader = function (method, uri, queries, requestBody) {
        return __awaiter(this, void 0, void 0, function () {
            var t, _a, _b, nt, r, e;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        t = this.makeBaseAuthorizationHeader();
                        _a = t;
                        _b = 'oauth_signature';
                        return [4 /*yield*/, this.makeSignature(method, uri, t, queries, requestBody)];
                    case 1:
                        _a[_b] = _c.sent();
                        nt = AuthenticatedRequestExecutor.sortParameters(t);
                        r = "OAuth ";
                        for (e in nt) {
                            r += nt[e][0] + "=\"" + nt[e][1] + "\", ";
                        }
                        return [2 /*return*/, r.substr(0, r.length - 2)];
                }
            });
        });
    };
    AuthenticatedRequestExecutor.prototype.request = function (method, uri, queries, headers, requestBody) {
        return __awaiter(this, void 0, void 0, function () {
            var ah, t, e, req;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.makeAuthorizationHeader(method, uri, queries, requestBody)];
                    case 1:
                        ah = _a.sent();
                        t = {};
                        for (e in headers) {
                            t[e] = headers[e];
                        }
                        t["Authorization"] = ah;
                        req = new HttpsRequest_1.HttpsRequest(uri, method, t, queries, requestBody);
                        return [4 /*yield*/, req.fetch()];
                    case 2: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    AuthenticatedRequestExecutor.prototype.requestUrlEncoded = function (method, uri, queries, headers, requestBody) {
        return __awaiter(this, void 0, void 0, function () {
            var s, u, r;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.request(method, uri, queries, headers, requestBody)];
                    case 1:
                        s = _a.sent();
                        u = new url.URLSearchParams(s);
                        r = {};
                        u.forEach((function (value, name) {
                            r[name] = value;
                        }));
                        return [2 /*return*/, r];
                }
            });
        });
    };
    AuthenticatedRequestExecutor.prototype.requestJson = function (method, uri, queries, headers, requestBody) {
        return __awaiter(this, void 0, void 0, function () {
            var s;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.request(method, uri, queries, headers, requestBody)];
                    case 1:
                        s = _a.sent();
                        return [2 /*return*/, JSON.parse(s)];
                }
            });
        });
    };
    return AuthenticatedRequestExecutor;
}());
exports.AuthenticatedRequestExecutor = AuthenticatedRequestExecutor;
//# sourceMappingURL=AuthenticatedRequestExecutor.js.map