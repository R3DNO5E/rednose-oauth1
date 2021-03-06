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
exports.OAuth1 = void 0;
var HttpsRequest_1 = require("./HttpsRequest");
var AuthenticatedRequestExecutor_1 = require("./AuthenticatedRequestExecutor");
var url = require("url");
var OAuth1 = /** @class */ (function () {
    function OAuth1(_a) {
        var consumerKey = _a.consumerKey, consumerSecret = _a.consumerSecret, token = _a.token, tokenSecret = _a.tokenSecret, callback = _a.callback;
        this.oauthConsumerKey = consumerKey;
        this.oauthConsumerSecret = consumerSecret;
        this.oauthToken = token;
        this.oauthTokenSecret = tokenSecret;
        this.oauthCallback = callback;
        this.makeRequester();
    }
    OAuth1.prototype.makeRequester = function () {
        this.requester = new AuthenticatedRequestExecutor_1.AuthenticatedRequestExecutor(this.oauthConsumerKey, this.oauthConsumerSecret, this.oauthToken, this.oauthTokenSecret);
    };
    OAuth1.prototype.get_tokens = function () {
        return [this.oauthToken, this.oauthTokenSecret];
    };
    OAuth1.prototype.fetch_authorization_url = function (temporary_credential_endpoint, authorization_endpoint) {
        return __awaiter(this, void 0, void 0, function () {
            var t, u;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.requester.requestUrlEncoded(HttpsRequest_1.HttpMethod.POST, temporary_credential_endpoint, {}, {}, { 'oauth_callback': this.oauthCallback })];
                    case 1:
                        t = _a.sent();
                        this.oauthToken = t['oauth_token'];
                        this.oauthTokenSecret = t['oauth_token_secret'];
                        this.makeRequester();
                        u = new url.URL(authorization_endpoint);
                        u.searchParams.set('oauth_token', this.oauthToken);
                        return [2 /*return*/, u.toString()];
                }
            });
        });
    };
    OAuth1.prototype.fetch_token_credential = function (request_token_endpoint, oauth_verifier) {
        return __awaiter(this, void 0, void 0, function () {
            var t;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.requester.requestUrlEncoded(HttpsRequest_1.HttpMethod.POST, request_token_endpoint, {}, {}, { 'oauth_verifier': oauth_verifier })];
                    case 1:
                        t = _a.sent();
                        this.oauthToken = t['oauth_token'];
                        this.oauthTokenSecret = t['oauth_token_secret'];
                        this.makeRequester();
                        return [2 /*return*/];
                }
            });
        });
    };
    OAuth1.prototype.fetch_resource = function (method, uri, params) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!(method == HttpsRequest_1.HttpMethod.GET)) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.requester.request(method, uri, params, {}, {})];
                    case 1: return [2 /*return*/, _a.sent()];
                    case 2:
                        if (!(method == HttpsRequest_1.HttpMethod.POST)) return [3 /*break*/, 4];
                        return [4 /*yield*/, this.requester.request(method, uri, {}, {}, params)];
                    case 3: return [2 /*return*/, _a.sent()];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    return OAuth1;
}());
exports.OAuth1 = OAuth1;
//# sourceMappingURL=OAuth1.js.map