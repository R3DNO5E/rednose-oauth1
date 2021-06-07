"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HttpsRequest = exports.HttpMethod = void 0;
var https = require("https");
var url = require("url");
var HttpMethod;
(function (HttpMethod) {
    HttpMethod["GET"] = "GET";
    HttpMethod["POST"] = "POST";
})(HttpMethod = exports.HttpMethod || (exports.HttpMethod = {}));
var HttpsRequest = /** @class */ (function () {
    function HttpsRequest(url, method, headers, queries, requestBody) {
        if (method === void 0) { method = HttpMethod.GET; }
        if (headers === void 0) { headers = {}; }
        if (queries === void 0) { queries = {}; }
        if (requestBody === void 0) { requestBody = {}; }
        this.method = HttpMethod.GET;
        this.base_url = url;
        this.method = method;
        this.headers = headers;
        this.queries = queries;
        this.requestBody = requestBody;
    }
    HttpsRequest.prototype.append_queries_to_search_param = function (param) {
        for (var field in this.queries) {
            param.append(field, this.queries[field]);
        }
    };
    HttpsRequest.prototype.make_url = function () {
        var u = new url.URL(this.base_url);
        this.append_queries_to_search_param(u.searchParams);
        return u;
    };
    HttpsRequest.prototype.make_request_body = function () {
        var p = new url.URLSearchParams();
        for (var field in this.requestBody) {
            p.append(field, this.requestBody[field]);
        }
        return p.toString();
    };
    HttpsRequest.prototype.set_header = function (field, value) {
        this.headers[field] = value;
    };
    HttpsRequest.prototype.fetch = function () {
        var _this = this;
        return new Promise(function (resolve, reject) {
            var response = '';
            if (Object.keys(_this.requestBody).length > 0) {
                _this.set_header("Content-Type", "application/x-www-form-urlencoded");
                _this.set_header("Content-Length", _this.make_request_body().length.toString());
            }
            var req = https.request(_this.make_url(), {
                headers: _this.headers,
                method: _this.method
            }, function (res) {
                res.on('data', function (chunk) {
                    response += chunk;
                });
                res.on('end', function () {
                    resolve(response);
                });
            });
            req.on('error', function (err) {
                reject(err);
            });
            req.write(_this.make_request_body());
            req.end();
        });
    };
    return HttpsRequest;
}());
exports.HttpsRequest = HttpsRequest;
//# sourceMappingURL=HttpsRequest.js.map