import {HttpMethod, HttpsRequest} from "./HttpsRequest";
import * as crypto from 'crypto';
import * as buffer from 'buffer';
import * as url from 'url'
import {v4 as uuidv4} from 'uuid';

export class AuthenticatedRequestExecutor {
    private readonly oauthConsumerKey: string;
    private readonly oauthConsumerSecret: string;
    private oauthToken: string;
    private oauthTokenSecret: string;
    private readonly usedNonce: Set<string> = new Set<string>();
    private readonly realm: string;
    private nonceTimestamp = 0;

    private static encodePercent(data: string): string {
        const input = buffer.Buffer.from(data, 'utf-8');
        let output = "";
        for (let i = 0; i < input.length; i++) {
            const n = input[i];
            if ((0x30 <= n && n <= 0x39) || (0x41 <= n && n <= 0x5a) || (0x61 <= n && n <= 0x7a) || n == 0x2d || n == 0x2e || n == 0x5f || n == 0x7e) {
                output += Buffer.from([n]).toString('utf-8');
            } else {
                let s = n.toString(16).toUpperCase();
                if (s.length == 1) s = '0' + 's';
                output += '%' + s;
            }
        }
        return output;
    }

    private makeBaseAuthorizationHeader(): { [field: string]: string } {
        const r: { [field: string]: string } = {};
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
    }

    private static currentTimestamp(): number {
        return Math.floor(Date.now() / 1000);
    }

    private generateNonce(): string {
        const t = AuthenticatedRequestExecutor.currentTimestamp();
        if (t != this.nonceTimestamp) {
            this.nonceTimestamp = t;
            this.usedNonce.clear();
        }
        while (true) {
            const r = uuidv4();
            if (!this.usedNonce.has(r)) {
                this.usedNonce.add(r);
                return r;
            }
        }
    }

    private static collectParameters(authorizationHeader: { [field: string]: string }, queries: { [field: string]: string }, requestBody: { [field: string]: string }): { [field: string]: string } {
        const r: { [field: string]: string } = {};
        for (const e in queries) {
            r[e] = queries[e];
        }
        for (const e in requestBody) {
            r[e] = requestBody[e];
        }
        for (const e in authorizationHeader) {
            if (e != "realm" && e != "oauth_signature") {
                r[e] = authorizationHeader[e];
            }
        }
        return r;
    }

    private static sortParameters(params: { [field: string]: string }): [string, string][] {
        const pe: [string, string][] = [];
        for (const e in params) {
            pe.push([AuthenticatedRequestExecutor.encodePercent(e), AuthenticatedRequestExecutor.encodePercent(params[e])]);
        }
        pe.sort(((a, b) => {
            if (a[0] != b[0]) {
                return a[0] > b[0] ? 1 : -1;
            } else if (a[1] != b[1]) {
                return a[1] > b[1] ? 1 : -1;
            } else {
                return 0;
            }
        }));
        return pe;
    }

    private static makeNormalizedParameters(authorizationHeader: { [field: string]: string }, queries: { [field: string]: string }, requestBody: { [field: string]: string }): string {
        const p = AuthenticatedRequestExecutor.collectParameters(authorizationHeader, queries, requestBody);
        const pe = this.sortParameters(p);
        let r = "";
        for (const e in pe) {
            r += pe[e][0] + '=' + pe[e][1] + '&';
        }
        return r.substr(0, r.length - 1);
    }

    private static makeBaseStringUri(uri: string): string {
        const u = new url.URL(uri);
        let proto = u.protocol.toLowerCase();
        if (proto != "http:" && proto != "https:") {
            throw "Invalid URL: " + proto;
        }
        return proto + "//" + u.hostname.toLowerCase() + u.port + u.pathname;
    }

    private static makeSignatureBaseString(method: HttpMethod, uri: string, authorizationHeader: { [field: string]: string }, queries: { [field: string]: string }, requestBody: { [field: string]: string }): string {
        return method + '&' +
            AuthenticatedRequestExecutor.encodePercent(AuthenticatedRequestExecutor.makeBaseStringUri(uri)) + '&' +
            AuthenticatedRequestExecutor.encodePercent(AuthenticatedRequestExecutor.makeNormalizedParameters(authorizationHeader, queries, requestBody));
    }

    private static computeHmacSha1(value: string, key: string): Promise<string> {
        return new Promise<string>((resolve, reject) => {
            const hmac = crypto.createHmac('sha1', key);
            hmac.update(value);
            hmac.on('error', err => {
                reject(err);
            });
            resolve(hmac.digest('base64'));
        });
    }

    private makeSignatureKey(): string {
        return AuthenticatedRequestExecutor.encodePercent(this.oauthConsumerSecret) + '&' + AuthenticatedRequestExecutor.encodePercent(this.oauthTokenSecret);
    }

    private async makeSignature(method: HttpMethod, uri: string, authorizationHeader: { [field: string]: string }, queries: { [field: string]: string }, requestBody: { [field: string]: string }): Promise<string> {
        const bs = AuthenticatedRequestExecutor.makeSignatureBaseString(method, uri, authorizationHeader, queries, requestBody);
        const sk = this.makeSignatureKey();
        return await AuthenticatedRequestExecutor.computeHmacSha1(bs, sk);
    }

    private async makeAuthorizationHeader(method: HttpMethod, uri: string, queries: { [field: string]: string }, requestBody: { [field: string]: string }): Promise<string> {
        const t = this.makeBaseAuthorizationHeader();
        t['oauth_signature'] = await this.makeSignature(method, uri, t, queries, requestBody);
        const nt = AuthenticatedRequestExecutor.sortParameters(t);
        let r = "OAuth ";
        for (const e in nt) {
            r += nt[e][0] + "=\"" + nt[e][1] + "\", ";
        }
        return r.substr(0, r.length - 2);
    }

    public constructor(consumerKey: string, consumerSecret: string, token: string = '', tokenSecret: string = '', realm: string = '') {
        this.oauthConsumerKey = consumerKey;
        this.oauthConsumerSecret = consumerSecret;
        this.oauthToken = token;
        this.oauthTokenSecret = tokenSecret;
        this.realm = realm;
    }

    public setTokens(token: string, tokenSecret: string) {
        this.oauthToken = token;
        this.oauthTokenSecret = tokenSecret;
    }

    public getTokens(): [string, string] {
        return [this.oauthToken, this.oauthTokenSecret];
    }

    public async request(method: HttpMethod, uri: string, queries: { [field: string]: string }, headers: { [field: string]: string }, requestBody: { [field: string]: string }): Promise<string> {
        const ah = await this.makeAuthorizationHeader(method, uri, queries, requestBody);
        const t: { [field: string]: string } = {};
        for (const e in headers) {
            t[e] = headers[e];
        }
        t["Authorization"] = ah;
        const req = new HttpsRequest(uri, method, t, queries, requestBody);
        return await req.fetch();
    }

    public async requestUrlEncoded(method: HttpMethod, uri: string, queries: { [field: string]: string }, headers: { [field: string]: string }, requestBody: { [field: string]: string }): Promise<{ [field: string]: string }> {
        const s = await this.request(method, uri, queries, headers, requestBody);
        const u = new url.URLSearchParams(s);
        const r: { [field: string]: string } = {};
        u.forEach(((value, name) => {
            r[name] = value;
        }));
        return r;
    }
}
