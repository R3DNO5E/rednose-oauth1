import {HttpMethod} from "./HttpsRequest";
import {AuthenticatedRequestExecutor} from "./AuthenticatedRequestExecutor";
import * as url from 'url';

export class OAuth1 {
    private oauthCallback: string;
    private requester: AuthenticatedRequestExecutor;


    public constructor({consumerKey, consumerSecret, token, tokenSecret, callback}
                           : { consumerKey: string, consumerSecret: string, token?: string, tokenSecret?: string, callback?: string }) {
        this.requester = new AuthenticatedRequestExecutor(consumerKey, consumerSecret, token, tokenSecret);
    }

    public get_tokens(): [string, string] {
        return this.requester.getTokens();
    }

    public async fetch_authorization_url(temporary_credential_endpoint: string, authorization_endpoint: string): Promise<string> {
        const t = await this.requester.requestUrlEncoded(HttpMethod.POST, temporary_credential_endpoint, {}, {}, {'oauth_callback': this.oauthCallback});
        this.requester.setTokens(t['oauth_token'], t['oauth_token_secret']);
        const u = new url.URL(authorization_endpoint);
        u.searchParams.set('oauth_token', t['oauth_token']);
        return u.toString();
    }

    public async fetch_token_credential(request_token_endpoint: string, oauth_verifier: string): Promise<[string, string]> {
        const t = await this.requester.requestUrlEncoded(HttpMethod.POST, request_token_endpoint, {}, {}, {'oauth_verifier': oauth_verifier});
        this.requester.setTokens(t['oauth_token'], t['oauth_token_secret']);
        return this.requester.getTokens();
    }

    public async fetch_resource(method: HttpMethod, uri: string, params: { [field: string]: string }): Promise<string> {
        if (method == HttpMethod.GET) {
            return await this.requester.request(method, uri, params, {}, {});
        } else if (method == HttpMethod.POST) {
            return await this.requester.request(method, uri, {}, {}, params);
        }
    }
}
