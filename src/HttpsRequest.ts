import * as https from 'https'
import * as url from 'url'

export enum HttpMethod {
    'GET' = 'GET', 'POST' = 'POST'
}

export class HttpsRequest {
    private readonly method: HttpMethod = HttpMethod.GET;
    private readonly headers: { [field: string]: string };
    private readonly queries: { [field: string]: string };
    private readonly requestBody: { [field: string]: string };
    private readonly base_url: string;

    private append_queries_to_search_param(param: url.URLSearchParams): void {
        for (const field in this.queries) {
            param.append(field, this.queries[field]);
        }
    }

    private make_url(): url.URL {
        const u = new url.URL(this.base_url);
        this.append_queries_to_search_param(u.searchParams);
        return u;
    }

    private make_request_body(): string {
        const p = new url.URLSearchParams();
        for (const field in this.requestBody) {
            p.append(field, this.requestBody[field]);
        }
        return p.toString();
    }

    public constructor(url: string, method: HttpMethod = HttpMethod.GET, headers: { [field: string]: string } = {}, queries: { [field: string]: string } = {}, requestBody: { [field: string]: string } = {}) {
        this.base_url = url;
        this.method = method;
        this.headers = headers;
        this.queries = queries;
        this.requestBody = requestBody;
    }

    private set_header(field: string, value: string) {
        this.headers[field] = value;
    }

    public fetch(): Promise<string> {
        return new Promise<string>((resolve, reject) => {
            let response: string = '';
            if (Object.keys(this.requestBody).length > 0) {
                this.set_header("Content-Type", "application/x-www-form-urlencoded");
                this.set_header("Content-Length", this.make_request_body().length.toString());
            }
            const req = https.request(this.make_url(), {
                headers: this.headers,
                method: this.method
            }, res => {
                res.on('data', chunk => {
                    response += chunk
                });
                res.on('end', () => {
                    resolve(response);
                });
            });
            req.on('error', (err) => {
                reject(err);
            });
            req.write(this.make_request_body());
            req.end();
        });
    }
}