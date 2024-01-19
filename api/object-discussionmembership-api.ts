/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import type { Configuration } from '../configuration';
import type { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';
import globalAxios from 'axios';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { DiscussionmembershipCreateObjectV1Request } from '../model';
// @ts-ignore
import { DiscussionmembershipCreateObjectV1Response } from '../model';
// @ts-ignore
import { DiscussionmembershipDeleteObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectDiscussionmembershipApi - axios parameter creator
 * @export
 */
export const ObjectDiscussionmembershipApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Discussionmembership
         * @param {DiscussionmembershipCreateObjectV1Request} discussionmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionmembershipCreateObjectV1: async (discussionmembershipCreateObjectV1Request: DiscussionmembershipCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'discussionmembershipCreateObjectV1Request' is not null or undefined
            assertParamExists('discussionmembershipCreateObjectV1', 'discussionmembershipCreateObjectV1Request', discussionmembershipCreateObjectV1Request)
            const localVarPath = `/1/object/discussionmembership`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'POST', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(discussionmembershipCreateObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
                        url: basePath + toPathString(localVarUrlObj) as string,
                        body: localVarRequestOptions.data || '' as string
                    }
                    const signatureHeaders = RequestSignature.getHeaders(headers)
                    localVarRequestOptions.headers = { ...localVarRequestOptions.headers, ...signatureHeaders }
                } 
            }

            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete an existing Discussionmembership
         * @param {number} pkiDiscussionmembershipID The unique ID of the Discussionmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionmembershipDeleteObjectV1: async (pkiDiscussionmembershipID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiDiscussionmembershipID' is not null or undefined
            assertParamExists('discussionmembershipDeleteObjectV1', 'pkiDiscussionmembershipID', pkiDiscussionmembershipID)
            const localVarPath = `/1/object/discussionmembership/{pkiDiscussionmembershipID}`
                .replace(`{${"pkiDiscussionmembershipID"}}`, encodeURIComponent(String(pkiDiscussionmembershipID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'DELETE', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'DELETE' as string,
                        url: basePath + toPathString(localVarUrlObj) as string,
                        body: localVarRequestOptions.data || '' as string
                    }
                    const signatureHeaders = RequestSignature.getHeaders(headers)
                    localVarRequestOptions.headers = { ...localVarRequestOptions.headers, ...signatureHeaders }
                } 
            }

            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * ObjectDiscussionmembershipApi - functional programming interface
 * @export
 */
export const ObjectDiscussionmembershipApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectDiscussionmembershipApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Discussionmembership
         * @param {DiscussionmembershipCreateObjectV1Request} discussionmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async discussionmembershipCreateObjectV1(discussionmembershipCreateObjectV1Request: DiscussionmembershipCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DiscussionmembershipCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.discussionmembershipCreateObjectV1(discussionmembershipCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Discussionmembership
         * @param {number} pkiDiscussionmembershipID The unique ID of the Discussionmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async discussionmembershipDeleteObjectV1(pkiDiscussionmembershipID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DiscussionmembershipDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.discussionmembershipDeleteObjectV1(pkiDiscussionmembershipID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectDiscussionmembershipApi - factory interface
 * @export
 */
export const ObjectDiscussionmembershipApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectDiscussionmembershipApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Discussionmembership
         * @param {DiscussionmembershipCreateObjectV1Request} discussionmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionmembershipCreateObjectV1(discussionmembershipCreateObjectV1Request: DiscussionmembershipCreateObjectV1Request, options?: any): AxiosPromise<DiscussionmembershipCreateObjectV1Response> {
            return localVarFp.discussionmembershipCreateObjectV1(discussionmembershipCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Discussionmembership
         * @param {number} pkiDiscussionmembershipID The unique ID of the Discussionmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionmembershipDeleteObjectV1(pkiDiscussionmembershipID: number, options?: any): AxiosPromise<DiscussionmembershipDeleteObjectV1Response> {
            return localVarFp.discussionmembershipDeleteObjectV1(pkiDiscussionmembershipID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectDiscussionmembershipApi - object-oriented interface
 * @export
 * @class ObjectDiscussionmembershipApi
 * @extends {BaseAPI}
 */
export class ObjectDiscussionmembershipApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Discussionmembership
     * @param {DiscussionmembershipCreateObjectV1Request} discussionmembershipCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectDiscussionmembershipApi
     */
    public discussionmembershipCreateObjectV1(discussionmembershipCreateObjectV1Request: DiscussionmembershipCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectDiscussionmembershipApiFp(this.configuration).discussionmembershipCreateObjectV1(discussionmembershipCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Discussionmembership
     * @param {number} pkiDiscussionmembershipID The unique ID of the Discussionmembership
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectDiscussionmembershipApi
     */
    public discussionmembershipDeleteObjectV1(pkiDiscussionmembershipID: number, options?: AxiosRequestConfig) {
        return ObjectDiscussionmembershipApiFp(this.configuration).discussionmembershipDeleteObjectV1(pkiDiscussionmembershipID, options).then((request) => request(this.axios, this.basePath));
    }
}

