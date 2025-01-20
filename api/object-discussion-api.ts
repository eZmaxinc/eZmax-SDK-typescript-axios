/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import type { Configuration } from '../configuration';
import type { AxiosPromise, AxiosInstance, RawAxiosRequestConfig } from 'axios';
import globalAxios from 'axios';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, type RequestArgs, BaseAPI, RequiredError, operationServerMap } from '../base';
// @ts-ignore
import type { CommonResponseError } from '../model';
// @ts-ignore
import type { DiscussionCreateObjectV1Request } from '../model';
// @ts-ignore
import type { DiscussionCreateObjectV1Response } from '../model';
// @ts-ignore
import type { DiscussionDeleteObjectV1Response } from '../model';
// @ts-ignore
import type { DiscussionGetObjectV2Response } from '../model';
// @ts-ignore
import type { DiscussionPatchObjectV1Request } from '../model';
// @ts-ignore
import type { DiscussionPatchObjectV1Response } from '../model';
// @ts-ignore
import type { DiscussionUpdateDiscussionreadstatusV1Request } from '../model';
// @ts-ignore
import type { DiscussionUpdateDiscussionreadstatusV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectDiscussionApi - axios parameter creator
 * @export
 */
export const ObjectDiscussionApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Discussion
         * @param {DiscussionCreateObjectV1Request} discussionCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionCreateObjectV1: async (discussionCreateObjectV1Request: DiscussionCreateObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'discussionCreateObjectV1Request' is not null or undefined
            assertParamExists('discussionCreateObjectV1', 'discussionCreateObjectV1Request', discussionCreateObjectV1Request)
            const localVarPath = `/1/object/discussion`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
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
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(discussionCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionDeleteObjectV1: async (pkiDiscussionID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiDiscussionID' is not null or undefined
            assertParamExists('discussionDeleteObjectV1', 'pkiDiscussionID', pkiDiscussionID)
            const localVarPath = `/1/object/discussion/{pkiDiscussionID}`
                .replace(`{${"pkiDiscussionID"}}`, encodeURIComponent(String(pkiDiscussionID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
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
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
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
        /**
         * 
         * @summary Retrieve an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionGetObjectV2: async (pkiDiscussionID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiDiscussionID' is not null or undefined
            assertParamExists('discussionGetObjectV2', 'pkiDiscussionID', pkiDiscussionID)
            const localVarPath = `/2/object/discussion/{pkiDiscussionID}`
                .replace(`{${"pkiDiscussionID"}}`, encodeURIComponent(String(pkiDiscussionID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'GET' as string,
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
         * @summary Patch an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {DiscussionPatchObjectV1Request} discussionPatchObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionPatchObjectV1: async (pkiDiscussionID: number, discussionPatchObjectV1Request: DiscussionPatchObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiDiscussionID' is not null or undefined
            assertParamExists('discussionPatchObjectV1', 'pkiDiscussionID', pkiDiscussionID)
            // verify required parameter 'discussionPatchObjectV1Request' is not null or undefined
            assertParamExists('discussionPatchObjectV1', 'discussionPatchObjectV1Request', discussionPatchObjectV1Request)
            const localVarPath = `/1/object/discussion/{pkiDiscussionID}`
                .replace(`{${"pkiDiscussionID"}}`, encodeURIComponent(String(pkiDiscussionID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'PATCH', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(discussionPatchObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'PATCH' as string,
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
         * @summary Update the read status of the discussion
         * @param {number} pkiDiscussionID 
         * @param {DiscussionUpdateDiscussionreadstatusV1Request} discussionUpdateDiscussionreadstatusV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionUpdateDiscussionreadstatusV1: async (pkiDiscussionID: number, discussionUpdateDiscussionreadstatusV1Request: DiscussionUpdateDiscussionreadstatusV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiDiscussionID' is not null or undefined
            assertParamExists('discussionUpdateDiscussionreadstatusV1', 'pkiDiscussionID', pkiDiscussionID)
            // verify required parameter 'discussionUpdateDiscussionreadstatusV1Request' is not null or undefined
            assertParamExists('discussionUpdateDiscussionreadstatusV1', 'discussionUpdateDiscussionreadstatusV1Request', discussionUpdateDiscussionreadstatusV1Request)
            const localVarPath = `/1/object/discussion/{pkiDiscussionID}/updateDiscussionreadstatus`
                .replace(`{${"pkiDiscussionID"}}`, encodeURIComponent(String(pkiDiscussionID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
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
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(discussionUpdateDiscussionreadstatusV1Request, localVarRequestOptions, configuration)

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
    }
};

/**
 * ObjectDiscussionApi - functional programming interface
 * @export
 */
export const ObjectDiscussionApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectDiscussionApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Discussion
         * @param {DiscussionCreateObjectV1Request} discussionCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async discussionCreateObjectV1(discussionCreateObjectV1Request: DiscussionCreateObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DiscussionCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.discussionCreateObjectV1(discussionCreateObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectDiscussionApi.discussionCreateObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Delete an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async discussionDeleteObjectV1(pkiDiscussionID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DiscussionDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.discussionDeleteObjectV1(pkiDiscussionID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectDiscussionApi.discussionDeleteObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async discussionGetObjectV2(pkiDiscussionID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DiscussionGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.discussionGetObjectV2(pkiDiscussionID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectDiscussionApi.discussionGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Patch an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {DiscussionPatchObjectV1Request} discussionPatchObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async discussionPatchObjectV1(pkiDiscussionID: number, discussionPatchObjectV1Request: DiscussionPatchObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DiscussionPatchObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.discussionPatchObjectV1(pkiDiscussionID, discussionPatchObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectDiscussionApi.discussionPatchObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Update the read status of the discussion
         * @param {number} pkiDiscussionID 
         * @param {DiscussionUpdateDiscussionreadstatusV1Request} discussionUpdateDiscussionreadstatusV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async discussionUpdateDiscussionreadstatusV1(pkiDiscussionID: number, discussionUpdateDiscussionreadstatusV1Request: DiscussionUpdateDiscussionreadstatusV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DiscussionUpdateDiscussionreadstatusV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.discussionUpdateDiscussionreadstatusV1(pkiDiscussionID, discussionUpdateDiscussionreadstatusV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectDiscussionApi.discussionUpdateDiscussionreadstatusV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectDiscussionApi - factory interface
 * @export
 */
export const ObjectDiscussionApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectDiscussionApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Discussion
         * @param {DiscussionCreateObjectV1Request} discussionCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionCreateObjectV1(discussionCreateObjectV1Request: DiscussionCreateObjectV1Request, options?: RawAxiosRequestConfig): AxiosPromise<DiscussionCreateObjectV1Response> {
            return localVarFp.discussionCreateObjectV1(discussionCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionDeleteObjectV1(pkiDiscussionID: number, options?: RawAxiosRequestConfig): AxiosPromise<DiscussionDeleteObjectV1Response> {
            return localVarFp.discussionDeleteObjectV1(pkiDiscussionID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionGetObjectV2(pkiDiscussionID: number, options?: RawAxiosRequestConfig): AxiosPromise<DiscussionGetObjectV2Response> {
            return localVarFp.discussionGetObjectV2(pkiDiscussionID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Patch an existing Discussion
         * @param {number} pkiDiscussionID The unique ID of the Discussion
         * @param {DiscussionPatchObjectV1Request} discussionPatchObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionPatchObjectV1(pkiDiscussionID: number, discussionPatchObjectV1Request: DiscussionPatchObjectV1Request, options?: RawAxiosRequestConfig): AxiosPromise<DiscussionPatchObjectV1Response> {
            return localVarFp.discussionPatchObjectV1(pkiDiscussionID, discussionPatchObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update the read status of the discussion
         * @param {number} pkiDiscussionID 
         * @param {DiscussionUpdateDiscussionreadstatusV1Request} discussionUpdateDiscussionreadstatusV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        discussionUpdateDiscussionreadstatusV1(pkiDiscussionID: number, discussionUpdateDiscussionreadstatusV1Request: DiscussionUpdateDiscussionreadstatusV1Request, options?: RawAxiosRequestConfig): AxiosPromise<DiscussionUpdateDiscussionreadstatusV1Response> {
            return localVarFp.discussionUpdateDiscussionreadstatusV1(pkiDiscussionID, discussionUpdateDiscussionreadstatusV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectDiscussionApi - object-oriented interface
 * @export
 * @class ObjectDiscussionApi
 * @extends {BaseAPI}
 */
export class ObjectDiscussionApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Discussion
     * @param {DiscussionCreateObjectV1Request} discussionCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectDiscussionApi
     */
    public discussionCreateObjectV1(discussionCreateObjectV1Request: DiscussionCreateObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectDiscussionApiFp(this.configuration).discussionCreateObjectV1(discussionCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Discussion
     * @param {number} pkiDiscussionID The unique ID of the Discussion
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectDiscussionApi
     */
    public discussionDeleteObjectV1(pkiDiscussionID: number, options?: RawAxiosRequestConfig) {
        return ObjectDiscussionApiFp(this.configuration).discussionDeleteObjectV1(pkiDiscussionID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Discussion
     * @param {number} pkiDiscussionID The unique ID of the Discussion
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectDiscussionApi
     */
    public discussionGetObjectV2(pkiDiscussionID: number, options?: RawAxiosRequestConfig) {
        return ObjectDiscussionApiFp(this.configuration).discussionGetObjectV2(pkiDiscussionID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Patch an existing Discussion
     * @param {number} pkiDiscussionID The unique ID of the Discussion
     * @param {DiscussionPatchObjectV1Request} discussionPatchObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectDiscussionApi
     */
    public discussionPatchObjectV1(pkiDiscussionID: number, discussionPatchObjectV1Request: DiscussionPatchObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectDiscussionApiFp(this.configuration).discussionPatchObjectV1(pkiDiscussionID, discussionPatchObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update the read status of the discussion
     * @param {number} pkiDiscussionID 
     * @param {DiscussionUpdateDiscussionreadstatusV1Request} discussionUpdateDiscussionreadstatusV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectDiscussionApi
     */
    public discussionUpdateDiscussionreadstatusV1(pkiDiscussionID: number, discussionUpdateDiscussionreadstatusV1Request: DiscussionUpdateDiscussionreadstatusV1Request, options?: RawAxiosRequestConfig) {
        return ObjectDiscussionApiFp(this.configuration).discussionUpdateDiscussionreadstatusV1(pkiDiscussionID, discussionUpdateDiscussionreadstatusV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}

