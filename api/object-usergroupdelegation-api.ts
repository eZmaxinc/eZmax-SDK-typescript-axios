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
import { UsergroupdelegationCreateObjectV1Request } from '../model';
// @ts-ignore
import { UsergroupdelegationCreateObjectV1Response } from '../model';
// @ts-ignore
import { UsergroupdelegationDeleteObjectV1Response } from '../model';
// @ts-ignore
import { UsergroupdelegationEditObjectV1Request } from '../model';
// @ts-ignore
import { UsergroupdelegationEditObjectV1Response } from '../model';
// @ts-ignore
import { UsergroupdelegationGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectUsergroupdelegationApi - axios parameter creator
 * @export
 */
export const ObjectUsergroupdelegationApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Usergroupdelegation
         * @param {UsergroupdelegationCreateObjectV1Request} usergroupdelegationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupdelegationCreateObjectV1: async (usergroupdelegationCreateObjectV1Request: UsergroupdelegationCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'usergroupdelegationCreateObjectV1Request' is not null or undefined
            assertParamExists('usergroupdelegationCreateObjectV1', 'usergroupdelegationCreateObjectV1Request', usergroupdelegationCreateObjectV1Request)
            const localVarPath = `/1/object/usergroupdelegation`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(usergroupdelegationCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupdelegationDeleteObjectV1: async (pkiUsergroupdelegationID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUsergroupdelegationID' is not null or undefined
            assertParamExists('usergroupdelegationDeleteObjectV1', 'pkiUsergroupdelegationID', pkiUsergroupdelegationID)
            const localVarPath = `/1/object/usergroupdelegation/{pkiUsergroupdelegationID}`
                .replace(`{${"pkiUsergroupdelegationID"}}`, encodeURIComponent(String(pkiUsergroupdelegationID)));
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
        /**
         * 
         * @summary Edit an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {UsergroupdelegationEditObjectV1Request} usergroupdelegationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupdelegationEditObjectV1: async (pkiUsergroupdelegationID: number, usergroupdelegationEditObjectV1Request: UsergroupdelegationEditObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUsergroupdelegationID' is not null or undefined
            assertParamExists('usergroupdelegationEditObjectV1', 'pkiUsergroupdelegationID', pkiUsergroupdelegationID)
            // verify required parameter 'usergroupdelegationEditObjectV1Request' is not null or undefined
            assertParamExists('usergroupdelegationEditObjectV1', 'usergroupdelegationEditObjectV1Request', usergroupdelegationEditObjectV1Request)
            const localVarPath = `/1/object/usergroupdelegation/{pkiUsergroupdelegationID}`
                .replace(`{${"pkiUsergroupdelegationID"}}`, encodeURIComponent(String(pkiUsergroupdelegationID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'PUT', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(usergroupdelegationEditObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'PUT' as string,
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
         * @summary Retrieve an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupdelegationGetObjectV2: async (pkiUsergroupdelegationID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUsergroupdelegationID' is not null or undefined
            assertParamExists('usergroupdelegationGetObjectV2', 'pkiUsergroupdelegationID', pkiUsergroupdelegationID)
            const localVarPath = `/2/object/usergroupdelegation/{pkiUsergroupdelegationID}`
                .replace(`{${"pkiUsergroupdelegationID"}}`, encodeURIComponent(String(pkiUsergroupdelegationID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
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
    }
};

/**
 * ObjectUsergroupdelegationApi - functional programming interface
 * @export
 */
export const ObjectUsergroupdelegationApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectUsergroupdelegationApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Usergroupdelegation
         * @param {UsergroupdelegationCreateObjectV1Request} usergroupdelegationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async usergroupdelegationCreateObjectV1(usergroupdelegationCreateObjectV1Request: UsergroupdelegationCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UsergroupdelegationCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.usergroupdelegationCreateObjectV1(usergroupdelegationCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async usergroupdelegationDeleteObjectV1(pkiUsergroupdelegationID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UsergroupdelegationDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.usergroupdelegationDeleteObjectV1(pkiUsergroupdelegationID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Edit an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {UsergroupdelegationEditObjectV1Request} usergroupdelegationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async usergroupdelegationEditObjectV1(pkiUsergroupdelegationID: number, usergroupdelegationEditObjectV1Request: UsergroupdelegationEditObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UsergroupdelegationEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.usergroupdelegationEditObjectV1(pkiUsergroupdelegationID, usergroupdelegationEditObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async usergroupdelegationGetObjectV2(pkiUsergroupdelegationID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UsergroupdelegationGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.usergroupdelegationGetObjectV2(pkiUsergroupdelegationID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectUsergroupdelegationApi - factory interface
 * @export
 */
export const ObjectUsergroupdelegationApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectUsergroupdelegationApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Usergroupdelegation
         * @param {UsergroupdelegationCreateObjectV1Request} usergroupdelegationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupdelegationCreateObjectV1(usergroupdelegationCreateObjectV1Request: UsergroupdelegationCreateObjectV1Request, options?: any): AxiosPromise<UsergroupdelegationCreateObjectV1Response> {
            return localVarFp.usergroupdelegationCreateObjectV1(usergroupdelegationCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupdelegationDeleteObjectV1(pkiUsergroupdelegationID: number, options?: any): AxiosPromise<UsergroupdelegationDeleteObjectV1Response> {
            return localVarFp.usergroupdelegationDeleteObjectV1(pkiUsergroupdelegationID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {UsergroupdelegationEditObjectV1Request} usergroupdelegationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupdelegationEditObjectV1(pkiUsergroupdelegationID: number, usergroupdelegationEditObjectV1Request: UsergroupdelegationEditObjectV1Request, options?: any): AxiosPromise<UsergroupdelegationEditObjectV1Response> {
            return localVarFp.usergroupdelegationEditObjectV1(pkiUsergroupdelegationID, usergroupdelegationEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Usergroupdelegation
         * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupdelegationGetObjectV2(pkiUsergroupdelegationID: number, options?: any): AxiosPromise<UsergroupdelegationGetObjectV2Response> {
            return localVarFp.usergroupdelegationGetObjectV2(pkiUsergroupdelegationID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectUsergroupdelegationApi - object-oriented interface
 * @export
 * @class ObjectUsergroupdelegationApi
 * @extends {BaseAPI}
 */
export class ObjectUsergroupdelegationApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Usergroupdelegation
     * @param {UsergroupdelegationCreateObjectV1Request} usergroupdelegationCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUsergroupdelegationApi
     */
    public usergroupdelegationCreateObjectV1(usergroupdelegationCreateObjectV1Request: UsergroupdelegationCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectUsergroupdelegationApiFp(this.configuration).usergroupdelegationCreateObjectV1(usergroupdelegationCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Usergroupdelegation
     * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUsergroupdelegationApi
     */
    public usergroupdelegationDeleteObjectV1(pkiUsergroupdelegationID: number, options?: AxiosRequestConfig) {
        return ObjectUsergroupdelegationApiFp(this.configuration).usergroupdelegationDeleteObjectV1(pkiUsergroupdelegationID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Usergroupdelegation
     * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
     * @param {UsergroupdelegationEditObjectV1Request} usergroupdelegationEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUsergroupdelegationApi
     */
    public usergroupdelegationEditObjectV1(pkiUsergroupdelegationID: number, usergroupdelegationEditObjectV1Request: UsergroupdelegationEditObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectUsergroupdelegationApiFp(this.configuration).usergroupdelegationEditObjectV1(pkiUsergroupdelegationID, usergroupdelegationEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Usergroupdelegation
     * @param {number} pkiUsergroupdelegationID The unique ID of the Usergroupdelegation
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUsergroupdelegationApi
     */
    public usergroupdelegationGetObjectV2(pkiUsergroupdelegationID: number, options?: AxiosRequestConfig) {
        return ObjectUsergroupdelegationApiFp(this.configuration).usergroupdelegationGetObjectV2(pkiUsergroupdelegationID, options).then((request) => request(this.axios, this.basePath));
    }
}
