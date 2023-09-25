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
import { UsergroupmembershipCreateObjectV1Request } from '../model';
// @ts-ignore
import { UsergroupmembershipCreateObjectV1Response } from '../model';
// @ts-ignore
import { UsergroupmembershipDeleteObjectV1Response } from '../model';
// @ts-ignore
import { UsergroupmembershipEditObjectV1Request } from '../model';
// @ts-ignore
import { UsergroupmembershipEditObjectV1Response } from '../model';
// @ts-ignore
import { UsergroupmembershipGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectUsergroupmembershipApi - axios parameter creator
 * @export
 */
export const ObjectUsergroupmembershipApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Usergroupmembership
         * @param {UsergroupmembershipCreateObjectV1Request} usergroupmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupmembershipCreateObjectV1: async (usergroupmembershipCreateObjectV1Request: UsergroupmembershipCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'usergroupmembershipCreateObjectV1Request' is not null or undefined
            assertParamExists('usergroupmembershipCreateObjectV1', 'usergroupmembershipCreateObjectV1Request', usergroupmembershipCreateObjectV1Request)
            const localVarPath = `/1/object/usergroupmembership`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(usergroupmembershipCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupmembershipDeleteObjectV1: async (pkiUsergroupmembershipID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUsergroupmembershipID' is not null or undefined
            assertParamExists('usergroupmembershipDeleteObjectV1', 'pkiUsergroupmembershipID', pkiUsergroupmembershipID)
            const localVarPath = `/1/object/usergroupmembership/{pkiUsergroupmembershipID}`
                .replace(`{${"pkiUsergroupmembershipID"}}`, encodeURIComponent(String(pkiUsergroupmembershipID)));
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
         * @summary Edit an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {UsergroupmembershipEditObjectV1Request} usergroupmembershipEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupmembershipEditObjectV1: async (pkiUsergroupmembershipID: number, usergroupmembershipEditObjectV1Request: UsergroupmembershipEditObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUsergroupmembershipID' is not null or undefined
            assertParamExists('usergroupmembershipEditObjectV1', 'pkiUsergroupmembershipID', pkiUsergroupmembershipID)
            // verify required parameter 'usergroupmembershipEditObjectV1Request' is not null or undefined
            assertParamExists('usergroupmembershipEditObjectV1', 'usergroupmembershipEditObjectV1Request', usergroupmembershipEditObjectV1Request)
            const localVarPath = `/1/object/usergroupmembership/{pkiUsergroupmembershipID}`
                .replace(`{${"pkiUsergroupmembershipID"}}`, encodeURIComponent(String(pkiUsergroupmembershipID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(usergroupmembershipEditObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Retrieve an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupmembershipGetObjectV2: async (pkiUsergroupmembershipID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUsergroupmembershipID' is not null or undefined
            assertParamExists('usergroupmembershipGetObjectV2', 'pkiUsergroupmembershipID', pkiUsergroupmembershipID)
            const localVarPath = `/2/object/usergroupmembership/{pkiUsergroupmembershipID}`
                .replace(`{${"pkiUsergroupmembershipID"}}`, encodeURIComponent(String(pkiUsergroupmembershipID)));
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
 * ObjectUsergroupmembershipApi - functional programming interface
 * @export
 */
export const ObjectUsergroupmembershipApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectUsergroupmembershipApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Usergroupmembership
         * @param {UsergroupmembershipCreateObjectV1Request} usergroupmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async usergroupmembershipCreateObjectV1(usergroupmembershipCreateObjectV1Request: UsergroupmembershipCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UsergroupmembershipCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.usergroupmembershipCreateObjectV1(usergroupmembershipCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async usergroupmembershipDeleteObjectV1(pkiUsergroupmembershipID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UsergroupmembershipDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.usergroupmembershipDeleteObjectV1(pkiUsergroupmembershipID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Edit an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {UsergroupmembershipEditObjectV1Request} usergroupmembershipEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async usergroupmembershipEditObjectV1(pkiUsergroupmembershipID: number, usergroupmembershipEditObjectV1Request: UsergroupmembershipEditObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UsergroupmembershipEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.usergroupmembershipEditObjectV1(pkiUsergroupmembershipID, usergroupmembershipEditObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async usergroupmembershipGetObjectV2(pkiUsergroupmembershipID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UsergroupmembershipGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.usergroupmembershipGetObjectV2(pkiUsergroupmembershipID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectUsergroupmembershipApi - factory interface
 * @export
 */
export const ObjectUsergroupmembershipApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectUsergroupmembershipApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Usergroupmembership
         * @param {UsergroupmembershipCreateObjectV1Request} usergroupmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupmembershipCreateObjectV1(usergroupmembershipCreateObjectV1Request: UsergroupmembershipCreateObjectV1Request, options?: any): AxiosPromise<UsergroupmembershipCreateObjectV1Response> {
            return localVarFp.usergroupmembershipCreateObjectV1(usergroupmembershipCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupmembershipDeleteObjectV1(pkiUsergroupmembershipID: number, options?: any): AxiosPromise<UsergroupmembershipDeleteObjectV1Response> {
            return localVarFp.usergroupmembershipDeleteObjectV1(pkiUsergroupmembershipID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {UsergroupmembershipEditObjectV1Request} usergroupmembershipEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupmembershipEditObjectV1(pkiUsergroupmembershipID: number, usergroupmembershipEditObjectV1Request: UsergroupmembershipEditObjectV1Request, options?: any): AxiosPromise<UsergroupmembershipEditObjectV1Response> {
            return localVarFp.usergroupmembershipEditObjectV1(pkiUsergroupmembershipID, usergroupmembershipEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Usergroupmembership
         * @param {number} pkiUsergroupmembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        usergroupmembershipGetObjectV2(pkiUsergroupmembershipID: number, options?: any): AxiosPromise<UsergroupmembershipGetObjectV2Response> {
            return localVarFp.usergroupmembershipGetObjectV2(pkiUsergroupmembershipID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectUsergroupmembershipApi - object-oriented interface
 * @export
 * @class ObjectUsergroupmembershipApi
 * @extends {BaseAPI}
 */
export class ObjectUsergroupmembershipApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Usergroupmembership
     * @param {UsergroupmembershipCreateObjectV1Request} usergroupmembershipCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUsergroupmembershipApi
     */
    public usergroupmembershipCreateObjectV1(usergroupmembershipCreateObjectV1Request: UsergroupmembershipCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectUsergroupmembershipApiFp(this.configuration).usergroupmembershipCreateObjectV1(usergroupmembershipCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Usergroupmembership
     * @param {number} pkiUsergroupmembershipID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUsergroupmembershipApi
     */
    public usergroupmembershipDeleteObjectV1(pkiUsergroupmembershipID: number, options?: AxiosRequestConfig) {
        return ObjectUsergroupmembershipApiFp(this.configuration).usergroupmembershipDeleteObjectV1(pkiUsergroupmembershipID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Usergroupmembership
     * @param {number} pkiUsergroupmembershipID 
     * @param {UsergroupmembershipEditObjectV1Request} usergroupmembershipEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUsergroupmembershipApi
     */
    public usergroupmembershipEditObjectV1(pkiUsergroupmembershipID: number, usergroupmembershipEditObjectV1Request: UsergroupmembershipEditObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectUsergroupmembershipApiFp(this.configuration).usergroupmembershipEditObjectV1(pkiUsergroupmembershipID, usergroupmembershipEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Usergroupmembership
     * @param {number} pkiUsergroupmembershipID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUsergroupmembershipApi
     */
    public usergroupmembershipGetObjectV2(pkiUsergroupmembershipID: number, options?: AxiosRequestConfig) {
        return ObjectUsergroupmembershipApiFp(this.configuration).usergroupmembershipGetObjectV2(pkiUsergroupmembershipID, options).then((request) => request(this.axios, this.basePath));
    }
}

