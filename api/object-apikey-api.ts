/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
import { ApikeyCreateObjectV2Request } from '../model';
// @ts-ignore
import { ApikeyCreateObjectV2Response } from '../model';
// @ts-ignore
import { ApikeyEditObjectV1Request } from '../model';
// @ts-ignore
import { ApikeyEditObjectV1Response } from '../model';
// @ts-ignore
import { ApikeyEditPermissionsV1Request } from '../model';
// @ts-ignore
import { ApikeyEditPermissionsV1Response } from '../model';
// @ts-ignore
import { ApikeyGetObjectV2Response } from '../model';
// @ts-ignore
import { ApikeyGetPermissionsV1Response } from '../model';
// @ts-ignore
import { ApikeyGetSubnetsV1Response } from '../model';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectApikeyApi - axios parameter creator
 * @export
 */
export const ObjectApikeyApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Apikey
         * @param {ApikeyCreateObjectV2Request} apikeyCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV2: async (apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'apikeyCreateObjectV2Request' is not null or undefined
            assertParamExists('apikeyCreateObjectV2', 'apikeyCreateObjectV2Request', apikeyCreateObjectV2Request)
            const localVarPath = `/2/object/apikey`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(apikeyCreateObjectV2Request, localVarRequestOptions, configuration)

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
         * @summary Edit an existing Apikey
         * @param {number} pkiApikeyID The unique ID of the Apikey
         * @param {ApikeyEditObjectV1Request} apikeyEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyEditObjectV1: async (pkiApikeyID: number, apikeyEditObjectV1Request: ApikeyEditObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiApikeyID' is not null or undefined
            assertParamExists('apikeyEditObjectV1', 'pkiApikeyID', pkiApikeyID)
            // verify required parameter 'apikeyEditObjectV1Request' is not null or undefined
            assertParamExists('apikeyEditObjectV1', 'apikeyEditObjectV1Request', apikeyEditObjectV1Request)
            const localVarPath = `/1/object/apikey/{pkiApikeyID}`
                .replace(`{${"pkiApikeyID"}}`, encodeURIComponent(String(pkiApikeyID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(apikeyEditObjectV1Request, localVarRequestOptions, configuration)

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
         * Using this endpoint, you can edit multiple Permissions at the same time.
         * @summary Edit multiple Permissions
         * @param {number} pkiApikeyID 
         * @param {ApikeyEditPermissionsV1Request} apikeyEditPermissionsV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyEditPermissionsV1: async (pkiApikeyID: number, apikeyEditPermissionsV1Request: ApikeyEditPermissionsV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiApikeyID' is not null or undefined
            assertParamExists('apikeyEditPermissionsV1', 'pkiApikeyID', pkiApikeyID)
            // verify required parameter 'apikeyEditPermissionsV1Request' is not null or undefined
            assertParamExists('apikeyEditPermissionsV1', 'apikeyEditPermissionsV1Request', apikeyEditPermissionsV1Request)
            const localVarPath = `/1/object/apikey/{pkiApikeyID}/editPermissions`
                .replace(`{${"pkiApikeyID"}}`, encodeURIComponent(String(pkiApikeyID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(apikeyEditPermissionsV1Request, localVarRequestOptions, configuration)

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
         * @summary Retrieve an existing Apikey
         * @param {number} pkiApikeyID The unique ID of the Apikey
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyGetObjectV2: async (pkiApikeyID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiApikeyID' is not null or undefined
            assertParamExists('apikeyGetObjectV2', 'pkiApikeyID', pkiApikeyID)
            const localVarPath = `/2/object/apikey/{pkiApikeyID}`
                .replace(`{${"pkiApikeyID"}}`, encodeURIComponent(String(pkiApikeyID)));
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
        /**
         * 
         * @summary Retrieve an existing Apikey\'s Permissions
         * @param {number} pkiApikeyID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyGetPermissionsV1: async (pkiApikeyID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiApikeyID' is not null or undefined
            assertParamExists('apikeyGetPermissionsV1', 'pkiApikeyID', pkiApikeyID)
            const localVarPath = `/1/object/apikey/{pkiApikeyID}/getPermissions`
                .replace(`{${"pkiApikeyID"}}`, encodeURIComponent(String(pkiApikeyID)));
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
        /**
         * 
         * @summary Retrieve an existing Apikey\'s subnets
         * @param {number} pkiApikeyID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyGetSubnetsV1: async (pkiApikeyID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiApikeyID' is not null or undefined
            assertParamExists('apikeyGetSubnetsV1', 'pkiApikeyID', pkiApikeyID)
            const localVarPath = `/1/object/apikey/{pkiApikeyID}/getSubnets`
                .replace(`{${"pkiApikeyID"}}`, encodeURIComponent(String(pkiApikeyID)));
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
 * ObjectApikeyApi - functional programming interface
 * @export
 */
export const ObjectApikeyApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectApikeyApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Apikey
         * @param {ApikeyCreateObjectV2Request} apikeyCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async apikeyCreateObjectV2(apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyCreateObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.apikeyCreateObjectV2(apikeyCreateObjectV2Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Edit an existing Apikey
         * @param {number} pkiApikeyID The unique ID of the Apikey
         * @param {ApikeyEditObjectV1Request} apikeyEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async apikeyEditObjectV1(pkiApikeyID: number, apikeyEditObjectV1Request: ApikeyEditObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.apikeyEditObjectV1(pkiApikeyID, apikeyEditObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * Using this endpoint, you can edit multiple Permissions at the same time.
         * @summary Edit multiple Permissions
         * @param {number} pkiApikeyID 
         * @param {ApikeyEditPermissionsV1Request} apikeyEditPermissionsV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async apikeyEditPermissionsV1(pkiApikeyID: number, apikeyEditPermissionsV1Request: ApikeyEditPermissionsV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyEditPermissionsV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.apikeyEditPermissionsV1(pkiApikeyID, apikeyEditPermissionsV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Apikey
         * @param {number} pkiApikeyID The unique ID of the Apikey
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async apikeyGetObjectV2(pkiApikeyID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.apikeyGetObjectV2(pkiApikeyID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Apikey\'s Permissions
         * @param {number} pkiApikeyID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async apikeyGetPermissionsV1(pkiApikeyID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyGetPermissionsV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.apikeyGetPermissionsV1(pkiApikeyID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Apikey\'s subnets
         * @param {number} pkiApikeyID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async apikeyGetSubnetsV1(pkiApikeyID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyGetSubnetsV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.apikeyGetSubnetsV1(pkiApikeyID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectApikeyApi - factory interface
 * @export
 */
export const ObjectApikeyApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectApikeyApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Apikey
         * @param {ApikeyCreateObjectV2Request} apikeyCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV2(apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request, options?: any): AxiosPromise<ApikeyCreateObjectV2Response> {
            return localVarFp.apikeyCreateObjectV2(apikeyCreateObjectV2Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Apikey
         * @param {number} pkiApikeyID The unique ID of the Apikey
         * @param {ApikeyEditObjectV1Request} apikeyEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyEditObjectV1(pkiApikeyID: number, apikeyEditObjectV1Request: ApikeyEditObjectV1Request, options?: any): AxiosPromise<ApikeyEditObjectV1Response> {
            return localVarFp.apikeyEditObjectV1(pkiApikeyID, apikeyEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * Using this endpoint, you can edit multiple Permissions at the same time.
         * @summary Edit multiple Permissions
         * @param {number} pkiApikeyID 
         * @param {ApikeyEditPermissionsV1Request} apikeyEditPermissionsV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyEditPermissionsV1(pkiApikeyID: number, apikeyEditPermissionsV1Request: ApikeyEditPermissionsV1Request, options?: any): AxiosPromise<ApikeyEditPermissionsV1Response> {
            return localVarFp.apikeyEditPermissionsV1(pkiApikeyID, apikeyEditPermissionsV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Apikey
         * @param {number} pkiApikeyID The unique ID of the Apikey
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyGetObjectV2(pkiApikeyID: number, options?: any): AxiosPromise<ApikeyGetObjectV2Response> {
            return localVarFp.apikeyGetObjectV2(pkiApikeyID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Apikey\'s Permissions
         * @param {number} pkiApikeyID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyGetPermissionsV1(pkiApikeyID: number, options?: any): AxiosPromise<ApikeyGetPermissionsV1Response> {
            return localVarFp.apikeyGetPermissionsV1(pkiApikeyID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Apikey\'s subnets
         * @param {number} pkiApikeyID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyGetSubnetsV1(pkiApikeyID: number, options?: any): AxiosPromise<ApikeyGetSubnetsV1Response> {
            return localVarFp.apikeyGetSubnetsV1(pkiApikeyID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectApikeyApi - object-oriented interface
 * @export
 * @class ObjectApikeyApi
 * @extends {BaseAPI}
 */
export class ObjectApikeyApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Apikey
     * @param {ApikeyCreateObjectV2Request} apikeyCreateObjectV2Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyCreateObjectV2(apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request, options?: AxiosRequestConfig) {
        return ObjectApikeyApiFp(this.configuration).apikeyCreateObjectV2(apikeyCreateObjectV2Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Apikey
     * @param {number} pkiApikeyID The unique ID of the Apikey
     * @param {ApikeyEditObjectV1Request} apikeyEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyEditObjectV1(pkiApikeyID: number, apikeyEditObjectV1Request: ApikeyEditObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectApikeyApiFp(this.configuration).apikeyEditObjectV1(pkiApikeyID, apikeyEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Using this endpoint, you can edit multiple Permissions at the same time.
     * @summary Edit multiple Permissions
     * @param {number} pkiApikeyID 
     * @param {ApikeyEditPermissionsV1Request} apikeyEditPermissionsV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyEditPermissionsV1(pkiApikeyID: number, apikeyEditPermissionsV1Request: ApikeyEditPermissionsV1Request, options?: AxiosRequestConfig) {
        return ObjectApikeyApiFp(this.configuration).apikeyEditPermissionsV1(pkiApikeyID, apikeyEditPermissionsV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Apikey
     * @param {number} pkiApikeyID The unique ID of the Apikey
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyGetObjectV2(pkiApikeyID: number, options?: AxiosRequestConfig) {
        return ObjectApikeyApiFp(this.configuration).apikeyGetObjectV2(pkiApikeyID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Apikey\'s Permissions
     * @param {number} pkiApikeyID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyGetPermissionsV1(pkiApikeyID: number, options?: AxiosRequestConfig) {
        return ObjectApikeyApiFp(this.configuration).apikeyGetPermissionsV1(pkiApikeyID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Apikey\'s subnets
     * @param {number} pkiApikeyID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyGetSubnetsV1(pkiApikeyID: number, options?: AxiosRequestConfig) {
        return ObjectApikeyApiFp(this.configuration).apikeyGetSubnetsV1(pkiApikeyID, options).then((request) => request(this.axios, this.basePath));
    }
}
