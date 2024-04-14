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
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError, operationServerMap } from '../base';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { UserstagedCreateUserV1Response } from '../model';
// @ts-ignore
import { UserstagedDeleteObjectV1Response } from '../model';
// @ts-ignore
import { UserstagedGetListV1Response } from '../model';
// @ts-ignore
import { UserstagedGetObjectV2Response } from '../model';
// @ts-ignore
import { UserstagedMapV1Request } from '../model';
// @ts-ignore
import { UserstagedMapV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectUserstagedApi - axios parameter creator
 * @export
 */
export const ObjectUserstagedApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Default values will be used while creating the User. If you need to change those values, you should use the route to edit a User.
         * @summary Create a User from a Userstaged and then map it
         * @param {number} pkiUserstagedID 
         * @param {object} body 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedCreateUserV1: async (pkiUserstagedID: number, body: object, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUserstagedID' is not null or undefined
            assertParamExists('userstagedCreateUserV1', 'pkiUserstagedID', pkiUserstagedID)
            // verify required parameter 'body' is not null or undefined
            assertParamExists('userstagedCreateUserV1', 'body', body)
            const localVarPath = `/1/object/userstaged/{pkiUserstagedID}/createUser`
                .replace(`{${"pkiUserstagedID"}}`, encodeURIComponent(String(pkiUserstagedID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(body, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Userstaged
         * @param {number} pkiUserstagedID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedDeleteObjectV1: async (pkiUserstagedID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUserstagedID' is not null or undefined
            assertParamExists('userstagedDeleteObjectV1', 'pkiUserstagedID', pkiUserstagedID)
            const localVarPath = `/1/object/userstaged/{pkiUserstagedID}`
                .replace(`{${"pkiUserstagedID"}}`, encodeURIComponent(String(pkiUserstagedID)));
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
         * @summary Retrieve Userstaged list
         * @param {UserstagedGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedGetListV1: async (eOrderBy?: UserstagedGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/userstaged/getList`;
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

            if (eOrderBy !== undefined) {
                localVarQueryParameter['eOrderBy'] = eOrderBy;
            }

            if (iRowMax !== undefined) {
                localVarQueryParameter['iRowMax'] = iRowMax;
            }

            if (iRowOffset !== undefined) {
                localVarQueryParameter['iRowOffset'] = iRowOffset;
            }

            if (sFilter !== undefined) {
                localVarQueryParameter['sFilter'] = sFilter;
            }

            if (acceptLanguage != null) {
                localVarHeaderParameter['Accept-Language'] = typeof acceptLanguage === 'string'
                    ? acceptLanguage
                    : JSON.stringify(acceptLanguage);
            }


    
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
         * @summary Retrieve an existing Userstaged
         * @param {number} pkiUserstagedID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedGetObjectV2: async (pkiUserstagedID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUserstagedID' is not null or undefined
            assertParamExists('userstagedGetObjectV2', 'pkiUserstagedID', pkiUserstagedID)
            const localVarPath = `/2/object/userstaged/{pkiUserstagedID}`
                .replace(`{${"pkiUserstagedID"}}`, encodeURIComponent(String(pkiUserstagedID)));
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
         * @summary Map the Userstaged to an existing user
         * @param {number} pkiUserstagedID 
         * @param {UserstagedMapV1Request} userstagedMapV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedMapV1: async (pkiUserstagedID: number, userstagedMapV1Request: UserstagedMapV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiUserstagedID' is not null or undefined
            assertParamExists('userstagedMapV1', 'pkiUserstagedID', pkiUserstagedID)
            // verify required parameter 'userstagedMapV1Request' is not null or undefined
            assertParamExists('userstagedMapV1', 'userstagedMapV1Request', userstagedMapV1Request)
            const localVarPath = `/1/object/userstaged/{pkiUserstagedID}/map`
                .replace(`{${"pkiUserstagedID"}}`, encodeURIComponent(String(pkiUserstagedID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(userstagedMapV1Request, localVarRequestOptions, configuration)

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
 * ObjectUserstagedApi - functional programming interface
 * @export
 */
export const ObjectUserstagedApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectUserstagedApiAxiosParamCreator(configuration)
    return {
        /**
         * Default values will be used while creating the User. If you need to change those values, you should use the route to edit a User.
         * @summary Create a User from a Userstaged and then map it
         * @param {number} pkiUserstagedID 
         * @param {object} body 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async userstagedCreateUserV1(pkiUserstagedID: number, body: object, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UserstagedCreateUserV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.userstagedCreateUserV1(pkiUserstagedID, body, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectUserstagedApi.userstagedCreateUserV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Delete an existing Userstaged
         * @param {number} pkiUserstagedID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async userstagedDeleteObjectV1(pkiUserstagedID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UserstagedDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.userstagedDeleteObjectV1(pkiUserstagedID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectUserstagedApi.userstagedDeleteObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve Userstaged list
         * @param {UserstagedGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async userstagedGetListV1(eOrderBy?: UserstagedGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UserstagedGetListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.userstagedGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectUserstagedApi.userstagedGetListV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Userstaged
         * @param {number} pkiUserstagedID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async userstagedGetObjectV2(pkiUserstagedID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UserstagedGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.userstagedGetObjectV2(pkiUserstagedID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectUserstagedApi.userstagedGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Map the Userstaged to an existing user
         * @param {number} pkiUserstagedID 
         * @param {UserstagedMapV1Request} userstagedMapV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async userstagedMapV1(pkiUserstagedID: number, userstagedMapV1Request: UserstagedMapV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UserstagedMapV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.userstagedMapV1(pkiUserstagedID, userstagedMapV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectUserstagedApi.userstagedMapV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectUserstagedApi - factory interface
 * @export
 */
export const ObjectUserstagedApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectUserstagedApiFp(configuration)
    return {
        /**
         * Default values will be used while creating the User. If you need to change those values, you should use the route to edit a User.
         * @summary Create a User from a Userstaged and then map it
         * @param {number} pkiUserstagedID 
         * @param {object} body 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedCreateUserV1(pkiUserstagedID: number, body: object, options?: any): AxiosPromise<UserstagedCreateUserV1Response> {
            return localVarFp.userstagedCreateUserV1(pkiUserstagedID, body, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Userstaged
         * @param {number} pkiUserstagedID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedDeleteObjectV1(pkiUserstagedID: number, options?: any): AxiosPromise<UserstagedDeleteObjectV1Response> {
            return localVarFp.userstagedDeleteObjectV1(pkiUserstagedID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Userstaged list
         * @param {UserstagedGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedGetListV1(eOrderBy?: UserstagedGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: any): AxiosPromise<UserstagedGetListV1Response> {
            return localVarFp.userstagedGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Userstaged
         * @param {number} pkiUserstagedID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedGetObjectV2(pkiUserstagedID: number, options?: any): AxiosPromise<UserstagedGetObjectV2Response> {
            return localVarFp.userstagedGetObjectV2(pkiUserstagedID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Map the Userstaged to an existing user
         * @param {number} pkiUserstagedID 
         * @param {UserstagedMapV1Request} userstagedMapV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userstagedMapV1(pkiUserstagedID: number, userstagedMapV1Request: UserstagedMapV1Request, options?: any): AxiosPromise<UserstagedMapV1Response> {
            return localVarFp.userstagedMapV1(pkiUserstagedID, userstagedMapV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectUserstagedApi - object-oriented interface
 * @export
 * @class ObjectUserstagedApi
 * @extends {BaseAPI}
 */
export class ObjectUserstagedApi extends BaseAPI {
    /**
     * Default values will be used while creating the User. If you need to change those values, you should use the route to edit a User.
     * @summary Create a User from a Userstaged and then map it
     * @param {number} pkiUserstagedID 
     * @param {object} body 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUserstagedApi
     */
    public userstagedCreateUserV1(pkiUserstagedID: number, body: object, options?: RawAxiosRequestConfig) {
        return ObjectUserstagedApiFp(this.configuration).userstagedCreateUserV1(pkiUserstagedID, body, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Userstaged
     * @param {number} pkiUserstagedID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUserstagedApi
     */
    public userstagedDeleteObjectV1(pkiUserstagedID: number, options?: RawAxiosRequestConfig) {
        return ObjectUserstagedApiFp(this.configuration).userstagedDeleteObjectV1(pkiUserstagedID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Userstaged list
     * @param {UserstagedGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
     * @param {number} [iRowMax] 
     * @param {number} [iRowOffset] 
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {string} [sFilter] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUserstagedApi
     */
    public userstagedGetListV1(eOrderBy?: UserstagedGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig) {
        return ObjectUserstagedApiFp(this.configuration).userstagedGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Userstaged
     * @param {number} pkiUserstagedID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUserstagedApi
     */
    public userstagedGetObjectV2(pkiUserstagedID: number, options?: RawAxiosRequestConfig) {
        return ObjectUserstagedApiFp(this.configuration).userstagedGetObjectV2(pkiUserstagedID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Map the Userstaged to an existing user
     * @param {number} pkiUserstagedID 
     * @param {UserstagedMapV1Request} userstagedMapV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUserstagedApi
     */
    public userstagedMapV1(pkiUserstagedID: number, userstagedMapV1Request: UserstagedMapV1Request, options?: RawAxiosRequestConfig) {
        return ObjectUserstagedApiFp(this.configuration).userstagedMapV1(pkiUserstagedID, userstagedMapV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const UserstagedGetListV1EOrderByEnum = {
    pkiUserstagedID_ASC: 'pkiUserstagedID_ASC',
    pkiUserstagedID_DESC: 'pkiUserstagedID_DESC',
    sEmailAddress_ASC: 'sEmailAddress_ASC',
    sEmailAddress_DESC: 'sEmailAddress_DESC',
    sUserstagedFirstname_ASC: 'sUserstagedFirstname_ASC',
    sUserstagedFirstname_DESC: 'sUserstagedFirstname_DESC',
    sUserstagedLastname_ASC: 'sUserstagedLastname_ASC',
    sUserstagedLastname_DESC: 'sUserstagedLastname_DESC',
    sUserstagedExternalid_ASC: 'sUserstagedExternalid_ASC',
    sUserstagedExternalid_DESC: 'sUserstagedExternalid_DESC'
} as const;
export type UserstagedGetListV1EOrderByEnum = typeof UserstagedGetListV1EOrderByEnum[keyof typeof UserstagedGetListV1EOrderByEnum];
