/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
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
import type { ScimGroup } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ScimGroupsApi - axios parameter creator
 * @export
 */
export const ScimGroupsApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Create a new Usergroup
         * @param {ScimGroup} scimGroup 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsCreateObjectScimV2: async (scimGroup: ScimGroup, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'scimGroup' is not null or undefined
            assertParamExists('groupsCreateObjectScimV2', 'scimGroup', scimGroup)
            const localVarPath = `/2/scim/Groups`;
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

            // authentication Bearer required
            // http bearer authentication required
            await setBearerAuthToObject(localVarHeaderParameter, configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(scimGroup, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Usergroup
         * @param {string} groupId 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsDeleteObjectScimV2: async (groupId: string, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'groupId' is not null or undefined
            assertParamExists('groupsDeleteObjectScimV2', 'groupId', groupId)
            const localVarPath = `/2/scim/Groups/{groupId}`
                .replace(`{${"groupId"}}`, encodeURIComponent(String(groupId)));
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

            // authentication Bearer required
            // http bearer authentication required
            await setBearerAuthToObject(localVarHeaderParameter, configuration)


    
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
         * @summary Edit an existing Usergroup
         * @param {string} groupId 
         * @param {ScimGroup} scimGroup 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsEditObjectScimV2: async (groupId: string, scimGroup: ScimGroup, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'groupId' is not null or undefined
            assertParamExists('groupsEditObjectScimV2', 'groupId', groupId)
            // verify required parameter 'scimGroup' is not null or undefined
            assertParamExists('groupsEditObjectScimV2', 'scimGroup', scimGroup)
            const localVarPath = `/2/scim/Groups/{groupId}`
                .replace(`{${"groupId"}}`, encodeURIComponent(String(groupId)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'PUT', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Bearer required
            // http bearer authentication required
            await setBearerAuthToObject(localVarHeaderParameter, configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(scimGroup, localVarRequestOptions, configuration)

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
         * @summary Retrieve Usergroup list
         * @param {string} [filter] Filter expression for searching groups
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsGetListScimV2: async (filter?: string, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/2/scim/Groups`;
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

            // authentication Bearer required
            // http bearer authentication required
            await setBearerAuthToObject(localVarHeaderParameter, configuration)

            if (filter !== undefined) {
                localVarQueryParameter['filter'] = filter;
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
         * @summary Retrieve an existing Usergroup
         * @param {string} groupId 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsGetObjectScimV2: async (groupId: string, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'groupId' is not null or undefined
            assertParamExists('groupsGetObjectScimV2', 'groupId', groupId)
            const localVarPath = `/2/scim/Groups/{groupId}`
                .replace(`{${"groupId"}}`, encodeURIComponent(String(groupId)));
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

            // authentication Bearer required
            // http bearer authentication required
            await setBearerAuthToObject(localVarHeaderParameter, configuration)


    
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
    }
};

/**
 * ScimGroupsApi - functional programming interface
 * @export
 */
export const ScimGroupsApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ScimGroupsApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Create a new Usergroup
         * @param {ScimGroup} scimGroup 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async groupsCreateObjectScimV2(scimGroup: ScimGroup, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScimGroup>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.groupsCreateObjectScimV2(scimGroup, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ScimGroupsApi.groupsCreateObjectScimV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Delete an existing Usergroup
         * @param {string} groupId 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async groupsDeleteObjectScimV2(groupId: string, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.groupsDeleteObjectScimV2(groupId, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ScimGroupsApi.groupsDeleteObjectScimV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Edit an existing Usergroup
         * @param {string} groupId 
         * @param {ScimGroup} scimGroup 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async groupsEditObjectScimV2(groupId: string, scimGroup: ScimGroup, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScimGroup>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.groupsEditObjectScimV2(groupId, scimGroup, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ScimGroupsApi.groupsEditObjectScimV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve Usergroup list
         * @param {string} [filter] Filter expression for searching groups
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async groupsGetListScimV2(filter?: string, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScimGroup>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.groupsGetListScimV2(filter, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ScimGroupsApi.groupsGetListScimV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Usergroup
         * @param {string} groupId 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async groupsGetObjectScimV2(groupId: string, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ScimGroup>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.groupsGetObjectScimV2(groupId, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ScimGroupsApi.groupsGetObjectScimV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ScimGroupsApi - factory interface
 * @export
 */
export const ScimGroupsApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ScimGroupsApiFp(configuration)
    return {
        /**
         * 
         * @summary Create a new Usergroup
         * @param {ScimGroup} scimGroup 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsCreateObjectScimV2(scimGroup: ScimGroup, options?: RawAxiosRequestConfig): AxiosPromise<ScimGroup> {
            return localVarFp.groupsCreateObjectScimV2(scimGroup, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Usergroup
         * @param {string} groupId 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsDeleteObjectScimV2(groupId: string, options?: RawAxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.groupsDeleteObjectScimV2(groupId, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Usergroup
         * @param {string} groupId 
         * @param {ScimGroup} scimGroup 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsEditObjectScimV2(groupId: string, scimGroup: ScimGroup, options?: RawAxiosRequestConfig): AxiosPromise<ScimGroup> {
            return localVarFp.groupsEditObjectScimV2(groupId, scimGroup, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Usergroup list
         * @param {string} [filter] Filter expression for searching groups
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsGetListScimV2(filter?: string, options?: RawAxiosRequestConfig): AxiosPromise<ScimGroup> {
            return localVarFp.groupsGetListScimV2(filter, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Usergroup
         * @param {string} groupId 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        groupsGetObjectScimV2(groupId: string, options?: RawAxiosRequestConfig): AxiosPromise<ScimGroup> {
            return localVarFp.groupsGetObjectScimV2(groupId, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ScimGroupsApi - object-oriented interface
 * @export
 * @class ScimGroupsApi
 * @extends {BaseAPI}
 */
export class ScimGroupsApi extends BaseAPI {
    /**
     * 
     * @summary Create a new Usergroup
     * @param {ScimGroup} scimGroup 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ScimGroupsApi
     */
    public groupsCreateObjectScimV2(scimGroup: ScimGroup, options?: RawAxiosRequestConfig) {
        return ScimGroupsApiFp(this.configuration).groupsCreateObjectScimV2(scimGroup, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Usergroup
     * @param {string} groupId 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ScimGroupsApi
     */
    public groupsDeleteObjectScimV2(groupId: string, options?: RawAxiosRequestConfig) {
        return ScimGroupsApiFp(this.configuration).groupsDeleteObjectScimV2(groupId, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Usergroup
     * @param {string} groupId 
     * @param {ScimGroup} scimGroup 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ScimGroupsApi
     */
    public groupsEditObjectScimV2(groupId: string, scimGroup: ScimGroup, options?: RawAxiosRequestConfig) {
        return ScimGroupsApiFp(this.configuration).groupsEditObjectScimV2(groupId, scimGroup, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Usergroup list
     * @param {string} [filter] Filter expression for searching groups
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ScimGroupsApi
     */
    public groupsGetListScimV2(filter?: string, options?: RawAxiosRequestConfig) {
        return ScimGroupsApiFp(this.configuration).groupsGetListScimV2(filter, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Usergroup
     * @param {string} groupId 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ScimGroupsApi
     */
    public groupsGetObjectScimV2(groupId: string, options?: RawAxiosRequestConfig) {
        return ScimGroupsApiFp(this.configuration).groupsGetObjectScimV2(groupId, options).then((request) => request(this.axios, this.basePath));
    }
}

