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
import type { CommonResponse } from '../model';
// @ts-ignore
import type { CommonResponseError } from '../model';
// @ts-ignore
import type { EzsignannotationCreateObjectV1Request } from '../model';
// @ts-ignore
import type { EzsignannotationCreateObjectV1Response } from '../model';
// @ts-ignore
import type { EzsignannotationEditObjectV1Request } from '../model';
// @ts-ignore
import type { EzsignannotationGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignannotationApi - axios parameter creator
 * @export
 */
export const ObjectEzsignannotationApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignannotation
         * @param {EzsignannotationCreateObjectV1Request} ezsignannotationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignannotationCreateObjectV1: async (ezsignannotationCreateObjectV1Request: EzsignannotationCreateObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignannotationCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsignannotationCreateObjectV1', 'ezsignannotationCreateObjectV1Request', ezsignannotationCreateObjectV1Request)
            const localVarPath = `/1/object/ezsignannotation`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignannotationCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignannotationDeleteObjectV1: async (pkiEzsignannotationID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignannotationID' is not null or undefined
            assertParamExists('ezsignannotationDeleteObjectV1', 'pkiEzsignannotationID', pkiEzsignannotationID)
            const localVarPath = `/1/object/ezsignannotation/{pkiEzsignannotationID}`
                .replace(`{${"pkiEzsignannotationID"}}`, encodeURIComponent(String(pkiEzsignannotationID)));
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
         * @summary Edit an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {EzsignannotationEditObjectV1Request} ezsignannotationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignannotationEditObjectV1: async (pkiEzsignannotationID: number, ezsignannotationEditObjectV1Request: EzsignannotationEditObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignannotationID' is not null or undefined
            assertParamExists('ezsignannotationEditObjectV1', 'pkiEzsignannotationID', pkiEzsignannotationID)
            // verify required parameter 'ezsignannotationEditObjectV1Request' is not null or undefined
            assertParamExists('ezsignannotationEditObjectV1', 'ezsignannotationEditObjectV1Request', ezsignannotationEditObjectV1Request)
            const localVarPath = `/1/object/ezsignannotation/{pkiEzsignannotationID}`
                .replace(`{${"pkiEzsignannotationID"}}`, encodeURIComponent(String(pkiEzsignannotationID)));
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

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignannotationEditObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Retrieve an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignannotationGetObjectV2: async (pkiEzsignannotationID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignannotationID' is not null or undefined
            assertParamExists('ezsignannotationGetObjectV2', 'pkiEzsignannotationID', pkiEzsignannotationID)
            const localVarPath = `/2/object/ezsignannotation/{pkiEzsignannotationID}`
                .replace(`{${"pkiEzsignannotationID"}}`, encodeURIComponent(String(pkiEzsignannotationID)));
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
    }
};

/**
 * ObjectEzsignannotationApi - functional programming interface
 * @export
 */
export const ObjectEzsignannotationApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignannotationApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignannotation
         * @param {EzsignannotationCreateObjectV1Request} ezsignannotationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignannotationCreateObjectV1(ezsignannotationCreateObjectV1Request: EzsignannotationCreateObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignannotationCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignannotationCreateObjectV1(ezsignannotationCreateObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignannotationApi.ezsignannotationCreateObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Delete an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignannotationDeleteObjectV1(pkiEzsignannotationID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignannotationDeleteObjectV1(pkiEzsignannotationID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignannotationApi.ezsignannotationDeleteObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Edit an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {EzsignannotationEditObjectV1Request} ezsignannotationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignannotationEditObjectV1(pkiEzsignannotationID: number, ezsignannotationEditObjectV1Request: EzsignannotationEditObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignannotationEditObjectV1(pkiEzsignannotationID, ezsignannotationEditObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignannotationApi.ezsignannotationEditObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignannotationGetObjectV2(pkiEzsignannotationID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignannotationGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignannotationGetObjectV2(pkiEzsignannotationID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignannotationApi.ezsignannotationGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectEzsignannotationApi - factory interface
 * @export
 */
export const ObjectEzsignannotationApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignannotationApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignannotation
         * @param {EzsignannotationCreateObjectV1Request} ezsignannotationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignannotationCreateObjectV1(ezsignannotationCreateObjectV1Request: EzsignannotationCreateObjectV1Request, options?: RawAxiosRequestConfig): AxiosPromise<EzsignannotationCreateObjectV1Response> {
            return localVarFp.ezsignannotationCreateObjectV1(ezsignannotationCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignannotationDeleteObjectV1(pkiEzsignannotationID: number, options?: RawAxiosRequestConfig): AxiosPromise<CommonResponse> {
            return localVarFp.ezsignannotationDeleteObjectV1(pkiEzsignannotationID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {EzsignannotationEditObjectV1Request} ezsignannotationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignannotationEditObjectV1(pkiEzsignannotationID: number, ezsignannotationEditObjectV1Request: EzsignannotationEditObjectV1Request, options?: RawAxiosRequestConfig): AxiosPromise<CommonResponse> {
            return localVarFp.ezsignannotationEditObjectV1(pkiEzsignannotationID, ezsignannotationEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignannotation
         * @param {number} pkiEzsignannotationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignannotationGetObjectV2(pkiEzsignannotationID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsignannotationGetObjectV2Response> {
            return localVarFp.ezsignannotationGetObjectV2(pkiEzsignannotationID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignannotationApi - object-oriented interface
 * @export
 * @class ObjectEzsignannotationApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignannotationApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsignannotation
     * @param {EzsignannotationCreateObjectV1Request} ezsignannotationCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignannotationApi
     */
    public ezsignannotationCreateObjectV1(ezsignannotationCreateObjectV1Request: EzsignannotationCreateObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsignannotationApiFp(this.configuration).ezsignannotationCreateObjectV1(ezsignannotationCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsignannotation
     * @param {number} pkiEzsignannotationID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignannotationApi
     */
    public ezsignannotationDeleteObjectV1(pkiEzsignannotationID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignannotationApiFp(this.configuration).ezsignannotationDeleteObjectV1(pkiEzsignannotationID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Ezsignannotation
     * @param {number} pkiEzsignannotationID 
     * @param {EzsignannotationEditObjectV1Request} ezsignannotationEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignannotationApi
     */
    public ezsignannotationEditObjectV1(pkiEzsignannotationID: number, ezsignannotationEditObjectV1Request: EzsignannotationEditObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsignannotationApiFp(this.configuration).ezsignannotationEditObjectV1(pkiEzsignannotationID, ezsignannotationEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignannotation
     * @param {number} pkiEzsignannotationID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignannotationApi
     */
    public ezsignannotationGetObjectV2(pkiEzsignannotationID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignannotationApiFp(this.configuration).ezsignannotationGetObjectV2(pkiEzsignannotationID, options).then((request) => request(this.axios, this.basePath));
    }
}

