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
import { EzsignsigningreasonCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsignsigningreasonCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsignsigningreasonEditObjectV1Request } from '../model';
// @ts-ignore
import { EzsignsigningreasonEditObjectV1Response } from '../model';
// @ts-ignore
import { EzsignsigningreasonGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { EzsignsigningreasonGetListV1Response } from '../model';
// @ts-ignore
import { EzsignsigningreasonGetObjectV2Response } from '../model';
// @ts-ignore
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignsigningreasonApi - axios parameter creator
 * @export
 */
export const ObjectEzsignsigningreasonApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignsigningreason
         * @param {EzsignsigningreasonCreateObjectV1Request} ezsignsigningreasonCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonCreateObjectV1: async (ezsignsigningreasonCreateObjectV1Request: EzsignsigningreasonCreateObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignsigningreasonCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsignsigningreasonCreateObjectV1', 'ezsignsigningreasonCreateObjectV1Request', ezsignsigningreasonCreateObjectV1Request)
            const localVarPath = `/1/object/ezsignsigningreason`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignsigningreasonCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Edit an existing Ezsignsigningreason
         * @param {number} pkiEzsignsigningreasonID The unique ID of the Ezsignsigningreason
         * @param {EzsignsigningreasonEditObjectV1Request} ezsignsigningreasonEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonEditObjectV1: async (pkiEzsignsigningreasonID: number, ezsignsigningreasonEditObjectV1Request: EzsignsigningreasonEditObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignsigningreasonID' is not null or undefined
            assertParamExists('ezsignsigningreasonEditObjectV1', 'pkiEzsignsigningreasonID', pkiEzsignsigningreasonID)
            // verify required parameter 'ezsignsigningreasonEditObjectV1Request' is not null or undefined
            assertParamExists('ezsignsigningreasonEditObjectV1', 'ezsignsigningreasonEditObjectV1Request', ezsignsigningreasonEditObjectV1Request)
            const localVarPath = `/1/object/ezsignsigningreason/{pkiEzsignsigningreasonID}`
                .replace(`{${"pkiEzsignsigningreasonID"}}`, encodeURIComponent(String(pkiEzsignsigningreasonID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignsigningreasonEditObjectV1Request, localVarRequestOptions, configuration)

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
         * Get the list of Ezsignsigningreason to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezsignsigningreasons and IDs
         * @param {EzsignsigningreasonGetAutocompleteV2SSelectorEnum} sSelector The type of Ezsignsigningreasons to return
         * @param {EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonGetAutocompleteV2: async (sSelector: EzsignsigningreasonGetAutocompleteV2SSelectorEnum, eFilterActive?: EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('ezsignsigningreasonGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/ezsignsigningreason/getAutocomplete/{sSelector}`
                .replace(`{${"sSelector"}}`, encodeURIComponent(String(sSelector)));
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

            if (eFilterActive !== undefined) {
                localVarQueryParameter['eFilterActive'] = eFilterActive;
            }

            if (sQuery !== undefined) {
                localVarQueryParameter['sQuery'] = sQuery;
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
         * @summary Retrieve Ezsignsigningreason list
         * @param {EzsignsigningreasonGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonGetListV1: async (eOrderBy?: EzsignsigningreasonGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/ezsignsigningreason/getList`;
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
         * @summary Retrieve an existing Ezsignsigningreason
         * @param {number} pkiEzsignsigningreasonID The unique ID of the Ezsignsigningreason
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonGetObjectV2: async (pkiEzsignsigningreasonID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignsigningreasonID' is not null or undefined
            assertParamExists('ezsignsigningreasonGetObjectV2', 'pkiEzsignsigningreasonID', pkiEzsignsigningreasonID)
            const localVarPath = `/2/object/ezsignsigningreason/{pkiEzsignsigningreasonID}`
                .replace(`{${"pkiEzsignsigningreasonID"}}`, encodeURIComponent(String(pkiEzsignsigningreasonID)));
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
 * ObjectEzsignsigningreasonApi - functional programming interface
 * @export
 */
export const ObjectEzsignsigningreasonApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignsigningreasonApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignsigningreason
         * @param {EzsignsigningreasonCreateObjectV1Request} ezsignsigningreasonCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignsigningreasonCreateObjectV1(ezsignsigningreasonCreateObjectV1Request: EzsignsigningreasonCreateObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignsigningreasonCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignsigningreasonCreateObjectV1(ezsignsigningreasonCreateObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignsigningreasonApi.ezsignsigningreasonCreateObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Edit an existing Ezsignsigningreason
         * @param {number} pkiEzsignsigningreasonID The unique ID of the Ezsignsigningreason
         * @param {EzsignsigningreasonEditObjectV1Request} ezsignsigningreasonEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignsigningreasonEditObjectV1(pkiEzsignsigningreasonID: number, ezsignsigningreasonEditObjectV1Request: EzsignsigningreasonEditObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignsigningreasonEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignsigningreasonEditObjectV1(pkiEzsignsigningreasonID, ezsignsigningreasonEditObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignsigningreasonApi.ezsignsigningreasonEditObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * Get the list of Ezsignsigningreason to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezsignsigningreasons and IDs
         * @param {EzsignsigningreasonGetAutocompleteV2SSelectorEnum} sSelector The type of Ezsignsigningreasons to return
         * @param {EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignsigningreasonGetAutocompleteV2(sSelector: EzsignsigningreasonGetAutocompleteV2SSelectorEnum, eFilterActive?: EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignsigningreasonGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignsigningreasonGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignsigningreasonApi.ezsignsigningreasonGetAutocompleteV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve Ezsignsigningreason list
         * @param {EzsignsigningreasonGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignsigningreasonGetListV1(eOrderBy?: EzsignsigningreasonGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignsigningreasonGetListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignsigningreasonGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignsigningreasonApi.ezsignsigningreasonGetListV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignsigningreason
         * @param {number} pkiEzsignsigningreasonID The unique ID of the Ezsignsigningreason
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignsigningreasonGetObjectV2(pkiEzsignsigningreasonID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignsigningreasonGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignsigningreasonGetObjectV2(pkiEzsignsigningreasonID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignsigningreasonApi.ezsignsigningreasonGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectEzsignsigningreasonApi - factory interface
 * @export
 */
export const ObjectEzsignsigningreasonApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignsigningreasonApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignsigningreason
         * @param {EzsignsigningreasonCreateObjectV1Request} ezsignsigningreasonCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonCreateObjectV1(ezsignsigningreasonCreateObjectV1Request: EzsignsigningreasonCreateObjectV1Request, options?: any): AxiosPromise<EzsignsigningreasonCreateObjectV1Response> {
            return localVarFp.ezsignsigningreasonCreateObjectV1(ezsignsigningreasonCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Ezsignsigningreason
         * @param {number} pkiEzsignsigningreasonID The unique ID of the Ezsignsigningreason
         * @param {EzsignsigningreasonEditObjectV1Request} ezsignsigningreasonEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonEditObjectV1(pkiEzsignsigningreasonID: number, ezsignsigningreasonEditObjectV1Request: EzsignsigningreasonEditObjectV1Request, options?: any): AxiosPromise<EzsignsigningreasonEditObjectV1Response> {
            return localVarFp.ezsignsigningreasonEditObjectV1(pkiEzsignsigningreasonID, ezsignsigningreasonEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * Get the list of Ezsignsigningreason to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezsignsigningreasons and IDs
         * @param {EzsignsigningreasonGetAutocompleteV2SSelectorEnum} sSelector The type of Ezsignsigningreasons to return
         * @param {EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonGetAutocompleteV2(sSelector: EzsignsigningreasonGetAutocompleteV2SSelectorEnum, eFilterActive?: EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<EzsignsigningreasonGetAutocompleteV2Response> {
            return localVarFp.ezsignsigningreasonGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Ezsignsigningreason list
         * @param {EzsignsigningreasonGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonGetListV1(eOrderBy?: EzsignsigningreasonGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: any): AxiosPromise<EzsignsigningreasonGetListV1Response> {
            return localVarFp.ezsignsigningreasonGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignsigningreason
         * @param {number} pkiEzsignsigningreasonID The unique ID of the Ezsignsigningreason
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsigningreasonGetObjectV2(pkiEzsignsigningreasonID: number, options?: any): AxiosPromise<EzsignsigningreasonGetObjectV2Response> {
            return localVarFp.ezsignsigningreasonGetObjectV2(pkiEzsignsigningreasonID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignsigningreasonApi - object-oriented interface
 * @export
 * @class ObjectEzsignsigningreasonApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignsigningreasonApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsignsigningreason
     * @param {EzsignsigningreasonCreateObjectV1Request} ezsignsigningreasonCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignsigningreasonApi
     */
    public ezsignsigningreasonCreateObjectV1(ezsignsigningreasonCreateObjectV1Request: EzsignsigningreasonCreateObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsignsigningreasonApiFp(this.configuration).ezsignsigningreasonCreateObjectV1(ezsignsigningreasonCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Ezsignsigningreason
     * @param {number} pkiEzsignsigningreasonID The unique ID of the Ezsignsigningreason
     * @param {EzsignsigningreasonEditObjectV1Request} ezsignsigningreasonEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignsigningreasonApi
     */
    public ezsignsigningreasonEditObjectV1(pkiEzsignsigningreasonID: number, ezsignsigningreasonEditObjectV1Request: EzsignsigningreasonEditObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsignsigningreasonApiFp(this.configuration).ezsignsigningreasonEditObjectV1(pkiEzsignsigningreasonID, ezsignsigningreasonEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Get the list of Ezsignsigningreason to be used in a dropdown or autocomplete control.
     * @summary Retrieve Ezsignsigningreasons and IDs
     * @param {EzsignsigningreasonGetAutocompleteV2SSelectorEnum} sSelector The type of Ezsignsigningreasons to return
     * @param {EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignsigningreasonApi
     */
    public ezsignsigningreasonGetAutocompleteV2(sSelector: EzsignsigningreasonGetAutocompleteV2SSelectorEnum, eFilterActive?: EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig) {
        return ObjectEzsignsigningreasonApiFp(this.configuration).ezsignsigningreasonGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Ezsignsigningreason list
     * @param {EzsignsigningreasonGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
     * @param {number} [iRowMax] 
     * @param {number} [iRowOffset] 
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {string} [sFilter] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignsigningreasonApi
     */
    public ezsignsigningreasonGetListV1(eOrderBy?: EzsignsigningreasonGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig) {
        return ObjectEzsignsigningreasonApiFp(this.configuration).ezsignsigningreasonGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignsigningreason
     * @param {number} pkiEzsignsigningreasonID The unique ID of the Ezsignsigningreason
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignsigningreasonApi
     */
    public ezsignsigningreasonGetObjectV2(pkiEzsignsigningreasonID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignsigningreasonApiFp(this.configuration).ezsignsigningreasonGetObjectV2(pkiEzsignsigningreasonID, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const EzsignsigningreasonGetAutocompleteV2SSelectorEnum = {
    All: 'All',
    Active: 'Active'
} as const;
export type EzsignsigningreasonGetAutocompleteV2SSelectorEnum = typeof EzsignsigningreasonGetAutocompleteV2SSelectorEnum[keyof typeof EzsignsigningreasonGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum = typeof EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum[keyof typeof EzsignsigningreasonGetAutocompleteV2EFilterActiveEnum];
/**
 * @export
 */
export const EzsignsigningreasonGetListV1EOrderByEnum = {
    pkiEzsignsigningreasonID_ASC: 'pkiEzsignsigningreasonID_ASC',
    pkiEzsignsigningreasonID_DESC: 'pkiEzsignsigningreasonID_DESC',
    sEzsignsigningreasonDescriptionX_ASC: 'sEzsignsigningreasonDescriptionX_ASC',
    sEzsignsigningreasonDescriptionX_DESC: 'sEzsignsigningreasonDescriptionX_DESC',
    bEzsignsigningreasonIsactive_ASC: 'bEzsignsigningreasonIsactive_ASC',
    bEzsignsigningreasonIsactive_DESC: 'bEzsignsigningreasonIsactive_DESC'
} as const;
export type EzsignsigningreasonGetListV1EOrderByEnum = typeof EzsignsigningreasonGetListV1EOrderByEnum[keyof typeof EzsignsigningreasonGetListV1EOrderByEnum];
