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
import type { BrandingCreateObjectV2Request } from '../model';
// @ts-ignore
import type { BrandingCreateObjectV2Response } from '../model';
// @ts-ignore
import type { BrandingEditObjectV2Request } from '../model';
// @ts-ignore
import type { BrandingEditObjectV2Response } from '../model';
// @ts-ignore
import type { BrandingGetAutocompleteV2Response } from '../model';
// @ts-ignore
import type { BrandingGetListV1Response } from '../model';
// @ts-ignore
import type { BrandingGetObjectV3Response } from '../model';
// @ts-ignore
import type { CommonResponseError } from '../model';
// @ts-ignore
import type { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectBrandingApi - axios parameter creator
 * @export
 */
export const ObjectBrandingApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Branding
         * @param {BrandingCreateObjectV2Request} brandingCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingCreateObjectV2: async (brandingCreateObjectV2Request: BrandingCreateObjectV2Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'brandingCreateObjectV2Request' is not null or undefined
            assertParamExists('brandingCreateObjectV2', 'brandingCreateObjectV2Request', brandingCreateObjectV2Request)
            const localVarPath = `/2/object/branding`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(brandingCreateObjectV2Request, localVarRequestOptions, configuration)

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
         * @summary Edit an existing Branding
         * @param {number} pkiBrandingID 
         * @param {BrandingEditObjectV2Request} brandingEditObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingEditObjectV2: async (pkiBrandingID: number, brandingEditObjectV2Request: BrandingEditObjectV2Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiBrandingID' is not null or undefined
            assertParamExists('brandingEditObjectV2', 'pkiBrandingID', pkiBrandingID)
            // verify required parameter 'brandingEditObjectV2Request' is not null or undefined
            assertParamExists('brandingEditObjectV2', 'brandingEditObjectV2Request', brandingEditObjectV2Request)
            const localVarPath = `/2/object/branding/{pkiBrandingID}`
                .replace(`{${"pkiBrandingID"}}`, encodeURIComponent(String(pkiBrandingID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(brandingEditObjectV2Request, localVarRequestOptions, configuration)

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
         * Get the list of Branding to be used in a dropdown or autocomplete control.
         * @summary Retrieve Brandings and IDs
         * @param {BrandingGetAutocompleteV2SSelectorEnum} sSelector The type of Brandings to return
         * @param {BrandingGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingGetAutocompleteV2: async (sSelector: BrandingGetAutocompleteV2SSelectorEnum, eFilterActive?: BrandingGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('brandingGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/branding/getAutocomplete/{sSelector}`
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
         * Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eBrandingLogo | Default<br>JPEG<br>PNG | | eBrandingLogointerface | Default<br>JPEG<br>PNG |
         * @summary Retrieve Branding list
         * @param {BrandingGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingGetListV1: async (eOrderBy?: BrandingGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/branding/getList`;
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
         * @summary Retrieve an existing Branding
         * @param {number} pkiBrandingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingGetObjectV3: async (pkiBrandingID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiBrandingID' is not null or undefined
            assertParamExists('brandingGetObjectV3', 'pkiBrandingID', pkiBrandingID)
            const localVarPath = `/3/object/branding/{pkiBrandingID}`
                .replace(`{${"pkiBrandingID"}}`, encodeURIComponent(String(pkiBrandingID)));
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
 * ObjectBrandingApi - functional programming interface
 * @export
 */
export const ObjectBrandingApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectBrandingApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Branding
         * @param {BrandingCreateObjectV2Request} brandingCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async brandingCreateObjectV2(brandingCreateObjectV2Request: BrandingCreateObjectV2Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BrandingCreateObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.brandingCreateObjectV2(brandingCreateObjectV2Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectBrandingApi.brandingCreateObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Edit an existing Branding
         * @param {number} pkiBrandingID 
         * @param {BrandingEditObjectV2Request} brandingEditObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async brandingEditObjectV2(pkiBrandingID: number, brandingEditObjectV2Request: BrandingEditObjectV2Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BrandingEditObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.brandingEditObjectV2(pkiBrandingID, brandingEditObjectV2Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectBrandingApi.brandingEditObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * Get the list of Branding to be used in a dropdown or autocomplete control.
         * @summary Retrieve Brandings and IDs
         * @param {BrandingGetAutocompleteV2SSelectorEnum} sSelector The type of Brandings to return
         * @param {BrandingGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async brandingGetAutocompleteV2(sSelector: BrandingGetAutocompleteV2SSelectorEnum, eFilterActive?: BrandingGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BrandingGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.brandingGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectBrandingApi.brandingGetAutocompleteV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eBrandingLogo | Default<br>JPEG<br>PNG | | eBrandingLogointerface | Default<br>JPEG<br>PNG |
         * @summary Retrieve Branding list
         * @param {BrandingGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async brandingGetListV1(eOrderBy?: BrandingGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BrandingGetListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.brandingGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectBrandingApi.brandingGetListV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Branding
         * @param {number} pkiBrandingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async brandingGetObjectV3(pkiBrandingID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BrandingGetObjectV3Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.brandingGetObjectV3(pkiBrandingID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectBrandingApi.brandingGetObjectV3']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectBrandingApi - factory interface
 * @export
 */
export const ObjectBrandingApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectBrandingApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Branding
         * @param {BrandingCreateObjectV2Request} brandingCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingCreateObjectV2(brandingCreateObjectV2Request: BrandingCreateObjectV2Request, options?: RawAxiosRequestConfig): AxiosPromise<BrandingCreateObjectV2Response> {
            return localVarFp.brandingCreateObjectV2(brandingCreateObjectV2Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Branding
         * @param {number} pkiBrandingID 
         * @param {BrandingEditObjectV2Request} brandingEditObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingEditObjectV2(pkiBrandingID: number, brandingEditObjectV2Request: BrandingEditObjectV2Request, options?: RawAxiosRequestConfig): AxiosPromise<BrandingEditObjectV2Response> {
            return localVarFp.brandingEditObjectV2(pkiBrandingID, brandingEditObjectV2Request, options).then((request) => request(axios, basePath));
        },
        /**
         * Get the list of Branding to be used in a dropdown or autocomplete control.
         * @summary Retrieve Brandings and IDs
         * @param {BrandingGetAutocompleteV2SSelectorEnum} sSelector The type of Brandings to return
         * @param {BrandingGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingGetAutocompleteV2(sSelector: BrandingGetAutocompleteV2SSelectorEnum, eFilterActive?: BrandingGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): AxiosPromise<BrandingGetAutocompleteV2Response> {
            return localVarFp.brandingGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
        /**
         * Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eBrandingLogo | Default<br>JPEG<br>PNG | | eBrandingLogointerface | Default<br>JPEG<br>PNG |
         * @summary Retrieve Branding list
         * @param {BrandingGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingGetListV1(eOrderBy?: BrandingGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig): AxiosPromise<BrandingGetListV1Response> {
            return localVarFp.brandingGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Branding
         * @param {number} pkiBrandingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingGetObjectV3(pkiBrandingID: number, options?: RawAxiosRequestConfig): AxiosPromise<BrandingGetObjectV3Response> {
            return localVarFp.brandingGetObjectV3(pkiBrandingID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectBrandingApi - object-oriented interface
 * @export
 * @class ObjectBrandingApi
 * @extends {BaseAPI}
 */
export class ObjectBrandingApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Branding
     * @param {BrandingCreateObjectV2Request} brandingCreateObjectV2Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBrandingApi
     */
    public brandingCreateObjectV2(brandingCreateObjectV2Request: BrandingCreateObjectV2Request, options?: RawAxiosRequestConfig) {
        return ObjectBrandingApiFp(this.configuration).brandingCreateObjectV2(brandingCreateObjectV2Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Branding
     * @param {number} pkiBrandingID 
     * @param {BrandingEditObjectV2Request} brandingEditObjectV2Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBrandingApi
     */
    public brandingEditObjectV2(pkiBrandingID: number, brandingEditObjectV2Request: BrandingEditObjectV2Request, options?: RawAxiosRequestConfig) {
        return ObjectBrandingApiFp(this.configuration).brandingEditObjectV2(pkiBrandingID, brandingEditObjectV2Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Get the list of Branding to be used in a dropdown or autocomplete control.
     * @summary Retrieve Brandings and IDs
     * @param {BrandingGetAutocompleteV2SSelectorEnum} sSelector The type of Brandings to return
     * @param {BrandingGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBrandingApi
     */
    public brandingGetAutocompleteV2(sSelector: BrandingGetAutocompleteV2SSelectorEnum, eFilterActive?: BrandingGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig) {
        return ObjectBrandingApiFp(this.configuration).brandingGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eBrandingLogo | Default<br>JPEG<br>PNG | | eBrandingLogointerface | Default<br>JPEG<br>PNG |
     * @summary Retrieve Branding list
     * @param {BrandingGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
     * @param {number} [iRowMax] 
     * @param {number} [iRowOffset] 
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {string} [sFilter] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBrandingApi
     */
    public brandingGetListV1(eOrderBy?: BrandingGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig) {
        return ObjectBrandingApiFp(this.configuration).brandingGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Branding
     * @param {number} pkiBrandingID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBrandingApi
     */
    public brandingGetObjectV3(pkiBrandingID: number, options?: RawAxiosRequestConfig) {
        return ObjectBrandingApiFp(this.configuration).brandingGetObjectV3(pkiBrandingID, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const BrandingGetAutocompleteV2SSelectorEnum = {
    All: 'All'
} as const;
export type BrandingGetAutocompleteV2SSelectorEnum = typeof BrandingGetAutocompleteV2SSelectorEnum[keyof typeof BrandingGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const BrandingGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type BrandingGetAutocompleteV2EFilterActiveEnum = typeof BrandingGetAutocompleteV2EFilterActiveEnum[keyof typeof BrandingGetAutocompleteV2EFilterActiveEnum];
/**
 * @export
 */
export const BrandingGetListV1EOrderByEnum = {
    pkiBrandingID_ASC: 'pkiBrandingID_ASC',
    pkiBrandingID_DESC: 'pkiBrandingID_DESC',
    sBrandingDescriptionX_ASC: 'sBrandingDescriptionX_ASC',
    sBrandingDescriptionX_DESC: 'sBrandingDescriptionX_DESC',
    iBrandingColortext_ASC: 'iBrandingColortext_ASC',
    iBrandingColortext_DESC: 'iBrandingColortext_DESC',
    iBrandingColortextlinkbox_ASC: 'iBrandingColortextlinkbox_ASC',
    iBrandingColortextlinkbox_DESC: 'iBrandingColortextlinkbox_DESC',
    iBrandingColortextbutton_ASC: 'iBrandingColortextbutton_ASC',
    iBrandingColortextbutton_DESC: 'iBrandingColortextbutton_DESC',
    iBrandingColorbackground_ASC: 'iBrandingColorbackground_ASC',
    iBrandingColorbackground_DESC: 'iBrandingColorbackground_DESC',
    iBrandingColorbackgroundbutton_ASC: 'iBrandingColorbackgroundbutton_ASC',
    iBrandingColorbackgroundbutton_DESC: 'iBrandingColorbackgroundbutton_DESC',
    iBrandingColorbackgroundsmallbox_ASC: 'iBrandingColorbackgroundsmallbox_ASC',
    iBrandingColorbackgroundsmallbox_DESC: 'iBrandingColorbackgroundsmallbox_DESC',
    bBrandingIsactive_ASC: 'bBrandingIsactive_ASC',
    bBrandingIsactive_DESC: 'bBrandingIsactive_DESC'
} as const;
export type BrandingGetListV1EOrderByEnum = typeof BrandingGetListV1EOrderByEnum[keyof typeof BrandingGetListV1EOrderByEnum];
