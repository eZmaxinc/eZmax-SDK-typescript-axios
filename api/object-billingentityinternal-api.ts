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
import { BillingentityinternalCreateObjectV1Request } from '../model';
// @ts-ignore
import { BillingentityinternalCreateObjectV1Response } from '../model';
// @ts-ignore
import { BillingentityinternalEditObjectV1Request } from '../model';
// @ts-ignore
import { BillingentityinternalEditObjectV1Response } from '../model';
// @ts-ignore
import { BillingentityinternalGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { BillingentityinternalGetListV1Response } from '../model';
// @ts-ignore
import { BillingentityinternalGetObjectV2Response } from '../model';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectBillingentityinternalApi - axios parameter creator
 * @export
 */
export const ObjectBillingentityinternalApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Billingentityinternal
         * @param {BillingentityinternalCreateObjectV1Request} billingentityinternalCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalCreateObjectV1: async (billingentityinternalCreateObjectV1Request: BillingentityinternalCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'billingentityinternalCreateObjectV1Request' is not null or undefined
            assertParamExists('billingentityinternalCreateObjectV1', 'billingentityinternalCreateObjectV1Request', billingentityinternalCreateObjectV1Request)
            const localVarPath = `/1/object/billingentityinternal`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(billingentityinternalCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Edit an existing Billingentityinternal
         * @param {number} pkiBillingentityinternalID 
         * @param {BillingentityinternalEditObjectV1Request} billingentityinternalEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalEditObjectV1: async (pkiBillingentityinternalID: number, billingentityinternalEditObjectV1Request: BillingentityinternalEditObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiBillingentityinternalID' is not null or undefined
            assertParamExists('billingentityinternalEditObjectV1', 'pkiBillingentityinternalID', pkiBillingentityinternalID)
            // verify required parameter 'billingentityinternalEditObjectV1Request' is not null or undefined
            assertParamExists('billingentityinternalEditObjectV1', 'billingentityinternalEditObjectV1Request', billingentityinternalEditObjectV1Request)
            const localVarPath = `/1/object/billingentityinternal/{pkiBillingentityinternalID}`
                .replace(`{${"pkiBillingentityinternalID"}}`, encodeURIComponent(String(pkiBillingentityinternalID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(billingentityinternalEditObjectV1Request, localVarRequestOptions, configuration)

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
         * Get the list of Billingentityinternal to be used in a dropdown or autocomplete control.
         * @summary Retrieve Billingentityinternals and IDs
         * @param {'All'} sSelector The type of Billingentityinternals to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalGetAutocompleteV2: async (sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('billingentityinternalGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/billingentityinternal/getAutocomplete/{sSelector}`
                .replace(`{${"sSelector"}}`, encodeURIComponent(String(sSelector)));
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
         * @summary Retrieve Billingentityinternal list
         * @param {'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC'} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalGetListV1: async (eOrderBy?: 'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC', iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/billingentityinternal/getList`;
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
         * @summary Retrieve an existing Billingentityinternal
         * @param {number} pkiBillingentityinternalID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalGetObjectV2: async (pkiBillingentityinternalID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiBillingentityinternalID' is not null or undefined
            assertParamExists('billingentityinternalGetObjectV2', 'pkiBillingentityinternalID', pkiBillingentityinternalID)
            const localVarPath = `/2/object/billingentityinternal/{pkiBillingentityinternalID}`
                .replace(`{${"pkiBillingentityinternalID"}}`, encodeURIComponent(String(pkiBillingentityinternalID)));
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
 * ObjectBillingentityinternalApi - functional programming interface
 * @export
 */
export const ObjectBillingentityinternalApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectBillingentityinternalApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Billingentityinternal
         * @param {BillingentityinternalCreateObjectV1Request} billingentityinternalCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async billingentityinternalCreateObjectV1(billingentityinternalCreateObjectV1Request: BillingentityinternalCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BillingentityinternalCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.billingentityinternalCreateObjectV1(billingentityinternalCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Edit an existing Billingentityinternal
         * @param {number} pkiBillingentityinternalID 
         * @param {BillingentityinternalEditObjectV1Request} billingentityinternalEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async billingentityinternalEditObjectV1(pkiBillingentityinternalID: number, billingentityinternalEditObjectV1Request: BillingentityinternalEditObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BillingentityinternalEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.billingentityinternalEditObjectV1(pkiBillingentityinternalID, billingentityinternalEditObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * Get the list of Billingentityinternal to be used in a dropdown or autocomplete control.
         * @summary Retrieve Billingentityinternals and IDs
         * @param {'All'} sSelector The type of Billingentityinternals to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async billingentityinternalGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BillingentityinternalGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.billingentityinternalGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve Billingentityinternal list
         * @param {'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC'} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async billingentityinternalGetListV1(eOrderBy?: 'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC', iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BillingentityinternalGetListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.billingentityinternalGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Billingentityinternal
         * @param {number} pkiBillingentityinternalID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async billingentityinternalGetObjectV2(pkiBillingentityinternalID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BillingentityinternalGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.billingentityinternalGetObjectV2(pkiBillingentityinternalID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectBillingentityinternalApi - factory interface
 * @export
 */
export const ObjectBillingentityinternalApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectBillingentityinternalApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Billingentityinternal
         * @param {BillingentityinternalCreateObjectV1Request} billingentityinternalCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalCreateObjectV1(billingentityinternalCreateObjectV1Request: BillingentityinternalCreateObjectV1Request, options?: any): AxiosPromise<BillingentityinternalCreateObjectV1Response> {
            return localVarFp.billingentityinternalCreateObjectV1(billingentityinternalCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Billingentityinternal
         * @param {number} pkiBillingentityinternalID 
         * @param {BillingentityinternalEditObjectV1Request} billingentityinternalEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalEditObjectV1(pkiBillingentityinternalID: number, billingentityinternalEditObjectV1Request: BillingentityinternalEditObjectV1Request, options?: any): AxiosPromise<BillingentityinternalEditObjectV1Response> {
            return localVarFp.billingentityinternalEditObjectV1(pkiBillingentityinternalID, billingentityinternalEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * Get the list of Billingentityinternal to be used in a dropdown or autocomplete control.
         * @summary Retrieve Billingentityinternals and IDs
         * @param {'All'} sSelector The type of Billingentityinternals to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<BillingentityinternalGetAutocompleteV2Response> {
            return localVarFp.billingentityinternalGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Billingentityinternal list
         * @param {'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC'} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalGetListV1(eOrderBy?: 'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC', iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: any): AxiosPromise<BillingentityinternalGetListV1Response> {
            return localVarFp.billingentityinternalGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Billingentityinternal
         * @param {number} pkiBillingentityinternalID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        billingentityinternalGetObjectV2(pkiBillingentityinternalID: number, options?: any): AxiosPromise<BillingentityinternalGetObjectV2Response> {
            return localVarFp.billingentityinternalGetObjectV2(pkiBillingentityinternalID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectBillingentityinternalApi - object-oriented interface
 * @export
 * @class ObjectBillingentityinternalApi
 * @extends {BaseAPI}
 */
export class ObjectBillingentityinternalApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Billingentityinternal
     * @param {BillingentityinternalCreateObjectV1Request} billingentityinternalCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBillingentityinternalApi
     */
    public billingentityinternalCreateObjectV1(billingentityinternalCreateObjectV1Request: BillingentityinternalCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectBillingentityinternalApiFp(this.configuration).billingentityinternalCreateObjectV1(billingentityinternalCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Billingentityinternal
     * @param {number} pkiBillingentityinternalID 
     * @param {BillingentityinternalEditObjectV1Request} billingentityinternalEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBillingentityinternalApi
     */
    public billingentityinternalEditObjectV1(pkiBillingentityinternalID: number, billingentityinternalEditObjectV1Request: BillingentityinternalEditObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectBillingentityinternalApiFp(this.configuration).billingentityinternalEditObjectV1(pkiBillingentityinternalID, billingentityinternalEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Get the list of Billingentityinternal to be used in a dropdown or autocomplete control.
     * @summary Retrieve Billingentityinternals and IDs
     * @param {'All'} sSelector The type of Billingentityinternals to return
     * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBillingentityinternalApi
     */
    public billingentityinternalGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectBillingentityinternalApiFp(this.configuration).billingentityinternalGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Billingentityinternal list
     * @param {'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC'} [eOrderBy] Specify how you want the results to be sorted
     * @param {number} [iRowMax] 
     * @param {number} [iRowOffset] 
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {string} [sFilter] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBillingentityinternalApi
     */
    public billingentityinternalGetListV1(eOrderBy?: 'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC', iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: AxiosRequestConfig) {
        return ObjectBillingentityinternalApiFp(this.configuration).billingentityinternalGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Billingentityinternal
     * @param {number} pkiBillingentityinternalID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBillingentityinternalApi
     */
    public billingentityinternalGetObjectV2(pkiBillingentityinternalID: number, options?: AxiosRequestConfig) {
        return ObjectBillingentityinternalApiFp(this.configuration).billingentityinternalGetObjectV2(pkiBillingentityinternalID, options).then((request) => request(this.axios, this.basePath));
    }
}
