/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import globalAxios, { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';
import { Configuration } from '../configuration';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { CommonGetAutocompleteV1Response } from '../model';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { EzmaxinvoicingGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { EzmaxinvoicingGetObjectV1Response } from '../model';
// @ts-ignore
import { EzmaxinvoicingGetObjectV2Response } from '../model';
// @ts-ignore
import { EzmaxinvoicingGetProvisionalV1Response } from '../model';
// @ts-ignore
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzmaxinvoicingApi - axios parameter creator
 * @export
 */
export const ObjectEzmaxinvoicingApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Ezmaxinvoicing to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezmaxinvoicings and IDs
         * @param {'All'} sSelector The type of Ezmaxinvoicings to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display. Active is the default value.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetAutocompleteV1: async (sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('ezmaxinvoicingGetAutocompleteV1', 'sSelector', sSelector)
            const localVarPath = `/1/object/ezmaxinvoicing/getAutocomplete/{sSelector}`
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
         * Get the list of Ezmaxinvoicing to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezmaxinvoicings and IDs
         * @param {'All'} sSelector The type of Ezmaxinvoicings to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetAutocompleteV2: async (sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('ezmaxinvoicingGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/ezmaxinvoicing/getAutocomplete/{sSelector}`
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
         * @summary Retrieve an existing Ezmaxinvoicing
         * @param {number} pkiEzmaxinvoicingID 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetObjectV1: async (pkiEzmaxinvoicingID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzmaxinvoicingID' is not null or undefined
            assertParamExists('ezmaxinvoicingGetObjectV1', 'pkiEzmaxinvoicingID', pkiEzmaxinvoicingID)
            const localVarPath = `/1/object/ezmaxinvoicing/{pkiEzmaxinvoicingID}`
                .replace(`{${"pkiEzmaxinvoicingID"}}`, encodeURIComponent(String(pkiEzmaxinvoicingID)));
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
         * @summary Retrieve an existing Ezmaxinvoicing
         * @param {number} pkiEzmaxinvoicingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetObjectV2: async (pkiEzmaxinvoicingID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzmaxinvoicingID' is not null or undefined
            assertParamExists('ezmaxinvoicingGetObjectV2', 'pkiEzmaxinvoicingID', pkiEzmaxinvoicingID)
            const localVarPath = `/2/object/ezmaxinvoicing/{pkiEzmaxinvoicingID}`
                .replace(`{${"pkiEzmaxinvoicingID"}}`, encodeURIComponent(String(pkiEzmaxinvoicingID)));
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
         * @summary Retrieve provisional Ezmaxinvoicing
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetProvisionalV1: async (options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/ezmaxinvoicing/getProvisional`;
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
 * ObjectEzmaxinvoicingApi - functional programming interface
 * @export
 */
export const ObjectEzmaxinvoicingApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzmaxinvoicingApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Ezmaxinvoicing to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezmaxinvoicings and IDs
         * @param {'All'} sSelector The type of Ezmaxinvoicings to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display. Active is the default value.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        async ezmaxinvoicingGetAutocompleteV1(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonGetAutocompleteV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezmaxinvoicingGetAutocompleteV1(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * Get the list of Ezmaxinvoicing to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezmaxinvoicings and IDs
         * @param {'All'} sSelector The type of Ezmaxinvoicings to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezmaxinvoicingGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzmaxinvoicingGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezmaxinvoicingGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezmaxinvoicing
         * @param {number} pkiEzmaxinvoicingID 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        async ezmaxinvoicingGetObjectV1(pkiEzmaxinvoicingID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzmaxinvoicingGetObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezmaxinvoicingGetObjectV1(pkiEzmaxinvoicingID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezmaxinvoicing
         * @param {number} pkiEzmaxinvoicingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezmaxinvoicingGetObjectV2(pkiEzmaxinvoicingID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzmaxinvoicingGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezmaxinvoicingGetObjectV2(pkiEzmaxinvoicingID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve provisional Ezmaxinvoicing
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezmaxinvoicingGetProvisionalV1(options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzmaxinvoicingGetProvisionalV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezmaxinvoicingGetProvisionalV1(options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzmaxinvoicingApi - factory interface
 * @export
 */
export const ObjectEzmaxinvoicingApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzmaxinvoicingApiFp(configuration)
    return {
        /**
         * Get the list of Ezmaxinvoicing to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezmaxinvoicings and IDs
         * @param {'All'} sSelector The type of Ezmaxinvoicings to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display. Active is the default value.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetAutocompleteV1(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<CommonGetAutocompleteV1Response> {
            return localVarFp.ezmaxinvoicingGetAutocompleteV1(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
        /**
         * Get the list of Ezmaxinvoicing to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezmaxinvoicings and IDs
         * @param {'All'} sSelector The type of Ezmaxinvoicings to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<EzmaxinvoicingGetAutocompleteV2Response> {
            return localVarFp.ezmaxinvoicingGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezmaxinvoicing
         * @param {number} pkiEzmaxinvoicingID 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetObjectV1(pkiEzmaxinvoicingID: number, options?: any): AxiosPromise<EzmaxinvoicingGetObjectV1Response> {
            return localVarFp.ezmaxinvoicingGetObjectV1(pkiEzmaxinvoicingID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezmaxinvoicing
         * @param {number} pkiEzmaxinvoicingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetObjectV2(pkiEzmaxinvoicingID: number, options?: any): AxiosPromise<EzmaxinvoicingGetObjectV2Response> {
            return localVarFp.ezmaxinvoicingGetObjectV2(pkiEzmaxinvoicingID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve provisional Ezmaxinvoicing
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezmaxinvoicingGetProvisionalV1(options?: any): AxiosPromise<EzmaxinvoicingGetProvisionalV1Response> {
            return localVarFp.ezmaxinvoicingGetProvisionalV1(options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzmaxinvoicingApi - object-oriented interface
 * @export
 * @class ObjectEzmaxinvoicingApi
 * @extends {BaseAPI}
 */
export class ObjectEzmaxinvoicingApi extends BaseAPI {
    /**
     * Get the list of Ezmaxinvoicing to be used in a dropdown or autocomplete control.
     * @summary Retrieve Ezmaxinvoicings and IDs
     * @param {'All'} sSelector The type of Ezmaxinvoicings to return
     * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display. Active is the default value.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @deprecated
     * @throws {RequiredError}
     * @memberof ObjectEzmaxinvoicingApi
     */
    public ezmaxinvoicingGetAutocompleteV1(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectEzmaxinvoicingApiFp(this.configuration).ezmaxinvoicingGetAutocompleteV1(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Get the list of Ezmaxinvoicing to be used in a dropdown or autocomplete control.
     * @summary Retrieve Ezmaxinvoicings and IDs
     * @param {'All'} sSelector The type of Ezmaxinvoicings to return
     * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzmaxinvoicingApi
     */
    public ezmaxinvoicingGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectEzmaxinvoicingApiFp(this.configuration).ezmaxinvoicingGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezmaxinvoicing
     * @param {number} pkiEzmaxinvoicingID 
     * @param {*} [options] Override http request option.
     * @deprecated
     * @throws {RequiredError}
     * @memberof ObjectEzmaxinvoicingApi
     */
    public ezmaxinvoicingGetObjectV1(pkiEzmaxinvoicingID: number, options?: AxiosRequestConfig) {
        return ObjectEzmaxinvoicingApiFp(this.configuration).ezmaxinvoicingGetObjectV1(pkiEzmaxinvoicingID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezmaxinvoicing
     * @param {number} pkiEzmaxinvoicingID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzmaxinvoicingApi
     */
    public ezmaxinvoicingGetObjectV2(pkiEzmaxinvoicingID: number, options?: AxiosRequestConfig) {
        return ObjectEzmaxinvoicingApiFp(this.configuration).ezmaxinvoicingGetObjectV2(pkiEzmaxinvoicingID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve provisional Ezmaxinvoicing
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzmaxinvoicingApi
     */
    public ezmaxinvoicingGetProvisionalV1(options?: AxiosRequestConfig) {
        return ObjectEzmaxinvoicingApiFp(this.configuration).ezmaxinvoicingGetProvisionalV1(options).then((request) => request(this.axios, this.basePath));
    }
}
