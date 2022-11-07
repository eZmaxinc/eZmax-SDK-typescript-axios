/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
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
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { TaxassignmentGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectTaxassignmentApi - axios parameter creator
 * @export
 */
export const ObjectTaxassignmentApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Taxassignment to be used in a dropdown or autocomplete control.
         * @summary Retrieve Taxassignments and IDs
         * @param {'All' | 'AllButNonrecoverable'} sSelector The type of Taxassignments to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        taxassignmentGetAutocompleteV1: async (sSelector: 'All' | 'AllButNonrecoverable', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('taxassignmentGetAutocompleteV1', 'sSelector', sSelector)
            const localVarPath = `/1/object/taxassignment/getAutocomplete/{sSelector}`
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
         * Get the list of Taxassignment to be used in a dropdown or autocomplete control.
         * @summary Retrieve Taxassignments and IDs
         * @param {'All' | 'AllButNonrecoverable'} sSelector The type of Taxassignments to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        taxassignmentGetAutocompleteV2: async (sSelector: 'All' | 'AllButNonrecoverable', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('taxassignmentGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/taxassignment/getAutocomplete/{sSelector}`
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
    }
};

/**
 * ObjectTaxassignmentApi - functional programming interface
 * @export
 */
export const ObjectTaxassignmentApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectTaxassignmentApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Taxassignment to be used in a dropdown or autocomplete control.
         * @summary Retrieve Taxassignments and IDs
         * @param {'All' | 'AllButNonrecoverable'} sSelector The type of Taxassignments to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        async taxassignmentGetAutocompleteV1(sSelector: 'All' | 'AllButNonrecoverable', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonGetAutocompleteV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.taxassignmentGetAutocompleteV1(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * Get the list of Taxassignment to be used in a dropdown or autocomplete control.
         * @summary Retrieve Taxassignments and IDs
         * @param {'All' | 'AllButNonrecoverable'} sSelector The type of Taxassignments to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async taxassignmentGetAutocompleteV2(sSelector: 'All' | 'AllButNonrecoverable', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<TaxassignmentGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.taxassignmentGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectTaxassignmentApi - factory interface
 * @export
 */
export const ObjectTaxassignmentApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectTaxassignmentApiFp(configuration)
    return {
        /**
         * Get the list of Taxassignment to be used in a dropdown or autocomplete control.
         * @summary Retrieve Taxassignments and IDs
         * @param {'All' | 'AllButNonrecoverable'} sSelector The type of Taxassignments to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        taxassignmentGetAutocompleteV1(sSelector: 'All' | 'AllButNonrecoverable', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<CommonGetAutocompleteV1Response> {
            return localVarFp.taxassignmentGetAutocompleteV1(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
        /**
         * Get the list of Taxassignment to be used in a dropdown or autocomplete control.
         * @summary Retrieve Taxassignments and IDs
         * @param {'All' | 'AllButNonrecoverable'} sSelector The type of Taxassignments to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        taxassignmentGetAutocompleteV2(sSelector: 'All' | 'AllButNonrecoverable', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<TaxassignmentGetAutocompleteV2Response> {
            return localVarFp.taxassignmentGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectTaxassignmentApi - object-oriented interface
 * @export
 * @class ObjectTaxassignmentApi
 * @extends {BaseAPI}
 */
export class ObjectTaxassignmentApi extends BaseAPI {
    /**
     * Get the list of Taxassignment to be used in a dropdown or autocomplete control.
     * @summary Retrieve Taxassignments and IDs
     * @param {'All' | 'AllButNonrecoverable'} sSelector The type of Taxassignments to return
     * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @deprecated
     * @throws {RequiredError}
     * @memberof ObjectTaxassignmentApi
     */
    public taxassignmentGetAutocompleteV1(sSelector: 'All' | 'AllButNonrecoverable', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectTaxassignmentApiFp(this.configuration).taxassignmentGetAutocompleteV1(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Get the list of Taxassignment to be used in a dropdown or autocomplete control.
     * @summary Retrieve Taxassignments and IDs
     * @param {'All' | 'AllButNonrecoverable'} sSelector The type of Taxassignments to return
     * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectTaxassignmentApi
     */
    public taxassignmentGetAutocompleteV2(sSelector: 'All' | 'AllButNonrecoverable', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectTaxassignmentApiFp(this.configuration).taxassignmentGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}
