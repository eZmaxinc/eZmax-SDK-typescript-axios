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
import { FontGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectFontApi - axios parameter creator
 * @export
 */
export const ObjectFontApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Font to be used in a dropdown or autocomplete control.
         * @summary Retrieve Fonts and IDs
         * @param {'All'} sSelector The type of Fonts to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        fontGetAutocompleteV2: async (sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('fontGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/font/getAutocomplete/{sSelector}`
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
 * ObjectFontApi - functional programming interface
 * @export
 */
export const ObjectFontApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectFontApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Font to be used in a dropdown or autocomplete control.
         * @summary Retrieve Fonts and IDs
         * @param {'All'} sSelector The type of Fonts to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async fontGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<FontGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.fontGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectFontApi - factory interface
 * @export
 */
export const ObjectFontApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectFontApiFp(configuration)
    return {
        /**
         * Get the list of Font to be used in a dropdown or autocomplete control.
         * @summary Retrieve Fonts and IDs
         * @param {'All'} sSelector The type of Fonts to return
         * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        fontGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<FontGetAutocompleteV2Response> {
            return localVarFp.fontGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectFontApi - object-oriented interface
 * @export
 * @class ObjectFontApi
 * @extends {BaseAPI}
 */
export class ObjectFontApi extends BaseAPI {
    /**
     * Get the list of Font to be used in a dropdown or autocomplete control.
     * @summary Retrieve Fonts and IDs
     * @param {'All'} sSelector The type of Fonts to return
     * @param {'All' | 'Active' | 'Inactive'} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectFontApi
     */
    public fontGetAutocompleteV2(sSelector: 'All', eFilterActive?: 'All' | 'Active' | 'Inactive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectFontApiFp(this.configuration).fontGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}
