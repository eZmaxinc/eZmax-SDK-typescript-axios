/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
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
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectBrandingApi - axios parameter creator
 * @export
 */
export const ObjectBrandingApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Branding to be used in a dropdown or autocomplete control.
         * @summary Retrieve Brandings and IDs
         * @param {'All'} sSelector The type of Brandings to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingGetAutocompleteV1: async (sSelector: 'All', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('brandingGetAutocompleteV1', 'sSelector', sSelector)
            const localVarPath = `/1/object/branding/getAutocomplete/{sSelector}`
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

            if (sQuery !== undefined) {
                localVarQueryParameter['sQuery'] = sQuery;
            }

            if (acceptLanguage !== undefined && acceptLanguage !== null) {
		localVarHeaderParameter['Accept-Language'] = String(acceptLanguage);
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
 * ObjectBrandingApi - functional programming interface
 * @export
 */
export const ObjectBrandingApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectBrandingApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Branding to be used in a dropdown or autocomplete control.
         * @summary Retrieve Brandings and IDs
         * @param {'All'} sSelector The type of Brandings to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async brandingGetAutocompleteV1(sSelector: 'All', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonGetAutocompleteV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.brandingGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
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
         * Get the list of Branding to be used in a dropdown or autocomplete control.
         * @summary Retrieve Brandings and IDs
         * @param {'All'} sSelector The type of Brandings to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        brandingGetAutocompleteV1(sSelector: 'All', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<CommonGetAutocompleteV1Response> {
            return localVarFp.brandingGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
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
     * Get the list of Branding to be used in a dropdown or autocomplete control.
     * @summary Retrieve Brandings and IDs
     * @param {'All'} sSelector The type of Brandings to return
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBrandingApi
     */
    public brandingGetAutocompleteV1(sSelector: 'All', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectBrandingApiFp(this.configuration).brandingGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}
