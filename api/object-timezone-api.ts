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
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { TimezoneGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectTimezoneApi - axios parameter creator
 * @export
 */
export const ObjectTimezoneApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Timezone to be used in a dropdown or autocomplete control.
         * @summary Retrieve Timezones and IDs
         * @param {TimezoneGetAutocompleteV2SSelectorEnum} sSelector The type of Timezones to return
         * @param {TimezoneGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        timezoneGetAutocompleteV2: async (sSelector: TimezoneGetAutocompleteV2SSelectorEnum, eFilterActive?: TimezoneGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('timezoneGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/timezone/getAutocomplete/{sSelector}`
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
    }
};

/**
 * ObjectTimezoneApi - functional programming interface
 * @export
 */
export const ObjectTimezoneApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectTimezoneApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Timezone to be used in a dropdown or autocomplete control.
         * @summary Retrieve Timezones and IDs
         * @param {TimezoneGetAutocompleteV2SSelectorEnum} sSelector The type of Timezones to return
         * @param {TimezoneGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async timezoneGetAutocompleteV2(sSelector: TimezoneGetAutocompleteV2SSelectorEnum, eFilterActive?: TimezoneGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<TimezoneGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.timezoneGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectTimezoneApi.timezoneGetAutocompleteV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectTimezoneApi - factory interface
 * @export
 */
export const ObjectTimezoneApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectTimezoneApiFp(configuration)
    return {
        /**
         * Get the list of Timezone to be used in a dropdown or autocomplete control.
         * @summary Retrieve Timezones and IDs
         * @param {TimezoneGetAutocompleteV2SSelectorEnum} sSelector The type of Timezones to return
         * @param {TimezoneGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        timezoneGetAutocompleteV2(sSelector: TimezoneGetAutocompleteV2SSelectorEnum, eFilterActive?: TimezoneGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<TimezoneGetAutocompleteV2Response> {
            return localVarFp.timezoneGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectTimezoneApi - object-oriented interface
 * @export
 * @class ObjectTimezoneApi
 * @extends {BaseAPI}
 */
export class ObjectTimezoneApi extends BaseAPI {
    /**
     * Get the list of Timezone to be used in a dropdown or autocomplete control.
     * @summary Retrieve Timezones and IDs
     * @param {TimezoneGetAutocompleteV2SSelectorEnum} sSelector The type of Timezones to return
     * @param {TimezoneGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectTimezoneApi
     */
    public timezoneGetAutocompleteV2(sSelector: TimezoneGetAutocompleteV2SSelectorEnum, eFilterActive?: TimezoneGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig) {
        return ObjectTimezoneApiFp(this.configuration).timezoneGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const TimezoneGetAutocompleteV2SSelectorEnum = {
    All: 'All',
    Active: 'Active'
} as const;
export type TimezoneGetAutocompleteV2SSelectorEnum = typeof TimezoneGetAutocompleteV2SSelectorEnum[keyof typeof TimezoneGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const TimezoneGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type TimezoneGetAutocompleteV2EFilterActiveEnum = typeof TimezoneGetAutocompleteV2EFilterActiveEnum[keyof typeof TimezoneGetAutocompleteV2EFilterActiveEnum];
