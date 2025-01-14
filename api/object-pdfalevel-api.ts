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
import { PdfalevelGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectPdfalevelApi - axios parameter creator
 * @export
 */
export const ObjectPdfalevelApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Pdfalevel to be used in a dropdown or autocomplete control.
         * @summary Retrieve Pdfalevels and IDs
         * @param {PdfalevelGetAutocompleteV2SSelectorEnum} sSelector The type of Pdfalevels to return
         * @param {PdfalevelGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        pdfalevelGetAutocompleteV2: async (sSelector: PdfalevelGetAutocompleteV2SSelectorEnum, eFilterActive?: PdfalevelGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('pdfalevelGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/pdfalevel/getAutocomplete/{sSelector}`
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
 * ObjectPdfalevelApi - functional programming interface
 * @export
 */
export const ObjectPdfalevelApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectPdfalevelApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Pdfalevel to be used in a dropdown or autocomplete control.
         * @summary Retrieve Pdfalevels and IDs
         * @param {PdfalevelGetAutocompleteV2SSelectorEnum} sSelector The type of Pdfalevels to return
         * @param {PdfalevelGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async pdfalevelGetAutocompleteV2(sSelector: PdfalevelGetAutocompleteV2SSelectorEnum, eFilterActive?: PdfalevelGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<PdfalevelGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.pdfalevelGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectPdfalevelApi.pdfalevelGetAutocompleteV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectPdfalevelApi - factory interface
 * @export
 */
export const ObjectPdfalevelApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectPdfalevelApiFp(configuration)
    return {
        /**
         * Get the list of Pdfalevel to be used in a dropdown or autocomplete control.
         * @summary Retrieve Pdfalevels and IDs
         * @param {PdfalevelGetAutocompleteV2SSelectorEnum} sSelector The type of Pdfalevels to return
         * @param {PdfalevelGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        pdfalevelGetAutocompleteV2(sSelector: PdfalevelGetAutocompleteV2SSelectorEnum, eFilterActive?: PdfalevelGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<PdfalevelGetAutocompleteV2Response> {
            return localVarFp.pdfalevelGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectPdfalevelApi - object-oriented interface
 * @export
 * @class ObjectPdfalevelApi
 * @extends {BaseAPI}
 */
export class ObjectPdfalevelApi extends BaseAPI {
    /**
     * Get the list of Pdfalevel to be used in a dropdown or autocomplete control.
     * @summary Retrieve Pdfalevels and IDs
     * @param {PdfalevelGetAutocompleteV2SSelectorEnum} sSelector The type of Pdfalevels to return
     * @param {PdfalevelGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectPdfalevelApi
     */
    public pdfalevelGetAutocompleteV2(sSelector: PdfalevelGetAutocompleteV2SSelectorEnum, eFilterActive?: PdfalevelGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig) {
        return ObjectPdfalevelApiFp(this.configuration).pdfalevelGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const PdfalevelGetAutocompleteV2SSelectorEnum = {
    All: 'All'
} as const;
export type PdfalevelGetAutocompleteV2SSelectorEnum = typeof PdfalevelGetAutocompleteV2SSelectorEnum[keyof typeof PdfalevelGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const PdfalevelGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type PdfalevelGetAutocompleteV2EFilterActiveEnum = typeof PdfalevelGetAutocompleteV2EFilterActiveEnum[keyof typeof PdfalevelGetAutocompleteV2EFilterActiveEnum];
