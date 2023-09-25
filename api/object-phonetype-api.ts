/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
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
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { PhonetypeGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectPhonetypeApi - axios parameter creator
 * @export
 */
export const ObjectPhonetypeApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Phonetype to be used in a dropdown or autocomplete control.
         * @summary Retrieve Phonetypes and IDs
         * @param {PhonetypeGetAutocompleteV2SSelectorEnum} sSelector The type of Phonetypes to return
         * @param {PhonetypeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        phonetypeGetAutocompleteV2: async (sSelector: PhonetypeGetAutocompleteV2SSelectorEnum, eFilterActive?: PhonetypeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('phonetypeGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/phonetype/getAutocomplete/{sSelector}`
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
 * ObjectPhonetypeApi - functional programming interface
 * @export
 */
export const ObjectPhonetypeApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectPhonetypeApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Phonetype to be used in a dropdown or autocomplete control.
         * @summary Retrieve Phonetypes and IDs
         * @param {PhonetypeGetAutocompleteV2SSelectorEnum} sSelector The type of Phonetypes to return
         * @param {PhonetypeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async phonetypeGetAutocompleteV2(sSelector: PhonetypeGetAutocompleteV2SSelectorEnum, eFilterActive?: PhonetypeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<PhonetypeGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.phonetypeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectPhonetypeApi - factory interface
 * @export
 */
export const ObjectPhonetypeApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectPhonetypeApiFp(configuration)
    return {
        /**
         * Get the list of Phonetype to be used in a dropdown or autocomplete control.
         * @summary Retrieve Phonetypes and IDs
         * @param {PhonetypeGetAutocompleteV2SSelectorEnum} sSelector The type of Phonetypes to return
         * @param {PhonetypeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        phonetypeGetAutocompleteV2(sSelector: PhonetypeGetAutocompleteV2SSelectorEnum, eFilterActive?: PhonetypeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<PhonetypeGetAutocompleteV2Response> {
            return localVarFp.phonetypeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectPhonetypeApi - object-oriented interface
 * @export
 * @class ObjectPhonetypeApi
 * @extends {BaseAPI}
 */
export class ObjectPhonetypeApi extends BaseAPI {
    /**
     * Get the list of Phonetype to be used in a dropdown or autocomplete control.
     * @summary Retrieve Phonetypes and IDs
     * @param {PhonetypeGetAutocompleteV2SSelectorEnum} sSelector The type of Phonetypes to return
     * @param {PhonetypeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectPhonetypeApi
     */
    public phonetypeGetAutocompleteV2(sSelector: PhonetypeGetAutocompleteV2SSelectorEnum, eFilterActive?: PhonetypeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectPhonetypeApiFp(this.configuration).phonetypeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const PhonetypeGetAutocompleteV2SSelectorEnum = {
    All: 'All'
} as const;
export type PhonetypeGetAutocompleteV2SSelectorEnum = typeof PhonetypeGetAutocompleteV2SSelectorEnum[keyof typeof PhonetypeGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const PhonetypeGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type PhonetypeGetAutocompleteV2EFilterActiveEnum = typeof PhonetypeGetAutocompleteV2EFilterActiveEnum[keyof typeof PhonetypeGetAutocompleteV2EFilterActiveEnum];
