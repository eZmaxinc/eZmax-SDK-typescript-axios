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
import { FranchiseofficeGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectFranchiseofficeApi - axios parameter creator
 * @export
 */
export const ObjectFranchiseofficeApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Franchiseoffice to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchiseoffices and IDs
         * @param {FranchiseofficeGetAutocompleteV2SSelectorEnum} sSelector The type of Franchiseoffices to return
         * @param {FranchiseofficeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchiseofficeGetAutocompleteV2: async (sSelector: FranchiseofficeGetAutocompleteV2SSelectorEnum, eFilterActive?: FranchiseofficeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('franchiseofficeGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/franchiseoffice/getAutocomplete/{sSelector}`
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
 * ObjectFranchiseofficeApi - functional programming interface
 * @export
 */
export const ObjectFranchiseofficeApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectFranchiseofficeApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Franchiseoffice to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchiseoffices and IDs
         * @param {FranchiseofficeGetAutocompleteV2SSelectorEnum} sSelector The type of Franchiseoffices to return
         * @param {FranchiseofficeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async franchiseofficeGetAutocompleteV2(sSelector: FranchiseofficeGetAutocompleteV2SSelectorEnum, eFilterActive?: FranchiseofficeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<FranchiseofficeGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.franchiseofficeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectFranchiseofficeApi - factory interface
 * @export
 */
export const ObjectFranchiseofficeApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectFranchiseofficeApiFp(configuration)
    return {
        /**
         * Get the list of Franchiseoffice to be used in a dropdown or autocomplete control.
         * @summary Retrieve Franchiseoffices and IDs
         * @param {FranchiseofficeGetAutocompleteV2SSelectorEnum} sSelector The type of Franchiseoffices to return
         * @param {FranchiseofficeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchiseofficeGetAutocompleteV2(sSelector: FranchiseofficeGetAutocompleteV2SSelectorEnum, eFilterActive?: FranchiseofficeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<FranchiseofficeGetAutocompleteV2Response> {
            return localVarFp.franchiseofficeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectFranchiseofficeApi - object-oriented interface
 * @export
 * @class ObjectFranchiseofficeApi
 * @extends {BaseAPI}
 */
export class ObjectFranchiseofficeApi extends BaseAPI {
    /**
     * Get the list of Franchiseoffice to be used in a dropdown or autocomplete control.
     * @summary Retrieve Franchiseoffices and IDs
     * @param {FranchiseofficeGetAutocompleteV2SSelectorEnum} sSelector The type of Franchiseoffices to return
     * @param {FranchiseofficeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectFranchiseofficeApi
     */
    public franchiseofficeGetAutocompleteV2(sSelector: FranchiseofficeGetAutocompleteV2SSelectorEnum, eFilterActive?: FranchiseofficeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectFranchiseofficeApiFp(this.configuration).franchiseofficeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const FranchiseofficeGetAutocompleteV2SSelectorEnum = {
    All: 'All'
} as const;
export type FranchiseofficeGetAutocompleteV2SSelectorEnum = typeof FranchiseofficeGetAutocompleteV2SSelectorEnum[keyof typeof FranchiseofficeGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const FranchiseofficeGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type FranchiseofficeGetAutocompleteV2EFilterActiveEnum = typeof FranchiseofficeGetAutocompleteV2EFilterActiveEnum[keyof typeof FranchiseofficeGetAutocompleteV2EFilterActiveEnum];
