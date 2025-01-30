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
import type { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import type { PeriodGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectPeriodApi - axios parameter creator
 * @export
 */
export const ObjectPeriodApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Period to be used in a dropdown or autocomplete control.
         * @summary Retrieve Periods and IDs
         * @param {PeriodGetAutocompleteV2SSelectorEnum} sSelector The type of Periods to return
         * @param {PeriodGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        periodGetAutocompleteV2: async (sSelector: PeriodGetAutocompleteV2SSelectorEnum, eFilterActive?: PeriodGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('periodGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/period/getAutocomplete/{sSelector}`
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
 * ObjectPeriodApi - functional programming interface
 * @export
 */
export const ObjectPeriodApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectPeriodApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Period to be used in a dropdown or autocomplete control.
         * @summary Retrieve Periods and IDs
         * @param {PeriodGetAutocompleteV2SSelectorEnum} sSelector The type of Periods to return
         * @param {PeriodGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async periodGetAutocompleteV2(sSelector: PeriodGetAutocompleteV2SSelectorEnum, eFilterActive?: PeriodGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<PeriodGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.periodGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectPeriodApi.periodGetAutocompleteV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectPeriodApi - factory interface
 * @export
 */
export const ObjectPeriodApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectPeriodApiFp(configuration)
    return {
        /**
         * Get the list of Period to be used in a dropdown or autocomplete control.
         * @summary Retrieve Periods and IDs
         * @param {PeriodGetAutocompleteV2SSelectorEnum} sSelector The type of Periods to return
         * @param {PeriodGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        periodGetAutocompleteV2(sSelector: PeriodGetAutocompleteV2SSelectorEnum, eFilterActive?: PeriodGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): AxiosPromise<PeriodGetAutocompleteV2Response> {
            return localVarFp.periodGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectPeriodApi - object-oriented interface
 * @export
 * @class ObjectPeriodApi
 * @extends {BaseAPI}
 */
export class ObjectPeriodApi extends BaseAPI {
    /**
     * Get the list of Period to be used in a dropdown or autocomplete control.
     * @summary Retrieve Periods and IDs
     * @param {PeriodGetAutocompleteV2SSelectorEnum} sSelector The type of Periods to return
     * @param {PeriodGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectPeriodApi
     */
    public periodGetAutocompleteV2(sSelector: PeriodGetAutocompleteV2SSelectorEnum, eFilterActive?: PeriodGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig) {
        return ObjectPeriodApiFp(this.configuration).periodGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const PeriodGetAutocompleteV2SSelectorEnum = {
    ActiveNormal: 'ActiveNormal',
    ActiveNormalAndEndOfYear: 'ActiveNormalAndEndOfYear',
    AllNormal: 'AllNormal',
    AllNormalAndEndOfYear: 'AllNormalAndEndOfYear'
} as const;
export type PeriodGetAutocompleteV2SSelectorEnum = typeof PeriodGetAutocompleteV2SSelectorEnum[keyof typeof PeriodGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const PeriodGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type PeriodGetAutocompleteV2EFilterActiveEnum = typeof PeriodGetAutocompleteV2EFilterActiveEnum[keyof typeof PeriodGetAutocompleteV2EFilterActiveEnum];
