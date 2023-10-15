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
import { UserlogintypeGetAutocompleteV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectUserlogintypeApi - axios parameter creator
 * @export
 */
export const ObjectUserlogintypeApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Userlogintype to be used in a dropdown or autocomplete control.
         * @summary Retrieve Userlogintypes and IDs
         * @param {UserlogintypeGetAutocompleteV2SSelectorEnum} sSelector The type of Userlogintypes to return
         * @param {UserlogintypeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userlogintypeGetAutocompleteV2: async (sSelector: UserlogintypeGetAutocompleteV2SSelectorEnum, eFilterActive?: UserlogintypeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('userlogintypeGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/userlogintype/getAutocomplete/{sSelector}`
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
 * ObjectUserlogintypeApi - functional programming interface
 * @export
 */
export const ObjectUserlogintypeApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectUserlogintypeApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Userlogintype to be used in a dropdown or autocomplete control.
         * @summary Retrieve Userlogintypes and IDs
         * @param {UserlogintypeGetAutocompleteV2SSelectorEnum} sSelector The type of Userlogintypes to return
         * @param {UserlogintypeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async userlogintypeGetAutocompleteV2(sSelector: UserlogintypeGetAutocompleteV2SSelectorEnum, eFilterActive?: UserlogintypeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UserlogintypeGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.userlogintypeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectUserlogintypeApi - factory interface
 * @export
 */
export const ObjectUserlogintypeApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectUserlogintypeApiFp(configuration)
    return {
        /**
         * Get the list of Userlogintype to be used in a dropdown or autocomplete control.
         * @summary Retrieve Userlogintypes and IDs
         * @param {UserlogintypeGetAutocompleteV2SSelectorEnum} sSelector The type of Userlogintypes to return
         * @param {UserlogintypeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userlogintypeGetAutocompleteV2(sSelector: UserlogintypeGetAutocompleteV2SSelectorEnum, eFilterActive?: UserlogintypeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<UserlogintypeGetAutocompleteV2Response> {
            return localVarFp.userlogintypeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectUserlogintypeApi - object-oriented interface
 * @export
 * @class ObjectUserlogintypeApi
 * @extends {BaseAPI}
 */
export class ObjectUserlogintypeApi extends BaseAPI {
    /**
     * Get the list of Userlogintype to be used in a dropdown or autocomplete control.
     * @summary Retrieve Userlogintypes and IDs
     * @param {UserlogintypeGetAutocompleteV2SSelectorEnum} sSelector The type of Userlogintypes to return
     * @param {UserlogintypeGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUserlogintypeApi
     */
    public userlogintypeGetAutocompleteV2(sSelector: UserlogintypeGetAutocompleteV2SSelectorEnum, eFilterActive?: UserlogintypeGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectUserlogintypeApiFp(this.configuration).userlogintypeGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const UserlogintypeGetAutocompleteV2SSelectorEnum = {
    All: 'All'
} as const;
export type UserlogintypeGetAutocompleteV2SSelectorEnum = typeof UserlogintypeGetAutocompleteV2SSelectorEnum[keyof typeof UserlogintypeGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const UserlogintypeGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type UserlogintypeGetAutocompleteV2EFilterActiveEnum = typeof UserlogintypeGetAutocompleteV2EFilterActiveEnum[keyof typeof UserlogintypeGetAutocompleteV2EFilterActiveEnum];
