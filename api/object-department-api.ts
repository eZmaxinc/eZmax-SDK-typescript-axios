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
import type { DepartmentGetAutocompleteV2Response } from '../model';
// @ts-ignore
import type { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectDepartmentApi - axios parameter creator
 * @export
 */
export const ObjectDepartmentApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Department to be used in a dropdown or autocomplete control.
         * @summary Retrieve Departments and IDs
         * @param {DepartmentGetAutocompleteV2SSelectorEnum} sSelector The type of Departments to return
         * @param {DepartmentGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        departmentGetAutocompleteV2: async (sSelector: DepartmentGetAutocompleteV2SSelectorEnum, eFilterActive?: DepartmentGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('departmentGetAutocompleteV2', 'sSelector', sSelector)
            const localVarPath = `/2/object/department/getAutocomplete/{sSelector}`
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
 * ObjectDepartmentApi - functional programming interface
 * @export
 */
export const ObjectDepartmentApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectDepartmentApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Department to be used in a dropdown or autocomplete control.
         * @summary Retrieve Departments and IDs
         * @param {DepartmentGetAutocompleteV2SSelectorEnum} sSelector The type of Departments to return
         * @param {DepartmentGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async departmentGetAutocompleteV2(sSelector: DepartmentGetAutocompleteV2SSelectorEnum, eFilterActive?: DepartmentGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DepartmentGetAutocompleteV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.departmentGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectDepartmentApi.departmentGetAutocompleteV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectDepartmentApi - factory interface
 * @export
 */
export const ObjectDepartmentApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectDepartmentApiFp(configuration)
    return {
        /**
         * Get the list of Department to be used in a dropdown or autocomplete control.
         * @summary Retrieve Departments and IDs
         * @param {DepartmentGetAutocompleteV2SSelectorEnum} sSelector The type of Departments to return
         * @param {DepartmentGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        departmentGetAutocompleteV2(sSelector: DepartmentGetAutocompleteV2SSelectorEnum, eFilterActive?: DepartmentGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig): AxiosPromise<DepartmentGetAutocompleteV2Response> {
            return localVarFp.departmentGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectDepartmentApi - object-oriented interface
 * @export
 * @class ObjectDepartmentApi
 * @extends {BaseAPI}
 */
export class ObjectDepartmentApi extends BaseAPI {
    /**
     * Get the list of Department to be used in a dropdown or autocomplete control.
     * @summary Retrieve Departments and IDs
     * @param {DepartmentGetAutocompleteV2SSelectorEnum} sSelector The type of Departments to return
     * @param {DepartmentGetAutocompleteV2EFilterActiveEnum} [eFilterActive] Specify which results we want to display.
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectDepartmentApi
     */
    public departmentGetAutocompleteV2(sSelector: DepartmentGetAutocompleteV2SSelectorEnum, eFilterActive?: DepartmentGetAutocompleteV2EFilterActiveEnum, sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: RawAxiosRequestConfig) {
        return ObjectDepartmentApiFp(this.configuration).departmentGetAutocompleteV2(sSelector, eFilterActive, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const DepartmentGetAutocompleteV2SSelectorEnum = {
    All: 'All',
    AllButDepartmentZero: 'AllButDepartmentZero',
    Company: 'Company',
    CompanyButDepartmentZero: 'CompanyButDepartmentZero'
} as const;
export type DepartmentGetAutocompleteV2SSelectorEnum = typeof DepartmentGetAutocompleteV2SSelectorEnum[keyof typeof DepartmentGetAutocompleteV2SSelectorEnum];
/**
 * @export
 */
export const DepartmentGetAutocompleteV2EFilterActiveEnum = {
    All: 'All',
    Active: 'Active',
    Inactive: 'Inactive'
} as const;
export type DepartmentGetAutocompleteV2EFilterActiveEnum = typeof DepartmentGetAutocompleteV2EFilterActiveEnum[keyof typeof DepartmentGetAutocompleteV2EFilterActiveEnum];
