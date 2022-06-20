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
 * ObjectUserApi - axios parameter creator
 * @export
 */
export const ObjectUserApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of User to be used in a dropdown or autocomplete control.
         * @summary Retrieve Users and IDs
         * @param {'All' | 'AllActive'} sSelector The type of Users to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userGetAutocompleteV1: async (sSelector: 'All' | 'AllActive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('userGetAutocompleteV1', 'sSelector', sSelector)
            const localVarPath = `/1/object/user/getAutocomplete/{sSelector}`
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
 * ObjectUserApi - functional programming interface
 * @export
 */
export const ObjectUserApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectUserApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of User to be used in a dropdown or autocomplete control.
         * @summary Retrieve Users and IDs
         * @param {'All' | 'AllActive'} sSelector The type of Users to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async userGetAutocompleteV1(sSelector: 'All' | 'AllActive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonGetAutocompleteV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.userGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectUserApi - factory interface
 * @export
 */
export const ObjectUserApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectUserApiFp(configuration)
    return {
        /**
         * Get the list of User to be used in a dropdown or autocomplete control.
         * @summary Retrieve Users and IDs
         * @param {'All' | 'AllActive'} sSelector The type of Users to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userGetAutocompleteV1(sSelector: 'All' | 'AllActive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<CommonGetAutocompleteV1Response> {
            return localVarFp.userGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectUserApi - object-oriented interface
 * @export
 * @class ObjectUserApi
 * @extends {BaseAPI}
 */
export class ObjectUserApi extends BaseAPI {
    /**
     * Get the list of User to be used in a dropdown or autocomplete control.
     * @summary Retrieve Users and IDs
     * @param {'All' | 'AllActive'} sSelector The type of Users to return
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectUserApi
     */
    public userGetAutocompleteV1(sSelector: 'All' | 'AllActive', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectUserApiFp(this.configuration).userGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }
}
