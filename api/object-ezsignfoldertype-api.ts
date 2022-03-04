/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
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
import { CommonResponseError } from '../model';
// @ts-ignore
import { EzsignfoldertypeGetListV1Response } from '../model';
// @ts-ignore
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignfoldertypeApi - axios parameter creator
 * @export
 */
export const ObjectEzsignfoldertypeApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Get the list of Ezsignfoldertypes to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezsignfoldertypes and IDs
         * @param {'Active' | 'All'} sSelector The type of Ezsignfoldertypes to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldertypeGetAutocompleteV1: async (sSelector: 'Active' | 'All', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'sSelector' is not null or undefined
            assertParamExists('ezsignfoldertypeGetAutocompleteV1', 'sSelector', sSelector)
            const localVarPath = `/1/object/ezsignfoldertype/getAutocomplete/{sSelector}`
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
        /**
         * Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsignfoldertypePrivacylevel | User<br>Usergroup |
         * @summary Retrieve Ezsignfoldertype list
         * @param {'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC'} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldertypeGetListV1: async (eOrderBy?: 'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC', iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/ezsignfoldertype/getList`;
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

            if (eOrderBy !== undefined) {
                localVarQueryParameter['eOrderBy'] = eOrderBy;
            }

            if (iRowMax !== undefined) {
                localVarQueryParameter['iRowMax'] = iRowMax;
            }

            if (iRowOffset !== undefined) {
                localVarQueryParameter['iRowOffset'] = iRowOffset;
            }

            if (sFilter !== undefined) {
                localVarQueryParameter['sFilter'] = sFilter;
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
 * ObjectEzsignfoldertypeApi - functional programming interface
 * @export
 */
export const ObjectEzsignfoldertypeApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignfoldertypeApiAxiosParamCreator(configuration)
    return {
        /**
         * Get the list of Ezsignfoldertypes to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezsignfoldertypes and IDs
         * @param {'Active' | 'All'} sSelector The type of Ezsignfoldertypes to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldertypeGetAutocompleteV1(sSelector: 'Active' | 'All', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonGetAutocompleteV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignfoldertypeGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsignfoldertypePrivacylevel | User<br>Usergroup |
         * @summary Retrieve Ezsignfoldertype list
         * @param {'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC'} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldertypeGetListV1(eOrderBy?: 'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC', iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldertypeGetListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignfoldertypeGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsignfoldertypeApi - factory interface
 * @export
 */
export const ObjectEzsignfoldertypeApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignfoldertypeApiFp(configuration)
    return {
        /**
         * Get the list of Ezsignfoldertypes to be used in a dropdown or autocomplete control.
         * @summary Retrieve Ezsignfoldertypes and IDs
         * @param {'Active' | 'All'} sSelector The type of Ezsignfoldertypes to return
         * @param {string} [sQuery] Allow to filter the returned results
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldertypeGetAutocompleteV1(sSelector: 'Active' | 'All', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: any): AxiosPromise<CommonGetAutocompleteV1Response> {
            return localVarFp.ezsignfoldertypeGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options).then((request) => request(axios, basePath));
        },
        /**
         * Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsignfoldertypePrivacylevel | User<br>Usergroup |
         * @summary Retrieve Ezsignfoldertype list
         * @param {'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC'} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldertypeGetListV1(eOrderBy?: 'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC', iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: any): AxiosPromise<EzsignfoldertypeGetListV1Response> {
            return localVarFp.ezsignfoldertypeGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignfoldertypeApi - object-oriented interface
 * @export
 * @class ObjectEzsignfoldertypeApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignfoldertypeApi extends BaseAPI {
    /**
     * Get the list of Ezsignfoldertypes to be used in a dropdown or autocomplete control.
     * @summary Retrieve Ezsignfoldertypes and IDs
     * @param {'Active' | 'All'} sSelector The type of Ezsignfoldertypes to return
     * @param {string} [sQuery] Allow to filter the returned results
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldertypeApi
     */
    public ezsignfoldertypeGetAutocompleteV1(sSelector: 'Active' | 'All', sQuery?: string, acceptLanguage?: HeaderAcceptLanguage, options?: AxiosRequestConfig) {
        return ObjectEzsignfoldertypeApiFp(this.configuration).ezsignfoldertypeGetAutocompleteV1(sSelector, sQuery, acceptLanguage, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsignfoldertypePrivacylevel | User<br>Usergroup |
     * @summary Retrieve Ezsignfoldertype list
     * @param {'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC'} [eOrderBy] Specify how you want the results to be sorted
     * @param {number} [iRowMax] 
     * @param {number} [iRowOffset] 
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {string} [sFilter] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldertypeApi
     */
    public ezsignfoldertypeGetListV1(eOrderBy?: 'pkiEzsignfoldertypeID_ASC' | 'pkiEzsignfoldertypeID_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'bEzsignfoldertypeIsactive_ASC' | 'bEzsignfoldertypeIsactive_DESC', iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: AxiosRequestConfig) {
        return ObjectEzsignfoldertypeApiFp(this.configuration).ezsignfoldertypeGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(this.axios, this.basePath));
    }
}
