/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
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
import { EzsignSuggestSignersV1Response } from '../model';
// @ts-ignore
import { EzsignSuggestTemplatesV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ModuleEzsignApi - axios parameter creator
 * @export
 */
export const ModuleEzsignApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Retrieve previously used Ezsignsigners and all users from the system
         * @summary Suggest signers
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignSuggestSignersV1: async (options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/module/ezsign/suggestSigners`;
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
         * Retrieve Ezsigntemplates and Ezsigntemplatepackages that can be imported in a Ezsignfolder
         * @summary Suggest templates
         * @param {number} [fkiEzsignfoldertypeID] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignSuggestTemplatesV1: async (fkiEzsignfoldertypeID?: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/module/ezsign/suggestTemplates`;
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

            if (fkiEzsignfoldertypeID !== undefined) {
                localVarQueryParameter['fkiEzsignfoldertypeID'] = fkiEzsignfoldertypeID;
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
 * ModuleEzsignApi - functional programming interface
 * @export
 */
export const ModuleEzsignApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ModuleEzsignApiAxiosParamCreator(configuration)
    return {
        /**
         * Retrieve previously used Ezsignsigners and all users from the system
         * @summary Suggest signers
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignSuggestSignersV1(options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignSuggestSignersV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignSuggestSignersV1(options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * Retrieve Ezsigntemplates and Ezsigntemplatepackages that can be imported in a Ezsignfolder
         * @summary Suggest templates
         * @param {number} [fkiEzsignfoldertypeID] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignSuggestTemplatesV1(fkiEzsignfoldertypeID?: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignSuggestTemplatesV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignSuggestTemplatesV1(fkiEzsignfoldertypeID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ModuleEzsignApi - factory interface
 * @export
 */
export const ModuleEzsignApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ModuleEzsignApiFp(configuration)
    return {
        /**
         * Retrieve previously used Ezsignsigners and all users from the system
         * @summary Suggest signers
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignSuggestSignersV1(options?: any): AxiosPromise<EzsignSuggestSignersV1Response> {
            return localVarFp.ezsignSuggestSignersV1(options).then((request) => request(axios, basePath));
        },
        /**
         * Retrieve Ezsigntemplates and Ezsigntemplatepackages that can be imported in a Ezsignfolder
         * @summary Suggest templates
         * @param {number} [fkiEzsignfoldertypeID] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignSuggestTemplatesV1(fkiEzsignfoldertypeID?: number, options?: any): AxiosPromise<EzsignSuggestTemplatesV1Response> {
            return localVarFp.ezsignSuggestTemplatesV1(fkiEzsignfoldertypeID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ModuleEzsignApi - object-oriented interface
 * @export
 * @class ModuleEzsignApi
 * @extends {BaseAPI}
 */
export class ModuleEzsignApi extends BaseAPI {
    /**
     * Retrieve previously used Ezsignsigners and all users from the system
     * @summary Suggest signers
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleEzsignApi
     */
    public ezsignSuggestSignersV1(options?: AxiosRequestConfig) {
        return ModuleEzsignApiFp(this.configuration).ezsignSuggestSignersV1(options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Retrieve Ezsigntemplates and Ezsigntemplatepackages that can be imported in a Ezsignfolder
     * @summary Suggest templates
     * @param {number} [fkiEzsignfoldertypeID] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleEzsignApi
     */
    public ezsignSuggestTemplatesV1(fkiEzsignfoldertypeID?: number, options?: AxiosRequestConfig) {
        return ModuleEzsignApiFp(this.configuration).ezsignSuggestTemplatesV1(fkiEzsignfoldertypeID, options).then((request) => request(this.axios, this.basePath));
    }
}
