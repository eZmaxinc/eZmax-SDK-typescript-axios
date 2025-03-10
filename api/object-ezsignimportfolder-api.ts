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
import type { CommonResponseError } from '../model';
// @ts-ignore
import type { EzsignimportfolderDeleteObjectV1Response } from '../model';
// @ts-ignore
import type { EzsignimportfolderGetListV1Response } from '../model';
// @ts-ignore
import type { EzsignimportfolderGetObjectV2Response } from '../model';
// @ts-ignore
import type { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignimportfolderApi - axios parameter creator
 * @export
 */
export const ObjectEzsignimportfolderApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Delete an existing Ezsignimportfolder
         * @param {number} pkiEzsignimportfolderID The unique ID of the Ezsignimportfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignimportfolderDeleteObjectV1: async (pkiEzsignimportfolderID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignimportfolderID' is not null or undefined
            assertParamExists('ezsignimportfolderDeleteObjectV1', 'pkiEzsignimportfolderID', pkiEzsignimportfolderID)
            const localVarPath = `/1/object/ezsignimportfolder/{pkiEzsignimportfolderID}`
                .replace(`{${"pkiEzsignimportfolderID"}}`, encodeURIComponent(String(pkiEzsignimportfolderID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'DELETE', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
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
                        method: 'DELETE' as string,
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
         * 
         * @summary Retrieve Ezsignimportfolder list
         * @param {EzsignimportfolderGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignimportfolderGetListV1: async (eOrderBy?: EzsignimportfolderGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/ezsignimportfolder/getList`;
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
        /**
         * 
         * @summary Retrieve an existing Ezsignimportfolder
         * @param {number} pkiEzsignimportfolderID The unique ID of the Ezsignimportfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignimportfolderGetObjectV2: async (pkiEzsignimportfolderID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignimportfolderID' is not null or undefined
            assertParamExists('ezsignimportfolderGetObjectV2', 'pkiEzsignimportfolderID', pkiEzsignimportfolderID)
            const localVarPath = `/2/object/ezsignimportfolder/{pkiEzsignimportfolderID}`
                .replace(`{${"pkiEzsignimportfolderID"}}`, encodeURIComponent(String(pkiEzsignimportfolderID)));
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
 * ObjectEzsignimportfolderApi - functional programming interface
 * @export
 */
export const ObjectEzsignimportfolderApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignimportfolderApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Delete an existing Ezsignimportfolder
         * @param {number} pkiEzsignimportfolderID The unique ID of the Ezsignimportfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignimportfolderDeleteObjectV1(pkiEzsignimportfolderID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignimportfolderDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignimportfolderDeleteObjectV1(pkiEzsignimportfolderID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignimportfolderApi.ezsignimportfolderDeleteObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve Ezsignimportfolder list
         * @param {EzsignimportfolderGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignimportfolderGetListV1(eOrderBy?: EzsignimportfolderGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignimportfolderGetListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignimportfolderGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignimportfolderApi.ezsignimportfolderGetListV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignimportfolder
         * @param {number} pkiEzsignimportfolderID The unique ID of the Ezsignimportfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignimportfolderGetObjectV2(pkiEzsignimportfolderID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignimportfolderGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignimportfolderGetObjectV2(pkiEzsignimportfolderID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignimportfolderApi.ezsignimportfolderGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectEzsignimportfolderApi - factory interface
 * @export
 */
export const ObjectEzsignimportfolderApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignimportfolderApiFp(configuration)
    return {
        /**
         * 
         * @summary Delete an existing Ezsignimportfolder
         * @param {number} pkiEzsignimportfolderID The unique ID of the Ezsignimportfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignimportfolderDeleteObjectV1(pkiEzsignimportfolderID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsignimportfolderDeleteObjectV1Response> {
            return localVarFp.ezsignimportfolderDeleteObjectV1(pkiEzsignimportfolderID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Ezsignimportfolder list
         * @param {EzsignimportfolderGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignimportfolderGetListV1(eOrderBy?: EzsignimportfolderGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig): AxiosPromise<EzsignimportfolderGetListV1Response> {
            return localVarFp.ezsignimportfolderGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignimportfolder
         * @param {number} pkiEzsignimportfolderID The unique ID of the Ezsignimportfolder
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignimportfolderGetObjectV2(pkiEzsignimportfolderID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsignimportfolderGetObjectV2Response> {
            return localVarFp.ezsignimportfolderGetObjectV2(pkiEzsignimportfolderID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignimportfolderApi - object-oriented interface
 * @export
 * @class ObjectEzsignimportfolderApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignimportfolderApi extends BaseAPI {
    /**
     * 
     * @summary Delete an existing Ezsignimportfolder
     * @param {number} pkiEzsignimportfolderID The unique ID of the Ezsignimportfolder
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignimportfolderApi
     */
    public ezsignimportfolderDeleteObjectV1(pkiEzsignimportfolderID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignimportfolderApiFp(this.configuration).ezsignimportfolderDeleteObjectV1(pkiEzsignimportfolderID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Ezsignimportfolder list
     * @param {EzsignimportfolderGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
     * @param {number} [iRowMax] 
     * @param {number} [iRowOffset] 
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {string} [sFilter] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignimportfolderApi
     */
    public ezsignimportfolderGetListV1(eOrderBy?: EzsignimportfolderGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig) {
        return ObjectEzsignimportfolderApiFp(this.configuration).ezsignimportfolderGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignimportfolder
     * @param {number} pkiEzsignimportfolderID The unique ID of the Ezsignimportfolder
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignimportfolderApi
     */
    public ezsignimportfolderGetObjectV2(pkiEzsignimportfolderID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignimportfolderApiFp(this.configuration).ezsignimportfolderGetObjectV2(pkiEzsignimportfolderID, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const EzsignimportfolderGetListV1EOrderByEnum = {
    pkiEzsignimportfolderID_ASC: 'pkiEzsignimportfolderID_ASC',
    pkiEzsignimportfolderID_DESC: 'pkiEzsignimportfolderID_DESC',
    sEzsignimportfolderName_ASC: 'sEzsignimportfolderName_ASC',
    sEzsignimportfolderName_DESC: 'sEzsignimportfolderName_DESC'
} as const;
export type EzsignimportfolderGetListV1EOrderByEnum = typeof EzsignimportfolderGetListV1EOrderByEnum[keyof typeof EzsignimportfolderGetListV1EOrderByEnum];
