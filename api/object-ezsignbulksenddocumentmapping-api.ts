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
import { BASE_PATH, COLLECTION_FORMATS, type RequestArgs, BaseAPI, RequiredError, operationServerMap } from '../base';
// @ts-ignore
import type { CommonResponse } from '../model';
// @ts-ignore
import type { CommonResponseError } from '../model';
// @ts-ignore
import type { EzsignbulksenddocumentmappingCreateObjectV1Request } from '../model';
// @ts-ignore
import type { EzsignbulksenddocumentmappingCreateObjectV1Response } from '../model';
// @ts-ignore
import type { EzsignbulksenddocumentmappingGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignbulksenddocumentmappingApi - axios parameter creator
 * @export
 */
export const ObjectEzsignbulksenddocumentmappingApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignbulksenddocumentmapping
         * @param {EzsignbulksenddocumentmappingCreateObjectV1Request} ezsignbulksenddocumentmappingCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksenddocumentmappingCreateObjectV1: async (ezsignbulksenddocumentmappingCreateObjectV1Request: EzsignbulksenddocumentmappingCreateObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignbulksenddocumentmappingCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsignbulksenddocumentmappingCreateObjectV1', 'ezsignbulksenddocumentmappingCreateObjectV1Request', ezsignbulksenddocumentmappingCreateObjectV1Request)
            const localVarPath = `/1/object/ezsignbulksenddocumentmapping`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'POST', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignbulksenddocumentmappingCreateObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
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
         * @summary Delete an existing Ezsignbulksenddocumentmapping
         * @param {number} pkiEzsignbulksenddocumentmappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksenddocumentmappingDeleteObjectV1: async (pkiEzsignbulksenddocumentmappingID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignbulksenddocumentmappingID' is not null or undefined
            assertParamExists('ezsignbulksenddocumentmappingDeleteObjectV1', 'pkiEzsignbulksenddocumentmappingID', pkiEzsignbulksenddocumentmappingID)
            const localVarPath = `/1/object/ezsignbulksenddocumentmapping/{pkiEzsignbulksenddocumentmappingID}`
                .replace(`{${"pkiEzsignbulksenddocumentmappingID"}}`, encodeURIComponent(String(pkiEzsignbulksenddocumentmappingID)));
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
         * @summary Retrieve an existing Ezsignbulksenddocumentmapping
         * @param {number} pkiEzsignbulksenddocumentmappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksenddocumentmappingGetObjectV2: async (pkiEzsignbulksenddocumentmappingID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignbulksenddocumentmappingID' is not null or undefined
            assertParamExists('ezsignbulksenddocumentmappingGetObjectV2', 'pkiEzsignbulksenddocumentmappingID', pkiEzsignbulksenddocumentmappingID)
            const localVarPath = `/2/object/ezsignbulksenddocumentmapping/{pkiEzsignbulksenddocumentmappingID}`
                .replace(`{${"pkiEzsignbulksenddocumentmappingID"}}`, encodeURIComponent(String(pkiEzsignbulksenddocumentmappingID)));
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
 * ObjectEzsignbulksenddocumentmappingApi - functional programming interface
 * @export
 */
export const ObjectEzsignbulksenddocumentmappingApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignbulksenddocumentmappingApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignbulksenddocumentmapping
         * @param {EzsignbulksenddocumentmappingCreateObjectV1Request} ezsignbulksenddocumentmappingCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksenddocumentmappingCreateObjectV1(ezsignbulksenddocumentmappingCreateObjectV1Request: EzsignbulksenddocumentmappingCreateObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignbulksenddocumentmappingCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksenddocumentmappingCreateObjectV1(ezsignbulksenddocumentmappingCreateObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignbulksenddocumentmappingApi.ezsignbulksenddocumentmappingCreateObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Delete an existing Ezsignbulksenddocumentmapping
         * @param {number} pkiEzsignbulksenddocumentmappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksenddocumentmappingDeleteObjectV1(pkiEzsignbulksenddocumentmappingID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommonResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksenddocumentmappingDeleteObjectV1(pkiEzsignbulksenddocumentmappingID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignbulksenddocumentmappingApi.ezsignbulksenddocumentmappingDeleteObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksenddocumentmapping
         * @param {number} pkiEzsignbulksenddocumentmappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksenddocumentmappingGetObjectV2(pkiEzsignbulksenddocumentmappingID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignbulksenddocumentmappingGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksenddocumentmappingGetObjectV2(pkiEzsignbulksenddocumentmappingID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignbulksenddocumentmappingApi.ezsignbulksenddocumentmappingGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectEzsignbulksenddocumentmappingApi - factory interface
 * @export
 */
export const ObjectEzsignbulksenddocumentmappingApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignbulksenddocumentmappingApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignbulksenddocumentmapping
         * @param {EzsignbulksenddocumentmappingCreateObjectV1Request} ezsignbulksenddocumentmappingCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksenddocumentmappingCreateObjectV1(ezsignbulksenddocumentmappingCreateObjectV1Request: EzsignbulksenddocumentmappingCreateObjectV1Request, options?: RawAxiosRequestConfig): AxiosPromise<EzsignbulksenddocumentmappingCreateObjectV1Response> {
            return localVarFp.ezsignbulksenddocumentmappingCreateObjectV1(ezsignbulksenddocumentmappingCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsignbulksenddocumentmapping
         * @param {number} pkiEzsignbulksenddocumentmappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksenddocumentmappingDeleteObjectV1(pkiEzsignbulksenddocumentmappingID: number, options?: RawAxiosRequestConfig): AxiosPromise<CommonResponse> {
            return localVarFp.ezsignbulksenddocumentmappingDeleteObjectV1(pkiEzsignbulksenddocumentmappingID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksenddocumentmapping
         * @param {number} pkiEzsignbulksenddocumentmappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksenddocumentmappingGetObjectV2(pkiEzsignbulksenddocumentmappingID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsignbulksenddocumentmappingGetObjectV2Response> {
            return localVarFp.ezsignbulksenddocumentmappingGetObjectV2(pkiEzsignbulksenddocumentmappingID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignbulksenddocumentmappingApi - object-oriented interface
 * @export
 * @class ObjectEzsignbulksenddocumentmappingApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignbulksenddocumentmappingApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsignbulksenddocumentmapping
     * @param {EzsignbulksenddocumentmappingCreateObjectV1Request} ezsignbulksenddocumentmappingCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksenddocumentmappingApi
     */
    public ezsignbulksenddocumentmappingCreateObjectV1(ezsignbulksenddocumentmappingCreateObjectV1Request: EzsignbulksenddocumentmappingCreateObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsignbulksenddocumentmappingApiFp(this.configuration).ezsignbulksenddocumentmappingCreateObjectV1(ezsignbulksenddocumentmappingCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsignbulksenddocumentmapping
     * @param {number} pkiEzsignbulksenddocumentmappingID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksenddocumentmappingApi
     */
    public ezsignbulksenddocumentmappingDeleteObjectV1(pkiEzsignbulksenddocumentmappingID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignbulksenddocumentmappingApiFp(this.configuration).ezsignbulksenddocumentmappingDeleteObjectV1(pkiEzsignbulksenddocumentmappingID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignbulksenddocumentmapping
     * @param {number} pkiEzsignbulksenddocumentmappingID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksenddocumentmappingApi
     */
    public ezsignbulksenddocumentmappingGetObjectV2(pkiEzsignbulksenddocumentmappingID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignbulksenddocumentmappingApiFp(this.configuration).ezsignbulksenddocumentmappingGetObjectV2(pkiEzsignbulksenddocumentmappingID, options).then((request) => request(this.axios, this.basePath));
    }
}

