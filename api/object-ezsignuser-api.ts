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
import type { EzsignuserEditObjectV1Request } from '../model';
// @ts-ignore
import type { EzsignuserEditObjectV1Response } from '../model';
// @ts-ignore
import type { EzsignuserGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignuserApi - axios parameter creator
 * @export
 */
export const ObjectEzsignuserApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Edit an existing Ezsignuser
         * @param {number} pkiEzsignuserID The unique ID of the Ezsignuser
         * @param {EzsignuserEditObjectV1Request} ezsignuserEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignuserEditObjectV1: async (pkiEzsignuserID: number, ezsignuserEditObjectV1Request: EzsignuserEditObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignuserID' is not null or undefined
            assertParamExists('ezsignuserEditObjectV1', 'pkiEzsignuserID', pkiEzsignuserID)
            // verify required parameter 'ezsignuserEditObjectV1Request' is not null or undefined
            assertParamExists('ezsignuserEditObjectV1', 'ezsignuserEditObjectV1Request', ezsignuserEditObjectV1Request)
            const localVarPath = `/1/object/ezsignuser/{pkiEzsignuserID}`
                .replace(`{${"pkiEzsignuserID"}}`, encodeURIComponent(String(pkiEzsignuserID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'PUT', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignuserEditObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'PUT' as string,
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
         * @summary Retrieve an existing Ezsignuser
         * @param {number} pkiEzsignuserID The unique ID of the Ezsignuser
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignuserGetObjectV2: async (pkiEzsignuserID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignuserID' is not null or undefined
            assertParamExists('ezsignuserGetObjectV2', 'pkiEzsignuserID', pkiEzsignuserID)
            const localVarPath = `/2/object/ezsignuser/{pkiEzsignuserID}`
                .replace(`{${"pkiEzsignuserID"}}`, encodeURIComponent(String(pkiEzsignuserID)));
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
 * ObjectEzsignuserApi - functional programming interface
 * @export
 */
export const ObjectEzsignuserApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignuserApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Edit an existing Ezsignuser
         * @param {number} pkiEzsignuserID The unique ID of the Ezsignuser
         * @param {EzsignuserEditObjectV1Request} ezsignuserEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignuserEditObjectV1(pkiEzsignuserID: number, ezsignuserEditObjectV1Request: EzsignuserEditObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignuserEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignuserEditObjectV1(pkiEzsignuserID, ezsignuserEditObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignuserApi.ezsignuserEditObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignuser
         * @param {number} pkiEzsignuserID The unique ID of the Ezsignuser
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignuserGetObjectV2(pkiEzsignuserID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignuserGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignuserGetObjectV2(pkiEzsignuserID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignuserApi.ezsignuserGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectEzsignuserApi - factory interface
 * @export
 */
export const ObjectEzsignuserApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignuserApiFp(configuration)
    return {
        /**
         * 
         * @summary Edit an existing Ezsignuser
         * @param {number} pkiEzsignuserID The unique ID of the Ezsignuser
         * @param {EzsignuserEditObjectV1Request} ezsignuserEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignuserEditObjectV1(pkiEzsignuserID: number, ezsignuserEditObjectV1Request: EzsignuserEditObjectV1Request, options?: RawAxiosRequestConfig): AxiosPromise<EzsignuserEditObjectV1Response> {
            return localVarFp.ezsignuserEditObjectV1(pkiEzsignuserID, ezsignuserEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignuser
         * @param {number} pkiEzsignuserID The unique ID of the Ezsignuser
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignuserGetObjectV2(pkiEzsignuserID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsignuserGetObjectV2Response> {
            return localVarFp.ezsignuserGetObjectV2(pkiEzsignuserID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignuserApi - object-oriented interface
 * @export
 * @class ObjectEzsignuserApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignuserApi extends BaseAPI {
    /**
     * 
     * @summary Edit an existing Ezsignuser
     * @param {number} pkiEzsignuserID The unique ID of the Ezsignuser
     * @param {EzsignuserEditObjectV1Request} ezsignuserEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignuserApi
     */
    public ezsignuserEditObjectV1(pkiEzsignuserID: number, ezsignuserEditObjectV1Request: EzsignuserEditObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsignuserApiFp(this.configuration).ezsignuserEditObjectV1(pkiEzsignuserID, ezsignuserEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignuser
     * @param {number} pkiEzsignuserID The unique ID of the Ezsignuser
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignuserApi
     */
    public ezsignuserGetObjectV2(pkiEzsignuserID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignuserApiFp(this.configuration).ezsignuserGetObjectV2(pkiEzsignuserID, options).then((request) => request(this.axios, this.basePath));
    }
}

