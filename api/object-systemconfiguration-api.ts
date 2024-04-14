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
import type { AxiosPromise, AxiosInstance, RawAxiosRequestConfig } from 'axios';
import globalAxios from 'axios';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError, operationServerMap } from '../base';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { SystemconfigurationEditObjectV1Request } from '../model';
// @ts-ignore
import { SystemconfigurationEditObjectV1Response } from '../model';
// @ts-ignore
import { SystemconfigurationGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectSystemconfigurationApi - axios parameter creator
 * @export
 */
export const ObjectSystemconfigurationApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Edit an existing Systemconfiguration
         * @param {number} pkiSystemconfigurationID The unique ID of the Systemconfiguration
         * @param {SystemconfigurationEditObjectV1Request} systemconfigurationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        systemconfigurationEditObjectV1: async (pkiSystemconfigurationID: number, systemconfigurationEditObjectV1Request: SystemconfigurationEditObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiSystemconfigurationID' is not null or undefined
            assertParamExists('systemconfigurationEditObjectV1', 'pkiSystemconfigurationID', pkiSystemconfigurationID)
            // verify required parameter 'systemconfigurationEditObjectV1Request' is not null or undefined
            assertParamExists('systemconfigurationEditObjectV1', 'systemconfigurationEditObjectV1Request', systemconfigurationEditObjectV1Request)
            const localVarPath = `/1/object/systemconfiguration/{pkiSystemconfigurationID}`
                .replace(`{${"pkiSystemconfigurationID"}}`, encodeURIComponent(String(pkiSystemconfigurationID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(systemconfigurationEditObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Retrieve an existing Systemconfiguration
         * @param {number} pkiSystemconfigurationID The unique ID of the Systemconfiguration
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        systemconfigurationGetObjectV2: async (pkiSystemconfigurationID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiSystemconfigurationID' is not null or undefined
            assertParamExists('systemconfigurationGetObjectV2', 'pkiSystemconfigurationID', pkiSystemconfigurationID)
            const localVarPath = `/2/object/systemconfiguration/{pkiSystemconfigurationID}`
                .replace(`{${"pkiSystemconfigurationID"}}`, encodeURIComponent(String(pkiSystemconfigurationID)));
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
 * ObjectSystemconfigurationApi - functional programming interface
 * @export
 */
export const ObjectSystemconfigurationApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectSystemconfigurationApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Edit an existing Systemconfiguration
         * @param {number} pkiSystemconfigurationID The unique ID of the Systemconfiguration
         * @param {SystemconfigurationEditObjectV1Request} systemconfigurationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async systemconfigurationEditObjectV1(pkiSystemconfigurationID: number, systemconfigurationEditObjectV1Request: SystemconfigurationEditObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<SystemconfigurationEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.systemconfigurationEditObjectV1(pkiSystemconfigurationID, systemconfigurationEditObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectSystemconfigurationApi.systemconfigurationEditObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Systemconfiguration
         * @param {number} pkiSystemconfigurationID The unique ID of the Systemconfiguration
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async systemconfigurationGetObjectV2(pkiSystemconfigurationID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<SystemconfigurationGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.systemconfigurationGetObjectV2(pkiSystemconfigurationID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectSystemconfigurationApi.systemconfigurationGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectSystemconfigurationApi - factory interface
 * @export
 */
export const ObjectSystemconfigurationApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectSystemconfigurationApiFp(configuration)
    return {
        /**
         * 
         * @summary Edit an existing Systemconfiguration
         * @param {number} pkiSystemconfigurationID The unique ID of the Systemconfiguration
         * @param {SystemconfigurationEditObjectV1Request} systemconfigurationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        systemconfigurationEditObjectV1(pkiSystemconfigurationID: number, systemconfigurationEditObjectV1Request: SystemconfigurationEditObjectV1Request, options?: any): AxiosPromise<SystemconfigurationEditObjectV1Response> {
            return localVarFp.systemconfigurationEditObjectV1(pkiSystemconfigurationID, systemconfigurationEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Systemconfiguration
         * @param {number} pkiSystemconfigurationID The unique ID of the Systemconfiguration
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        systemconfigurationGetObjectV2(pkiSystemconfigurationID: number, options?: any): AxiosPromise<SystemconfigurationGetObjectV2Response> {
            return localVarFp.systemconfigurationGetObjectV2(pkiSystemconfigurationID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectSystemconfigurationApi - object-oriented interface
 * @export
 * @class ObjectSystemconfigurationApi
 * @extends {BaseAPI}
 */
export class ObjectSystemconfigurationApi extends BaseAPI {
    /**
     * 
     * @summary Edit an existing Systemconfiguration
     * @param {number} pkiSystemconfigurationID The unique ID of the Systemconfiguration
     * @param {SystemconfigurationEditObjectV1Request} systemconfigurationEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectSystemconfigurationApi
     */
    public systemconfigurationEditObjectV1(pkiSystemconfigurationID: number, systemconfigurationEditObjectV1Request: SystemconfigurationEditObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectSystemconfigurationApiFp(this.configuration).systemconfigurationEditObjectV1(pkiSystemconfigurationID, systemconfigurationEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Systemconfiguration
     * @param {number} pkiSystemconfigurationID The unique ID of the Systemconfiguration
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectSystemconfigurationApi
     */
    public systemconfigurationGetObjectV2(pkiSystemconfigurationID: number, options?: RawAxiosRequestConfig) {
        return ObjectSystemconfigurationApiFp(this.configuration).systemconfigurationGetObjectV2(pkiSystemconfigurationID, options).then((request) => request(this.axios, this.basePath));
    }
}

