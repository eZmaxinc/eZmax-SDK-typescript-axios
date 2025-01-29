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
import type { CommonResponseError } from '../model';
// @ts-ignore
import type { ElectronicfundstransferGetCommunicationCountV1Response } from '../model';
// @ts-ignore
import type { ElectronicfundstransferGetCommunicationListV1Response } from '../model';
// @ts-ignore
import type { ElectronicfundstransferGetCommunicationrecipientsV1Response } from '../model';
// @ts-ignore
import type { ElectronicfundstransferGetCommunicationsendersV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectElectronicfundstransferApi - axios parameter creator
 * @export
 */
export const ObjectElectronicfundstransferApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve Communication count
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        electronicfundstransferGetCommunicationCountV1: async (pkiElectronicfundstransferID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiElectronicfundstransferID' is not null or undefined
            assertParamExists('electronicfundstransferGetCommunicationCountV1', 'pkiElectronicfundstransferID', pkiElectronicfundstransferID)
            const localVarPath = `/1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationCount`
                .replace(`{${"pkiElectronicfundstransferID"}}`, encodeURIComponent(String(pkiElectronicfundstransferID)));
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
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        electronicfundstransferGetCommunicationListV1: async (pkiElectronicfundstransferID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiElectronicfundstransferID' is not null or undefined
            assertParamExists('electronicfundstransferGetCommunicationListV1', 'pkiElectronicfundstransferID', pkiElectronicfundstransferID)
            const localVarPath = `/1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationList`
                .replace(`{${"pkiElectronicfundstransferID"}}`, encodeURIComponent(String(pkiElectronicfundstransferID)));
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
        /**
         * 
         * @summary Retrieve Electronicfundstransfer\'s Communicationrecipient
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        electronicfundstransferGetCommunicationrecipientsV1: async (pkiElectronicfundstransferID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiElectronicfundstransferID' is not null or undefined
            assertParamExists('electronicfundstransferGetCommunicationrecipientsV1', 'pkiElectronicfundstransferID', pkiElectronicfundstransferID)
            const localVarPath = `/1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationrecipients`
                .replace(`{${"pkiElectronicfundstransferID"}}`, encodeURIComponent(String(pkiElectronicfundstransferID)));
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
        /**
         * 
         * @summary Retrieve Electronicfundstransfer\'s Communicationsender
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        electronicfundstransferGetCommunicationsendersV1: async (pkiElectronicfundstransferID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiElectronicfundstransferID' is not null or undefined
            assertParamExists('electronicfundstransferGetCommunicationsendersV1', 'pkiElectronicfundstransferID', pkiElectronicfundstransferID)
            const localVarPath = `/1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationsenders`
                .replace(`{${"pkiElectronicfundstransferID"}}`, encodeURIComponent(String(pkiElectronicfundstransferID)));
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
 * ObjectElectronicfundstransferApi - functional programming interface
 * @export
 */
export const ObjectElectronicfundstransferApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectElectronicfundstransferApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve Communication count
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async electronicfundstransferGetCommunicationCountV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ElectronicfundstransferGetCommunicationCountV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.electronicfundstransferGetCommunicationCountV1(pkiElectronicfundstransferID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectElectronicfundstransferApi.electronicfundstransferGetCommunicationCountV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async electronicfundstransferGetCommunicationListV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ElectronicfundstransferGetCommunicationListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.electronicfundstransferGetCommunicationListV1(pkiElectronicfundstransferID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectElectronicfundstransferApi.electronicfundstransferGetCommunicationListV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve Electronicfundstransfer\'s Communicationrecipient
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async electronicfundstransferGetCommunicationrecipientsV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ElectronicfundstransferGetCommunicationrecipientsV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.electronicfundstransferGetCommunicationrecipientsV1(pkiElectronicfundstransferID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectElectronicfundstransferApi.electronicfundstransferGetCommunicationrecipientsV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve Electronicfundstransfer\'s Communicationsender
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async electronicfundstransferGetCommunicationsendersV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ElectronicfundstransferGetCommunicationsendersV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.electronicfundstransferGetCommunicationsendersV1(pkiElectronicfundstransferID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectElectronicfundstransferApi.electronicfundstransferGetCommunicationsendersV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectElectronicfundstransferApi - factory interface
 * @export
 */
export const ObjectElectronicfundstransferApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectElectronicfundstransferApiFp(configuration)
    return {
        /**
         * 
         * @summary Retrieve Communication count
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        electronicfundstransferGetCommunicationCountV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig): AxiosPromise<ElectronicfundstransferGetCommunicationCountV1Response> {
            return localVarFp.electronicfundstransferGetCommunicationCountV1(pkiElectronicfundstransferID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        electronicfundstransferGetCommunicationListV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig): AxiosPromise<ElectronicfundstransferGetCommunicationListV1Response> {
            return localVarFp.electronicfundstransferGetCommunicationListV1(pkiElectronicfundstransferID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Electronicfundstransfer\'s Communicationrecipient
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        electronicfundstransferGetCommunicationrecipientsV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig): AxiosPromise<ElectronicfundstransferGetCommunicationrecipientsV1Response> {
            return localVarFp.electronicfundstransferGetCommunicationrecipientsV1(pkiElectronicfundstransferID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Electronicfundstransfer\'s Communicationsender
         * @param {number} pkiElectronicfundstransferID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        electronicfundstransferGetCommunicationsendersV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig): AxiosPromise<ElectronicfundstransferGetCommunicationsendersV1Response> {
            return localVarFp.electronicfundstransferGetCommunicationsendersV1(pkiElectronicfundstransferID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectElectronicfundstransferApi - object-oriented interface
 * @export
 * @class ObjectElectronicfundstransferApi
 * @extends {BaseAPI}
 */
export class ObjectElectronicfundstransferApi extends BaseAPI {
    /**
     * 
     * @summary Retrieve Communication count
     * @param {number} pkiElectronicfundstransferID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectElectronicfundstransferApi
     */
    public electronicfundstransferGetCommunicationCountV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig) {
        return ObjectElectronicfundstransferApiFp(this.configuration).electronicfundstransferGetCommunicationCountV1(pkiElectronicfundstransferID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Communication list
     * @param {number} pkiElectronicfundstransferID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectElectronicfundstransferApi
     */
    public electronicfundstransferGetCommunicationListV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig) {
        return ObjectElectronicfundstransferApiFp(this.configuration).electronicfundstransferGetCommunicationListV1(pkiElectronicfundstransferID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Electronicfundstransfer\'s Communicationrecipient
     * @param {number} pkiElectronicfundstransferID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectElectronicfundstransferApi
     */
    public electronicfundstransferGetCommunicationrecipientsV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig) {
        return ObjectElectronicfundstransferApiFp(this.configuration).electronicfundstransferGetCommunicationrecipientsV1(pkiElectronicfundstransferID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Electronicfundstransfer\'s Communicationsender
     * @param {number} pkiElectronicfundstransferID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectElectronicfundstransferApi
     */
    public electronicfundstransferGetCommunicationsendersV1(pkiElectronicfundstransferID: number, options?: RawAxiosRequestConfig) {
        return ObjectElectronicfundstransferApiFp(this.configuration).electronicfundstransferGetCommunicationsendersV1(pkiElectronicfundstransferID, options).then((request) => request(this.axios, this.basePath));
    }
}

