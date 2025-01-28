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
import type { EzsigntemplatesignatureCreateObjectV2Request } from '../model';
// @ts-ignore
import type { EzsigntemplatesignatureCreateObjectV2Response } from '../model';
// @ts-ignore
import type { EzsigntemplatesignatureDeleteObjectV1Response } from '../model';
// @ts-ignore
import type { EzsigntemplatesignatureEditObjectV2Request } from '../model';
// @ts-ignore
import type { EzsigntemplatesignatureEditObjectV2Response } from '../model';
// @ts-ignore
import type { EzsigntemplatesignatureGetObjectV3Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsigntemplatesignatureApi - axios parameter creator
 * @export
 */
export const ObjectEzsigntemplatesignatureApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatesignature
         * @param {EzsigntemplatesignatureCreateObjectV2Request} ezsigntemplatesignatureCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureCreateObjectV2: async (ezsigntemplatesignatureCreateObjectV2Request: EzsigntemplatesignatureCreateObjectV2Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsigntemplatesignatureCreateObjectV2Request' is not null or undefined
            assertParamExists('ezsigntemplatesignatureCreateObjectV2', 'ezsigntemplatesignatureCreateObjectV2Request', ezsigntemplatesignatureCreateObjectV2Request)
            const localVarPath = `/2/object/ezsigntemplatesignature`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigntemplatesignatureCreateObjectV2Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureDeleteObjectV1: async (pkiEzsigntemplatesignatureID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatesignatureID' is not null or undefined
            assertParamExists('ezsigntemplatesignatureDeleteObjectV1', 'pkiEzsigntemplatesignatureID', pkiEzsigntemplatesignatureID)
            const localVarPath = `/1/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}`
                .replace(`{${"pkiEzsigntemplatesignatureID"}}`, encodeURIComponent(String(pkiEzsigntemplatesignatureID)));
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
         * @summary Edit an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {EzsigntemplatesignatureEditObjectV2Request} ezsigntemplatesignatureEditObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureEditObjectV2: async (pkiEzsigntemplatesignatureID: number, ezsigntemplatesignatureEditObjectV2Request: EzsigntemplatesignatureEditObjectV2Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatesignatureID' is not null or undefined
            assertParamExists('ezsigntemplatesignatureEditObjectV2', 'pkiEzsigntemplatesignatureID', pkiEzsigntemplatesignatureID)
            // verify required parameter 'ezsigntemplatesignatureEditObjectV2Request' is not null or undefined
            assertParamExists('ezsigntemplatesignatureEditObjectV2', 'ezsigntemplatesignatureEditObjectV2Request', ezsigntemplatesignatureEditObjectV2Request)
            const localVarPath = `/2/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}`
                .replace(`{${"pkiEzsigntemplatesignatureID"}}`, encodeURIComponent(String(pkiEzsigntemplatesignatureID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigntemplatesignatureEditObjectV2Request, localVarRequestOptions, configuration)

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
         * @summary Retrieve an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureGetObjectV3: async (pkiEzsigntemplatesignatureID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatesignatureID' is not null or undefined
            assertParamExists('ezsigntemplatesignatureGetObjectV3', 'pkiEzsigntemplatesignatureID', pkiEzsigntemplatesignatureID)
            const localVarPath = `/3/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}`
                .replace(`{${"pkiEzsigntemplatesignatureID"}}`, encodeURIComponent(String(pkiEzsigntemplatesignatureID)));
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
 * ObjectEzsigntemplatesignatureApi - functional programming interface
 * @export
 */
export const ObjectEzsigntemplatesignatureApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsigntemplatesignatureApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatesignature
         * @param {EzsigntemplatesignatureCreateObjectV2Request} ezsigntemplatesignatureCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatesignatureCreateObjectV2(ezsigntemplatesignatureCreateObjectV2Request: EzsigntemplatesignatureCreateObjectV2Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatesignatureCreateObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatesignatureCreateObjectV2(ezsigntemplatesignatureCreateObjectV2Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsigntemplatesignatureApi.ezsigntemplatesignatureCreateObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatesignatureDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsigntemplatesignatureApi.ezsigntemplatesignatureDeleteObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Edit an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {EzsigntemplatesignatureEditObjectV2Request} ezsigntemplatesignatureEditObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatesignatureEditObjectV2(pkiEzsigntemplatesignatureID: number, ezsigntemplatesignatureEditObjectV2Request: EzsigntemplatesignatureEditObjectV2Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatesignatureEditObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatesignatureEditObjectV2(pkiEzsigntemplatesignatureID, ezsigntemplatesignatureEditObjectV2Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsigntemplatesignatureApi.ezsigntemplatesignatureEditObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatesignatureGetObjectV3(pkiEzsigntemplatesignatureID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatesignatureGetObjectV3Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatesignatureGetObjectV3(pkiEzsigntemplatesignatureID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsigntemplatesignatureApi.ezsigntemplatesignatureGetObjectV3']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectEzsigntemplatesignatureApi - factory interface
 * @export
 */
export const ObjectEzsigntemplatesignatureApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsigntemplatesignatureApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatesignature
         * @param {EzsigntemplatesignatureCreateObjectV2Request} ezsigntemplatesignatureCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureCreateObjectV2(ezsigntemplatesignatureCreateObjectV2Request: EzsigntemplatesignatureCreateObjectV2Request, options?: RawAxiosRequestConfig): AxiosPromise<EzsigntemplatesignatureCreateObjectV2Response> {
            return localVarFp.ezsigntemplatesignatureCreateObjectV2(ezsigntemplatesignatureCreateObjectV2Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsigntemplatesignatureDeleteObjectV1Response> {
            return localVarFp.ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {EzsigntemplatesignatureEditObjectV2Request} ezsigntemplatesignatureEditObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureEditObjectV2(pkiEzsigntemplatesignatureID: number, ezsigntemplatesignatureEditObjectV2Request: EzsigntemplatesignatureEditObjectV2Request, options?: RawAxiosRequestConfig): AxiosPromise<EzsigntemplatesignatureEditObjectV2Response> {
            return localVarFp.ezsigntemplatesignatureEditObjectV2(pkiEzsigntemplatesignatureID, ezsigntemplatesignatureEditObjectV2Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureGetObjectV3(pkiEzsigntemplatesignatureID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsigntemplatesignatureGetObjectV3Response> {
            return localVarFp.ezsigntemplatesignatureGetObjectV3(pkiEzsigntemplatesignatureID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsigntemplatesignatureApi - object-oriented interface
 * @export
 * @class ObjectEzsigntemplatesignatureApi
 * @extends {BaseAPI}
 */
export class ObjectEzsigntemplatesignatureApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsigntemplatesignature
     * @param {EzsigntemplatesignatureCreateObjectV2Request} ezsigntemplatesignatureCreateObjectV2Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatesignatureApi
     */
    public ezsigntemplatesignatureCreateObjectV2(ezsigntemplatesignatureCreateObjectV2Request: EzsigntemplatesignatureCreateObjectV2Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsigntemplatesignatureApiFp(this.configuration).ezsigntemplatesignatureCreateObjectV2(ezsigntemplatesignatureCreateObjectV2Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsigntemplatesignature
     * @param {number} pkiEzsigntemplatesignatureID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatesignatureApi
     */
    public ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsigntemplatesignatureApiFp(this.configuration).ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Ezsigntemplatesignature
     * @param {number} pkiEzsigntemplatesignatureID 
     * @param {EzsigntemplatesignatureEditObjectV2Request} ezsigntemplatesignatureEditObjectV2Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatesignatureApi
     */
    public ezsigntemplatesignatureEditObjectV2(pkiEzsigntemplatesignatureID: number, ezsigntemplatesignatureEditObjectV2Request: EzsigntemplatesignatureEditObjectV2Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsigntemplatesignatureApiFp(this.configuration).ezsigntemplatesignatureEditObjectV2(pkiEzsigntemplatesignatureID, ezsigntemplatesignatureEditObjectV2Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsigntemplatesignature
     * @param {number} pkiEzsigntemplatesignatureID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatesignatureApi
     */
    public ezsigntemplatesignatureGetObjectV3(pkiEzsigntemplatesignatureID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsigntemplatesignatureApiFp(this.configuration).ezsigntemplatesignatureGetObjectV3(pkiEzsigntemplatesignatureID, options).then((request) => request(this.axios, this.basePath));
    }
}

