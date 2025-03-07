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
import type { EzsignsignergroupmembershipCreateObjectV1Request } from '../model';
// @ts-ignore
import type { EzsignsignergroupmembershipCreateObjectV1Response } from '../model';
// @ts-ignore
import type { EzsignsignergroupmembershipDeleteObjectV1Response } from '../model';
// @ts-ignore
import type { EzsignsignergroupmembershipGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignsignergroupmembershipApi - axios parameter creator
 * @export
 */
export const ObjectEzsignsignergroupmembershipApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignsignergroupmembership
         * @param {EzsignsignergroupmembershipCreateObjectV1Request} ezsignsignergroupmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsignergroupmembershipCreateObjectV1: async (ezsignsignergroupmembershipCreateObjectV1Request: EzsignsignergroupmembershipCreateObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignsignergroupmembershipCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsignsignergroupmembershipCreateObjectV1', 'ezsignsignergroupmembershipCreateObjectV1Request', ezsignsignergroupmembershipCreateObjectV1Request)
            const localVarPath = `/1/object/ezsignsignergroupmembership`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignsignergroupmembershipCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Ezsignsignergroupmembership
         * @param {number} pkiEzsignsignergroupmembershipID The unique ID of the Ezsignsignergroupmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsignergroupmembershipDeleteObjectV1: async (pkiEzsignsignergroupmembershipID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignsignergroupmembershipID' is not null or undefined
            assertParamExists('ezsignsignergroupmembershipDeleteObjectV1', 'pkiEzsignsignergroupmembershipID', pkiEzsignsignergroupmembershipID)
            const localVarPath = `/1/object/ezsignsignergroupmembership/{pkiEzsignsignergroupmembershipID}`
                .replace(`{${"pkiEzsignsignergroupmembershipID"}}`, encodeURIComponent(String(pkiEzsignsignergroupmembershipID)));
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
         * @summary Retrieve an existing Ezsignsignergroupmembership
         * @param {number} pkiEzsignsignergroupmembershipID The unique ID of the Ezsignsignergroupmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsignergroupmembershipGetObjectV2: async (pkiEzsignsignergroupmembershipID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignsignergroupmembershipID' is not null or undefined
            assertParamExists('ezsignsignergroupmembershipGetObjectV2', 'pkiEzsignsignergroupmembershipID', pkiEzsignsignergroupmembershipID)
            const localVarPath = `/2/object/ezsignsignergroupmembership/{pkiEzsignsignergroupmembershipID}`
                .replace(`{${"pkiEzsignsignergroupmembershipID"}}`, encodeURIComponent(String(pkiEzsignsignergroupmembershipID)));
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
 * ObjectEzsignsignergroupmembershipApi - functional programming interface
 * @export
 */
export const ObjectEzsignsignergroupmembershipApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignsignergroupmembershipApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignsignergroupmembership
         * @param {EzsignsignergroupmembershipCreateObjectV1Request} ezsignsignergroupmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignsignergroupmembershipCreateObjectV1(ezsignsignergroupmembershipCreateObjectV1Request: EzsignsignergroupmembershipCreateObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignsignergroupmembershipCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignsignergroupmembershipCreateObjectV1(ezsignsignergroupmembershipCreateObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignsignergroupmembershipApi.ezsignsignergroupmembershipCreateObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Delete an existing Ezsignsignergroupmembership
         * @param {number} pkiEzsignsignergroupmembershipID The unique ID of the Ezsignsignergroupmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignsignergroupmembershipDeleteObjectV1(pkiEzsignsignergroupmembershipID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignsignergroupmembershipDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignsignergroupmembershipDeleteObjectV1(pkiEzsignsignergroupmembershipID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignsignergroupmembershipApi.ezsignsignergroupmembershipDeleteObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignsignergroupmembership
         * @param {number} pkiEzsignsignergroupmembershipID The unique ID of the Ezsignsignergroupmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignsignergroupmembershipGetObjectV2(pkiEzsignsignergroupmembershipID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignsignergroupmembershipGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignsignergroupmembershipGetObjectV2(pkiEzsignsignergroupmembershipID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzsignsignergroupmembershipApi.ezsignsignergroupmembershipGetObjectV2']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectEzsignsignergroupmembershipApi - factory interface
 * @export
 */
export const ObjectEzsignsignergroupmembershipApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignsignergroupmembershipApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignsignergroupmembership
         * @param {EzsignsignergroupmembershipCreateObjectV1Request} ezsignsignergroupmembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsignergroupmembershipCreateObjectV1(ezsignsignergroupmembershipCreateObjectV1Request: EzsignsignergroupmembershipCreateObjectV1Request, options?: RawAxiosRequestConfig): AxiosPromise<EzsignsignergroupmembershipCreateObjectV1Response> {
            return localVarFp.ezsignsignergroupmembershipCreateObjectV1(ezsignsignergroupmembershipCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsignsignergroupmembership
         * @param {number} pkiEzsignsignergroupmembershipID The unique ID of the Ezsignsignergroupmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsignergroupmembershipDeleteObjectV1(pkiEzsignsignergroupmembershipID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsignsignergroupmembershipDeleteObjectV1Response> {
            return localVarFp.ezsignsignergroupmembershipDeleteObjectV1(pkiEzsignsignergroupmembershipID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignsignergroupmembership
         * @param {number} pkiEzsignsignergroupmembershipID The unique ID of the Ezsignsignergroupmembership
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignsignergroupmembershipGetObjectV2(pkiEzsignsignergroupmembershipID: number, options?: RawAxiosRequestConfig): AxiosPromise<EzsignsignergroupmembershipGetObjectV2Response> {
            return localVarFp.ezsignsignergroupmembershipGetObjectV2(pkiEzsignsignergroupmembershipID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignsignergroupmembershipApi - object-oriented interface
 * @export
 * @class ObjectEzsignsignergroupmembershipApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignsignergroupmembershipApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsignsignergroupmembership
     * @param {EzsignsignergroupmembershipCreateObjectV1Request} ezsignsignergroupmembershipCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignsignergroupmembershipApi
     */
    public ezsignsignergroupmembershipCreateObjectV1(ezsignsignergroupmembershipCreateObjectV1Request: EzsignsignergroupmembershipCreateObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectEzsignsignergroupmembershipApiFp(this.configuration).ezsignsignergroupmembershipCreateObjectV1(ezsignsignergroupmembershipCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsignsignergroupmembership
     * @param {number} pkiEzsignsignergroupmembershipID The unique ID of the Ezsignsignergroupmembership
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignsignergroupmembershipApi
     */
    public ezsignsignergroupmembershipDeleteObjectV1(pkiEzsignsignergroupmembershipID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignsignergroupmembershipApiFp(this.configuration).ezsignsignergroupmembershipDeleteObjectV1(pkiEzsignsignergroupmembershipID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignsignergroupmembership
     * @param {number} pkiEzsignsignergroupmembershipID The unique ID of the Ezsignsignergroupmembership
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignsignergroupmembershipApi
     */
    public ezsignsignergroupmembershipGetObjectV2(pkiEzsignsignergroupmembershipID: number, options?: RawAxiosRequestConfig) {
        return ObjectEzsignsignergroupmembershipApiFp(this.configuration).ezsignsignergroupmembershipGetObjectV2(pkiEzsignsignergroupmembershipID, options).then((request) => request(this.axios, this.basePath));
    }
}

