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
import { CommonResponseError } from '../model';
// @ts-ignore
import { EzsignformfieldgroupCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsignformfieldgroupCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsignformfieldgroupDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsignformfieldgroupEditObjectV1Request } from '../model';
// @ts-ignore
import { EzsignformfieldgroupEditObjectV1Response } from '../model';
// @ts-ignore
import { EzsignformfieldgroupGetObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignformfieldgroupApi - axios parameter creator
 * @export
 */
export const ObjectEzsignformfieldgroupApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignformfieldgroup
         * @param {EzsignformfieldgroupCreateObjectV1Request} ezsignformfieldgroupCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignformfieldgroupCreateObjectV1: async (ezsignformfieldgroupCreateObjectV1Request: EzsignformfieldgroupCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignformfieldgroupCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsignformfieldgroupCreateObjectV1', 'ezsignformfieldgroupCreateObjectV1Request', ezsignformfieldgroupCreateObjectV1Request)
            const localVarPath = `/1/object/ezsignformfieldgroup`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
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
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignformfieldgroupCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignformfieldgroupDeleteObjectV1: async (pkiEzsignformfieldgroupID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignformfieldgroupID' is not null or undefined
            assertParamExists('ezsignformfieldgroupDeleteObjectV1', 'pkiEzsignformfieldgroupID', pkiEzsignformfieldgroupID)
            const localVarPath = `/1/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID}`
                .replace(`{${"pkiEzsignformfieldgroupID"}}`, encodeURIComponent(String(pkiEzsignformfieldgroupID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
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
         * @summary Edit an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {EzsignformfieldgroupEditObjectV1Request} ezsignformfieldgroupEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignformfieldgroupEditObjectV1: async (pkiEzsignformfieldgroupID: number, ezsignformfieldgroupEditObjectV1Request: EzsignformfieldgroupEditObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignformfieldgroupID' is not null or undefined
            assertParamExists('ezsignformfieldgroupEditObjectV1', 'pkiEzsignformfieldgroupID', pkiEzsignformfieldgroupID)
            // verify required parameter 'ezsignformfieldgroupEditObjectV1Request' is not null or undefined
            assertParamExists('ezsignformfieldgroupEditObjectV1', 'ezsignformfieldgroupEditObjectV1Request', ezsignformfieldgroupEditObjectV1Request)
            const localVarPath = `/1/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID}`
                .replace(`{${"pkiEzsignformfieldgroupID"}}`, encodeURIComponent(String(pkiEzsignformfieldgroupID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
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
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignformfieldgroupEditObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Retrieve an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignformfieldgroupGetObjectV1: async (pkiEzsignformfieldgroupID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignformfieldgroupID' is not null or undefined
            assertParamExists('ezsignformfieldgroupGetObjectV1', 'pkiEzsignformfieldgroupID', pkiEzsignformfieldgroupID)
            const localVarPath = `/1/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID}`
                .replace(`{${"pkiEzsignformfieldgroupID"}}`, encodeURIComponent(String(pkiEzsignformfieldgroupID)));
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
    }
};

/**
 * ObjectEzsignformfieldgroupApi - functional programming interface
 * @export
 */
export const ObjectEzsignformfieldgroupApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignformfieldgroupApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignformfieldgroup
         * @param {EzsignformfieldgroupCreateObjectV1Request} ezsignformfieldgroupCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignformfieldgroupCreateObjectV1(ezsignformfieldgroupCreateObjectV1Request: EzsignformfieldgroupCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignformfieldgroupCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignformfieldgroupCreateObjectV1(ezsignformfieldgroupCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignformfieldgroupDeleteObjectV1(pkiEzsignformfieldgroupID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignformfieldgroupDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignformfieldgroupDeleteObjectV1(pkiEzsignformfieldgroupID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Edit an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {EzsignformfieldgroupEditObjectV1Request} ezsignformfieldgroupEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignformfieldgroupEditObjectV1(pkiEzsignformfieldgroupID: number, ezsignformfieldgroupEditObjectV1Request: EzsignformfieldgroupEditObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignformfieldgroupEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignformfieldgroupEditObjectV1(pkiEzsignformfieldgroupID, ezsignformfieldgroupEditObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignformfieldgroupGetObjectV1(pkiEzsignformfieldgroupID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignformfieldgroupGetObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignformfieldgroupGetObjectV1(pkiEzsignformfieldgroupID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsignformfieldgroupApi - factory interface
 * @export
 */
export const ObjectEzsignformfieldgroupApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignformfieldgroupApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignformfieldgroup
         * @param {EzsignformfieldgroupCreateObjectV1Request} ezsignformfieldgroupCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignformfieldgroupCreateObjectV1(ezsignformfieldgroupCreateObjectV1Request: EzsignformfieldgroupCreateObjectV1Request, options?: any): AxiosPromise<EzsignformfieldgroupCreateObjectV1Response> {
            return localVarFp.ezsignformfieldgroupCreateObjectV1(ezsignformfieldgroupCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignformfieldgroupDeleteObjectV1(pkiEzsignformfieldgroupID: number, options?: any): AxiosPromise<EzsignformfieldgroupDeleteObjectV1Response> {
            return localVarFp.ezsignformfieldgroupDeleteObjectV1(pkiEzsignformfieldgroupID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {EzsignformfieldgroupEditObjectV1Request} ezsignformfieldgroupEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignformfieldgroupEditObjectV1(pkiEzsignformfieldgroupID: number, ezsignformfieldgroupEditObjectV1Request: EzsignformfieldgroupEditObjectV1Request, options?: any): AxiosPromise<EzsignformfieldgroupEditObjectV1Response> {
            return localVarFp.ezsignformfieldgroupEditObjectV1(pkiEzsignformfieldgroupID, ezsignformfieldgroupEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignformfieldgroup
         * @param {number} pkiEzsignformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignformfieldgroupGetObjectV1(pkiEzsignformfieldgroupID: number, options?: any): AxiosPromise<EzsignformfieldgroupGetObjectV1Response> {
            return localVarFp.ezsignformfieldgroupGetObjectV1(pkiEzsignformfieldgroupID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignformfieldgroupApi - object-oriented interface
 * @export
 * @class ObjectEzsignformfieldgroupApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignformfieldgroupApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsignformfieldgroup
     * @param {EzsignformfieldgroupCreateObjectV1Request} ezsignformfieldgroupCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignformfieldgroupApi
     */
    public ezsignformfieldgroupCreateObjectV1(ezsignformfieldgroupCreateObjectV1Request: EzsignformfieldgroupCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsignformfieldgroupApiFp(this.configuration).ezsignformfieldgroupCreateObjectV1(ezsignformfieldgroupCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsignformfieldgroup
     * @param {number} pkiEzsignformfieldgroupID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignformfieldgroupApi
     */
    public ezsignformfieldgroupDeleteObjectV1(pkiEzsignformfieldgroupID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignformfieldgroupApiFp(this.configuration).ezsignformfieldgroupDeleteObjectV1(pkiEzsignformfieldgroupID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Ezsignformfieldgroup
     * @param {number} pkiEzsignformfieldgroupID 
     * @param {EzsignformfieldgroupEditObjectV1Request} ezsignformfieldgroupEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignformfieldgroupApi
     */
    public ezsignformfieldgroupEditObjectV1(pkiEzsignformfieldgroupID: number, ezsignformfieldgroupEditObjectV1Request: EzsignformfieldgroupEditObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsignformfieldgroupApiFp(this.configuration).ezsignformfieldgroupEditObjectV1(pkiEzsignformfieldgroupID, ezsignformfieldgroupEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignformfieldgroup
     * @param {number} pkiEzsignformfieldgroupID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignformfieldgroupApi
     */
    public ezsignformfieldgroupGetObjectV1(pkiEzsignformfieldgroupID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignformfieldgroupApiFp(this.configuration).ezsignformfieldgroupGetObjectV1(pkiEzsignformfieldgroupID, options).then((request) => request(this.axios, this.basePath));
    }
}
