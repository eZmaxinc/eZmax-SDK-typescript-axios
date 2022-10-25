/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
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
import { EzsigntemplateformfieldgroupCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsigntemplateformfieldgroupCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplateformfieldgroupDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplateformfieldgroupEditObjectV1Request } from '../model';
// @ts-ignore
import { EzsigntemplateformfieldgroupEditObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplateformfieldgroupGetObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsigntemplateformfieldgroupApi - axios parameter creator
 * @export
 */
export const ObjectEzsigntemplateformfieldgroupApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplateformfieldgroup
         * @param {EzsigntemplateformfieldgroupCreateObjectV1Request} ezsigntemplateformfieldgroupCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplateformfieldgroupCreateObjectV1: async (ezsigntemplateformfieldgroupCreateObjectV1Request: EzsigntemplateformfieldgroupCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsigntemplateformfieldgroupCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsigntemplateformfieldgroupCreateObjectV1', 'ezsigntemplateformfieldgroupCreateObjectV1Request', ezsigntemplateformfieldgroupCreateObjectV1Request)
            const localVarPath = `/1/object/ezsigntemplateformfieldgroup`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigntemplateformfieldgroupCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplateformfieldgroupDeleteObjectV1: async (pkiEzsigntemplateformfieldgroupID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplateformfieldgroupID' is not null or undefined
            assertParamExists('ezsigntemplateformfieldgroupDeleteObjectV1', 'pkiEzsigntemplateformfieldgroupID', pkiEzsigntemplateformfieldgroupID)
            const localVarPath = `/1/object/ezsigntemplateformfieldgroup/{pkiEzsigntemplateformfieldgroupID}`
                .replace(`{${"pkiEzsigntemplateformfieldgroupID"}}`, encodeURIComponent(String(pkiEzsigntemplateformfieldgroupID)));
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
         * @summary Edit an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {EzsigntemplateformfieldgroupEditObjectV1Request} ezsigntemplateformfieldgroupEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplateformfieldgroupEditObjectV1: async (pkiEzsigntemplateformfieldgroupID: number, ezsigntemplateformfieldgroupEditObjectV1Request: EzsigntemplateformfieldgroupEditObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplateformfieldgroupID' is not null or undefined
            assertParamExists('ezsigntemplateformfieldgroupEditObjectV1', 'pkiEzsigntemplateformfieldgroupID', pkiEzsigntemplateformfieldgroupID)
            // verify required parameter 'ezsigntemplateformfieldgroupEditObjectV1Request' is not null or undefined
            assertParamExists('ezsigntemplateformfieldgroupEditObjectV1', 'ezsigntemplateformfieldgroupEditObjectV1Request', ezsigntemplateformfieldgroupEditObjectV1Request)
            const localVarPath = `/1/object/ezsigntemplateformfieldgroup/{pkiEzsigntemplateformfieldgroupID}`
                .replace(`{${"pkiEzsigntemplateformfieldgroupID"}}`, encodeURIComponent(String(pkiEzsigntemplateformfieldgroupID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigntemplateformfieldgroupEditObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Retrieve an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplateformfieldgroupGetObjectV1: async (pkiEzsigntemplateformfieldgroupID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplateformfieldgroupID' is not null or undefined
            assertParamExists('ezsigntemplateformfieldgroupGetObjectV1', 'pkiEzsigntemplateformfieldgroupID', pkiEzsigntemplateformfieldgroupID)
            const localVarPath = `/1/object/ezsigntemplateformfieldgroup/{pkiEzsigntemplateformfieldgroupID}`
                .replace(`{${"pkiEzsigntemplateformfieldgroupID"}}`, encodeURIComponent(String(pkiEzsigntemplateformfieldgroupID)));
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
 * ObjectEzsigntemplateformfieldgroupApi - functional programming interface
 * @export
 */
export const ObjectEzsigntemplateformfieldgroupApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsigntemplateformfieldgroupApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplateformfieldgroup
         * @param {EzsigntemplateformfieldgroupCreateObjectV1Request} ezsigntemplateformfieldgroupCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplateformfieldgroupCreateObjectV1(ezsigntemplateformfieldgroupCreateObjectV1Request: EzsigntemplateformfieldgroupCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplateformfieldgroupCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplateformfieldgroupCreateObjectV1(ezsigntemplateformfieldgroupCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplateformfieldgroupDeleteObjectV1(pkiEzsigntemplateformfieldgroupID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplateformfieldgroupDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplateformfieldgroupDeleteObjectV1(pkiEzsigntemplateformfieldgroupID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Edit an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {EzsigntemplateformfieldgroupEditObjectV1Request} ezsigntemplateformfieldgroupEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplateformfieldgroupEditObjectV1(pkiEzsigntemplateformfieldgroupID: number, ezsigntemplateformfieldgroupEditObjectV1Request: EzsigntemplateformfieldgroupEditObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplateformfieldgroupEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplateformfieldgroupEditObjectV1(pkiEzsigntemplateformfieldgroupID, ezsigntemplateformfieldgroupEditObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplateformfieldgroupGetObjectV1(pkiEzsigntemplateformfieldgroupID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplateformfieldgroupGetObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplateformfieldgroupGetObjectV1(pkiEzsigntemplateformfieldgroupID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsigntemplateformfieldgroupApi - factory interface
 * @export
 */
export const ObjectEzsigntemplateformfieldgroupApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsigntemplateformfieldgroupApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplateformfieldgroup
         * @param {EzsigntemplateformfieldgroupCreateObjectV1Request} ezsigntemplateformfieldgroupCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplateformfieldgroupCreateObjectV1(ezsigntemplateformfieldgroupCreateObjectV1Request: EzsigntemplateformfieldgroupCreateObjectV1Request, options?: any): AxiosPromise<EzsigntemplateformfieldgroupCreateObjectV1Response> {
            return localVarFp.ezsigntemplateformfieldgroupCreateObjectV1(ezsigntemplateformfieldgroupCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplateformfieldgroupDeleteObjectV1(pkiEzsigntemplateformfieldgroupID: number, options?: any): AxiosPromise<EzsigntemplateformfieldgroupDeleteObjectV1Response> {
            return localVarFp.ezsigntemplateformfieldgroupDeleteObjectV1(pkiEzsigntemplateformfieldgroupID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {EzsigntemplateformfieldgroupEditObjectV1Request} ezsigntemplateformfieldgroupEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplateformfieldgroupEditObjectV1(pkiEzsigntemplateformfieldgroupID: number, ezsigntemplateformfieldgroupEditObjectV1Request: EzsigntemplateformfieldgroupEditObjectV1Request, options?: any): AxiosPromise<EzsigntemplateformfieldgroupEditObjectV1Response> {
            return localVarFp.ezsigntemplateformfieldgroupEditObjectV1(pkiEzsigntemplateformfieldgroupID, ezsigntemplateformfieldgroupEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplateformfieldgroup
         * @param {number} pkiEzsigntemplateformfieldgroupID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplateformfieldgroupGetObjectV1(pkiEzsigntemplateformfieldgroupID: number, options?: any): AxiosPromise<EzsigntemplateformfieldgroupGetObjectV1Response> {
            return localVarFp.ezsigntemplateformfieldgroupGetObjectV1(pkiEzsigntemplateformfieldgroupID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsigntemplateformfieldgroupApi - object-oriented interface
 * @export
 * @class ObjectEzsigntemplateformfieldgroupApi
 * @extends {BaseAPI}
 */
export class ObjectEzsigntemplateformfieldgroupApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsigntemplateformfieldgroup
     * @param {EzsigntemplateformfieldgroupCreateObjectV1Request} ezsigntemplateformfieldgroupCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplateformfieldgroupApi
     */
    public ezsigntemplateformfieldgroupCreateObjectV1(ezsigntemplateformfieldgroupCreateObjectV1Request: EzsigntemplateformfieldgroupCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplateformfieldgroupApiFp(this.configuration).ezsigntemplateformfieldgroupCreateObjectV1(ezsigntemplateformfieldgroupCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsigntemplateformfieldgroup
     * @param {number} pkiEzsigntemplateformfieldgroupID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplateformfieldgroupApi
     */
    public ezsigntemplateformfieldgroupDeleteObjectV1(pkiEzsigntemplateformfieldgroupID: number, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplateformfieldgroupApiFp(this.configuration).ezsigntemplateformfieldgroupDeleteObjectV1(pkiEzsigntemplateformfieldgroupID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Ezsigntemplateformfieldgroup
     * @param {number} pkiEzsigntemplateformfieldgroupID 
     * @param {EzsigntemplateformfieldgroupEditObjectV1Request} ezsigntemplateformfieldgroupEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplateformfieldgroupApi
     */
    public ezsigntemplateformfieldgroupEditObjectV1(pkiEzsigntemplateformfieldgroupID: number, ezsigntemplateformfieldgroupEditObjectV1Request: EzsigntemplateformfieldgroupEditObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplateformfieldgroupApiFp(this.configuration).ezsigntemplateformfieldgroupEditObjectV1(pkiEzsigntemplateformfieldgroupID, ezsigntemplateformfieldgroupEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsigntemplateformfieldgroup
     * @param {number} pkiEzsigntemplateformfieldgroupID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplateformfieldgroupApi
     */
    public ezsigntemplateformfieldgroupGetObjectV1(pkiEzsigntemplateformfieldgroupID: number, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplateformfieldgroupApiFp(this.configuration).ezsigntemplateformfieldgroupGetObjectV1(pkiEzsigntemplateformfieldgroupID, options).then((request) => request(this.axios, this.basePath));
    }
}
