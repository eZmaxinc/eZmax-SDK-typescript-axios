/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { EzsigntemplatesignatureCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsigntemplatesignatureCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplatesignatureDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplatesignatureEditObjectV1Request } from '../model';
// @ts-ignore
import { EzsigntemplatesignatureEditObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplatesignatureGetObjectV2Response } from '../model';
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
         * @param {EzsigntemplatesignatureCreateObjectV1Request} ezsigntemplatesignatureCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureCreateObjectV1: async (ezsigntemplatesignatureCreateObjectV1Request: EzsigntemplatesignatureCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsigntemplatesignatureCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsigntemplatesignatureCreateObjectV1', 'ezsigntemplatesignatureCreateObjectV1Request', ezsigntemplatesignatureCreateObjectV1Request)
            const localVarPath = `/1/object/ezsigntemplatesignature`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigntemplatesignatureCreateObjectV1Request, localVarRequestOptions, configuration)

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
        ezsigntemplatesignatureDeleteObjectV1: async (pkiEzsigntemplatesignatureID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatesignatureID' is not null or undefined
            assertParamExists('ezsigntemplatesignatureDeleteObjectV1', 'pkiEzsigntemplatesignatureID', pkiEzsigntemplatesignatureID)
            const localVarPath = `/1/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}`
                .replace(`{${"pkiEzsigntemplatesignatureID"}}`, encodeURIComponent(String(pkiEzsigntemplatesignatureID)));
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
         * @summary Edit an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {EzsigntemplatesignatureEditObjectV1Request} ezsigntemplatesignatureEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureEditObjectV1: async (pkiEzsigntemplatesignatureID: number, ezsigntemplatesignatureEditObjectV1Request: EzsigntemplatesignatureEditObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatesignatureID' is not null or undefined
            assertParamExists('ezsigntemplatesignatureEditObjectV1', 'pkiEzsigntemplatesignatureID', pkiEzsigntemplatesignatureID)
            // verify required parameter 'ezsigntemplatesignatureEditObjectV1Request' is not null or undefined
            assertParamExists('ezsigntemplatesignatureEditObjectV1', 'ezsigntemplatesignatureEditObjectV1Request', ezsigntemplatesignatureEditObjectV1Request)
            const localVarPath = `/1/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}`
                .replace(`{${"pkiEzsigntemplatesignatureID"}}`, encodeURIComponent(String(pkiEzsigntemplatesignatureID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigntemplatesignatureEditObjectV1Request, localVarRequestOptions, configuration)

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
        ezsigntemplatesignatureGetObjectV2: async (pkiEzsigntemplatesignatureID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatesignatureID' is not null or undefined
            assertParamExists('ezsigntemplatesignatureGetObjectV2', 'pkiEzsigntemplatesignatureID', pkiEzsigntemplatesignatureID)
            const localVarPath = `/2/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}`
                .replace(`{${"pkiEzsigntemplatesignatureID"}}`, encodeURIComponent(String(pkiEzsigntemplatesignatureID)));
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
 * ObjectEzsigntemplatesignatureApi - functional programming interface
 * @export
 */
export const ObjectEzsigntemplatesignatureApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsigntemplatesignatureApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatesignature
         * @param {EzsigntemplatesignatureCreateObjectV1Request} ezsigntemplatesignatureCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatesignatureCreateObjectV1(ezsigntemplatesignatureCreateObjectV1Request: EzsigntemplatesignatureCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatesignatureCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatesignatureCreateObjectV1(ezsigntemplatesignatureCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatesignatureDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Edit an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {EzsigntemplatesignatureEditObjectV1Request} ezsigntemplatesignatureEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatesignatureEditObjectV1(pkiEzsigntemplatesignatureID: number, ezsigntemplatesignatureEditObjectV1Request: EzsigntemplatesignatureEditObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatesignatureEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatesignatureEditObjectV1(pkiEzsigntemplatesignatureID, ezsigntemplatesignatureEditObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatesignatureGetObjectV2(pkiEzsigntemplatesignatureID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatesignatureGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatesignatureGetObjectV2(pkiEzsigntemplatesignatureID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
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
         * @param {EzsigntemplatesignatureCreateObjectV1Request} ezsigntemplatesignatureCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureCreateObjectV1(ezsigntemplatesignatureCreateObjectV1Request: EzsigntemplatesignatureCreateObjectV1Request, options?: any): AxiosPromise<EzsigntemplatesignatureCreateObjectV1Response> {
            return localVarFp.ezsigntemplatesignatureCreateObjectV1(ezsigntemplatesignatureCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID: number, options?: any): AxiosPromise<EzsigntemplatesignatureDeleteObjectV1Response> {
            return localVarFp.ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {EzsigntemplatesignatureEditObjectV1Request} ezsigntemplatesignatureEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureEditObjectV1(pkiEzsigntemplatesignatureID: number, ezsigntemplatesignatureEditObjectV1Request: EzsigntemplatesignatureEditObjectV1Request, options?: any): AxiosPromise<EzsigntemplatesignatureEditObjectV1Response> {
            return localVarFp.ezsigntemplatesignatureEditObjectV1(pkiEzsigntemplatesignatureID, ezsigntemplatesignatureEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplatesignature
         * @param {number} pkiEzsigntemplatesignatureID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatesignatureGetObjectV2(pkiEzsigntemplatesignatureID: number, options?: any): AxiosPromise<EzsigntemplatesignatureGetObjectV2Response> {
            return localVarFp.ezsigntemplatesignatureGetObjectV2(pkiEzsigntemplatesignatureID, options).then((request) => request(axios, basePath));
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
     * @param {EzsigntemplatesignatureCreateObjectV1Request} ezsigntemplatesignatureCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatesignatureApi
     */
    public ezsigntemplatesignatureCreateObjectV1(ezsigntemplatesignatureCreateObjectV1Request: EzsigntemplatesignatureCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatesignatureApiFp(this.configuration).ezsigntemplatesignatureCreateObjectV1(ezsigntemplatesignatureCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsigntemplatesignature
     * @param {number} pkiEzsigntemplatesignatureID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatesignatureApi
     */
    public ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID: number, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatesignatureApiFp(this.configuration).ezsigntemplatesignatureDeleteObjectV1(pkiEzsigntemplatesignatureID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Ezsigntemplatesignature
     * @param {number} pkiEzsigntemplatesignatureID 
     * @param {EzsigntemplatesignatureEditObjectV1Request} ezsigntemplatesignatureEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatesignatureApi
     */
    public ezsigntemplatesignatureEditObjectV1(pkiEzsigntemplatesignatureID: number, ezsigntemplatesignatureEditObjectV1Request: EzsigntemplatesignatureEditObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatesignatureApiFp(this.configuration).ezsigntemplatesignatureEditObjectV1(pkiEzsigntemplatesignatureID, ezsigntemplatesignatureEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsigntemplatesignature
     * @param {number} pkiEzsigntemplatesignatureID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatesignatureApi
     */
    public ezsigntemplatesignatureGetObjectV2(pkiEzsigntemplatesignatureID: number, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatesignatureApiFp(this.configuration).ezsigntemplatesignatureGetObjectV2(pkiEzsigntemplatesignatureID, options).then((request) => request(this.axios, this.basePath));
    }
}
