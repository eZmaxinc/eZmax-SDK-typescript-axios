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


import type { Configuration } from '../configuration';
import type { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';
import globalAxios from 'axios';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { EzsigntemplatepackagemembershipCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsigntemplatepackagemembershipCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplatepackagemembershipDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplatepackagemembershipGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsigntemplatepackagemembershipApi - axios parameter creator
 * @export
 */
export const ObjectEzsigntemplatepackagemembershipApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatepackagemembership
         * @param {EzsigntemplatepackagemembershipCreateObjectV1Request} ezsigntemplatepackagemembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagemembershipCreateObjectV1: async (ezsigntemplatepackagemembershipCreateObjectV1Request: EzsigntemplatepackagemembershipCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsigntemplatepackagemembershipCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsigntemplatepackagemembershipCreateObjectV1', 'ezsigntemplatepackagemembershipCreateObjectV1Request', ezsigntemplatepackagemembershipCreateObjectV1Request)
            const localVarPath = `/1/object/ezsigntemplatepackagemembership`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigntemplatepackagemembershipCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Ezsigntemplatepackagemembership
         * @param {number} pkiEzsigntemplatepackagemembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagemembershipDeleteObjectV1: async (pkiEzsigntemplatepackagemembershipID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatepackagemembershipID' is not null or undefined
            assertParamExists('ezsigntemplatepackagemembershipDeleteObjectV1', 'pkiEzsigntemplatepackagemembershipID', pkiEzsigntemplatepackagemembershipID)
            const localVarPath = `/1/object/ezsigntemplatepackagemembership/{pkiEzsigntemplatepackagemembershipID}`
                .replace(`{${"pkiEzsigntemplatepackagemembershipID"}}`, encodeURIComponent(String(pkiEzsigntemplatepackagemembershipID)));
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
         * @summary Retrieve an existing Ezsigntemplatepackagemembership
         * @param {number} pkiEzsigntemplatepackagemembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagemembershipGetObjectV2: async (pkiEzsigntemplatepackagemembershipID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatepackagemembershipID' is not null or undefined
            assertParamExists('ezsigntemplatepackagemembershipGetObjectV2', 'pkiEzsigntemplatepackagemembershipID', pkiEzsigntemplatepackagemembershipID)
            const localVarPath = `/2/object/ezsigntemplatepackagemembership/{pkiEzsigntemplatepackagemembershipID}`
                .replace(`{${"pkiEzsigntemplatepackagemembershipID"}}`, encodeURIComponent(String(pkiEzsigntemplatepackagemembershipID)));
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
 * ObjectEzsigntemplatepackagemembershipApi - functional programming interface
 * @export
 */
export const ObjectEzsigntemplatepackagemembershipApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsigntemplatepackagemembershipApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatepackagemembership
         * @param {EzsigntemplatepackagemembershipCreateObjectV1Request} ezsigntemplatepackagemembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatepackagemembershipCreateObjectV1(ezsigntemplatepackagemembershipCreateObjectV1Request: EzsigntemplatepackagemembershipCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatepackagemembershipCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatepackagemembershipCreateObjectV1(ezsigntemplatepackagemembershipCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplatepackagemembership
         * @param {number} pkiEzsigntemplatepackagemembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatepackagemembershipDeleteObjectV1(pkiEzsigntemplatepackagemembershipID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatepackagemembershipDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatepackagemembershipDeleteObjectV1(pkiEzsigntemplatepackagemembershipID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplatepackagemembership
         * @param {number} pkiEzsigntemplatepackagemembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatepackagemembershipGetObjectV2(pkiEzsigntemplatepackagemembershipID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatepackagemembershipGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatepackagemembershipGetObjectV2(pkiEzsigntemplatepackagemembershipID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsigntemplatepackagemembershipApi - factory interface
 * @export
 */
export const ObjectEzsigntemplatepackagemembershipApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsigntemplatepackagemembershipApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatepackagemembership
         * @param {EzsigntemplatepackagemembershipCreateObjectV1Request} ezsigntemplatepackagemembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagemembershipCreateObjectV1(ezsigntemplatepackagemembershipCreateObjectV1Request: EzsigntemplatepackagemembershipCreateObjectV1Request, options?: any): AxiosPromise<EzsigntemplatepackagemembershipCreateObjectV1Response> {
            return localVarFp.ezsigntemplatepackagemembershipCreateObjectV1(ezsigntemplatepackagemembershipCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplatepackagemembership
         * @param {number} pkiEzsigntemplatepackagemembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagemembershipDeleteObjectV1(pkiEzsigntemplatepackagemembershipID: number, options?: any): AxiosPromise<EzsigntemplatepackagemembershipDeleteObjectV1Response> {
            return localVarFp.ezsigntemplatepackagemembershipDeleteObjectV1(pkiEzsigntemplatepackagemembershipID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplatepackagemembership
         * @param {number} pkiEzsigntemplatepackagemembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagemembershipGetObjectV2(pkiEzsigntemplatepackagemembershipID: number, options?: any): AxiosPromise<EzsigntemplatepackagemembershipGetObjectV2Response> {
            return localVarFp.ezsigntemplatepackagemembershipGetObjectV2(pkiEzsigntemplatepackagemembershipID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsigntemplatepackagemembershipApi - object-oriented interface
 * @export
 * @class ObjectEzsigntemplatepackagemembershipApi
 * @extends {BaseAPI}
 */
export class ObjectEzsigntemplatepackagemembershipApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsigntemplatepackagemembership
     * @param {EzsigntemplatepackagemembershipCreateObjectV1Request} ezsigntemplatepackagemembershipCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatepackagemembershipApi
     */
    public ezsigntemplatepackagemembershipCreateObjectV1(ezsigntemplatepackagemembershipCreateObjectV1Request: EzsigntemplatepackagemembershipCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatepackagemembershipApiFp(this.configuration).ezsigntemplatepackagemembershipCreateObjectV1(ezsigntemplatepackagemembershipCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsigntemplatepackagemembership
     * @param {number} pkiEzsigntemplatepackagemembershipID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatepackagemembershipApi
     */
    public ezsigntemplatepackagemembershipDeleteObjectV1(pkiEzsigntemplatepackagemembershipID: number, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatepackagemembershipApiFp(this.configuration).ezsigntemplatepackagemembershipDeleteObjectV1(pkiEzsigntemplatepackagemembershipID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsigntemplatepackagemembership
     * @param {number} pkiEzsigntemplatepackagemembershipID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatepackagemembershipApi
     */
    public ezsigntemplatepackagemembershipGetObjectV2(pkiEzsigntemplatepackagemembershipID: number, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatepackagemembershipApiFp(this.configuration).ezsigntemplatepackagemembershipGetObjectV2(pkiEzsigntemplatepackagemembershipID, options).then((request) => request(this.axios, this.basePath));
    }
}
