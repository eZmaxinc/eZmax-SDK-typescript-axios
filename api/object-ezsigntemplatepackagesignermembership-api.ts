/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
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
import { EzsigntemplatepackagesignermembershipCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsigntemplatepackagesignermembershipCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplatepackagesignermembershipDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsigntemplatepackagesignermembershipGetObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsigntemplatepackagesignermembershipApi - axios parameter creator
 * @export
 */
export const ObjectEzsigntemplatepackagesignermembershipApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatepackagesignermembership
         * @param {EzsigntemplatepackagesignermembershipCreateObjectV1Request} ezsigntemplatepackagesignermembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagesignermembershipCreateObjectV1: async (ezsigntemplatepackagesignermembershipCreateObjectV1Request: EzsigntemplatepackagesignermembershipCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsigntemplatepackagesignermembershipCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsigntemplatepackagesignermembershipCreateObjectV1', 'ezsigntemplatepackagesignermembershipCreateObjectV1Request', ezsigntemplatepackagesignermembershipCreateObjectV1Request)
            const localVarPath = `/1/object/ezsigntemplatepackagesignermembership`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigntemplatepackagesignermembershipCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Ezsigntemplatepackagesignermembership
         * @param {number} pkiEzsigntemplatepackagesignermembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagesignermembershipDeleteObjectV1: async (pkiEzsigntemplatepackagesignermembershipID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatepackagesignermembershipID' is not null or undefined
            assertParamExists('ezsigntemplatepackagesignermembershipDeleteObjectV1', 'pkiEzsigntemplatepackagesignermembershipID', pkiEzsigntemplatepackagesignermembershipID)
            const localVarPath = `/1/object/ezsigntemplatepackagesignermembership/{pkiEzsigntemplatepackagesignermembershipID}`
                .replace(`{${"pkiEzsigntemplatepackagesignermembershipID"}}`, encodeURIComponent(String(pkiEzsigntemplatepackagesignermembershipID)));
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
         * @summary Retrieve an existing Ezsigntemplatepackagesignermembership
         * @param {number} pkiEzsigntemplatepackagesignermembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagesignermembershipGetObjectV1: async (pkiEzsigntemplatepackagesignermembershipID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigntemplatepackagesignermembershipID' is not null or undefined
            assertParamExists('ezsigntemplatepackagesignermembershipGetObjectV1', 'pkiEzsigntemplatepackagesignermembershipID', pkiEzsigntemplatepackagesignermembershipID)
            const localVarPath = `/1/object/ezsigntemplatepackagesignermembership/{pkiEzsigntemplatepackagesignermembershipID}`
                .replace(`{${"pkiEzsigntemplatepackagesignermembershipID"}}`, encodeURIComponent(String(pkiEzsigntemplatepackagesignermembershipID)));
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
 * ObjectEzsigntemplatepackagesignermembershipApi - functional programming interface
 * @export
 */
export const ObjectEzsigntemplatepackagesignermembershipApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsigntemplatepackagesignermembershipApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatepackagesignermembership
         * @param {EzsigntemplatepackagesignermembershipCreateObjectV1Request} ezsigntemplatepackagesignermembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatepackagesignermembershipCreateObjectV1(ezsigntemplatepackagesignermembershipCreateObjectV1Request: EzsigntemplatepackagesignermembershipCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatepackagesignermembershipCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatepackagesignermembershipCreateObjectV1(ezsigntemplatepackagesignermembershipCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplatepackagesignermembership
         * @param {number} pkiEzsigntemplatepackagesignermembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatepackagesignermembershipDeleteObjectV1(pkiEzsigntemplatepackagesignermembershipID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatepackagesignermembershipDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatepackagesignermembershipDeleteObjectV1(pkiEzsigntemplatepackagesignermembershipID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplatepackagesignermembership
         * @param {number} pkiEzsigntemplatepackagesignermembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigntemplatepackagesignermembershipGetObjectV1(pkiEzsigntemplatepackagesignermembershipID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigntemplatepackagesignermembershipGetObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigntemplatepackagesignermembershipGetObjectV1(pkiEzsigntemplatepackagesignermembershipID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsigntemplatepackagesignermembershipApi - factory interface
 * @export
 */
export const ObjectEzsigntemplatepackagesignermembershipApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsigntemplatepackagesignermembershipApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsigntemplatepackagesignermembership
         * @param {EzsigntemplatepackagesignermembershipCreateObjectV1Request} ezsigntemplatepackagesignermembershipCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagesignermembershipCreateObjectV1(ezsigntemplatepackagesignermembershipCreateObjectV1Request: EzsigntemplatepackagesignermembershipCreateObjectV1Request, options?: any): AxiosPromise<EzsigntemplatepackagesignermembershipCreateObjectV1Response> {
            return localVarFp.ezsigntemplatepackagesignermembershipCreateObjectV1(ezsigntemplatepackagesignermembershipCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsigntemplatepackagesignermembership
         * @param {number} pkiEzsigntemplatepackagesignermembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagesignermembershipDeleteObjectV1(pkiEzsigntemplatepackagesignermembershipID: number, options?: any): AxiosPromise<EzsigntemplatepackagesignermembershipDeleteObjectV1Response> {
            return localVarFp.ezsigntemplatepackagesignermembershipDeleteObjectV1(pkiEzsigntemplatepackagesignermembershipID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigntemplatepackagesignermembership
         * @param {number} pkiEzsigntemplatepackagesignermembershipID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigntemplatepackagesignermembershipGetObjectV1(pkiEzsigntemplatepackagesignermembershipID: number, options?: any): AxiosPromise<EzsigntemplatepackagesignermembershipGetObjectV1Response> {
            return localVarFp.ezsigntemplatepackagesignermembershipGetObjectV1(pkiEzsigntemplatepackagesignermembershipID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsigntemplatepackagesignermembershipApi - object-oriented interface
 * @export
 * @class ObjectEzsigntemplatepackagesignermembershipApi
 * @extends {BaseAPI}
 */
export class ObjectEzsigntemplatepackagesignermembershipApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsigntemplatepackagesignermembership
     * @param {EzsigntemplatepackagesignermembershipCreateObjectV1Request} ezsigntemplatepackagesignermembershipCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatepackagesignermembershipApi
     */
    public ezsigntemplatepackagesignermembershipCreateObjectV1(ezsigntemplatepackagesignermembershipCreateObjectV1Request: EzsigntemplatepackagesignermembershipCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatepackagesignermembershipApiFp(this.configuration).ezsigntemplatepackagesignermembershipCreateObjectV1(ezsigntemplatepackagesignermembershipCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsigntemplatepackagesignermembership
     * @param {number} pkiEzsigntemplatepackagesignermembershipID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatepackagesignermembershipApi
     */
    public ezsigntemplatepackagesignermembershipDeleteObjectV1(pkiEzsigntemplatepackagesignermembershipID: number, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatepackagesignermembershipApiFp(this.configuration).ezsigntemplatepackagesignermembershipDeleteObjectV1(pkiEzsigntemplatepackagesignermembershipID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsigntemplatepackagesignermembership
     * @param {number} pkiEzsigntemplatepackagesignermembershipID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigntemplatepackagesignermembershipApi
     */
    public ezsigntemplatepackagesignermembershipGetObjectV1(pkiEzsigntemplatepackagesignermembershipID: number, options?: AxiosRequestConfig) {
        return ObjectEzsigntemplatepackagesignermembershipApiFp(this.configuration).ezsigntemplatepackagesignermembershipGetObjectV1(pkiEzsigntemplatepackagesignermembershipID, options).then((request) => request(this.axios, this.basePath));
    }
}
