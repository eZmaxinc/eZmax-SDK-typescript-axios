/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
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
import { ApikeyCreateObjectV1Request } from '../model';
// @ts-ignore
import { ApikeyCreateObjectV1Response } from '../model';
// @ts-ignore
import { ApikeyCreateObjectV2Request } from '../model';
// @ts-ignore
import { ApikeyCreateObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectApikeyApi - axios parameter creator
 * @export
 */
export const ObjectApikeyApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        apikeyCreateObjectV1: async (apikeyCreateObjectV1Request: Array<ApikeyCreateObjectV1Request>, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'apikeyCreateObjectV1Request' is not null or undefined
            assertParamExists('apikeyCreateObjectV1', 'apikeyCreateObjectV1Request', apikeyCreateObjectV1Request)
            const localVarPath = `/1/object/apikey`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(apikeyCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Apikey
         * @param {ApikeyCreateObjectV2Request} apikeyCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV2: async (apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'apikeyCreateObjectV2Request' is not null or undefined
            assertParamExists('apikeyCreateObjectV2', 'apikeyCreateObjectV2Request', apikeyCreateObjectV2Request)
            const localVarPath = `/2/object/apikey`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(apikeyCreateObjectV2Request, localVarRequestOptions, configuration)

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
    }
};

/**
 * ObjectApikeyApi - functional programming interface
 * @export
 */
export const ObjectApikeyApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectApikeyApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        async apikeyCreateObjectV1(apikeyCreateObjectV1Request: Array<ApikeyCreateObjectV1Request>, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.apikeyCreateObjectV1(apikeyCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Apikey
         * @param {ApikeyCreateObjectV2Request} apikeyCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async apikeyCreateObjectV2(apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ApikeyCreateObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.apikeyCreateObjectV2(apikeyCreateObjectV2Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectApikeyApi - factory interface
 * @export
 */
export const ObjectApikeyApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectApikeyApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Apikey
         * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        apikeyCreateObjectV1(apikeyCreateObjectV1Request: Array<ApikeyCreateObjectV1Request>, options?: any): AxiosPromise<ApikeyCreateObjectV1Response> {
            return localVarFp.apikeyCreateObjectV1(apikeyCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Apikey
         * @param {ApikeyCreateObjectV2Request} apikeyCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        apikeyCreateObjectV2(apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request, options?: any): AxiosPromise<ApikeyCreateObjectV2Response> {
            return localVarFp.apikeyCreateObjectV2(apikeyCreateObjectV2Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectApikeyApi - object-oriented interface
 * @export
 * @class ObjectApikeyApi
 * @extends {BaseAPI}
 */
export class ObjectApikeyApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Apikey
     * @param {Array<ApikeyCreateObjectV1Request>} apikeyCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @deprecated
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyCreateObjectV1(apikeyCreateObjectV1Request: Array<ApikeyCreateObjectV1Request>, options?: AxiosRequestConfig) {
        return ObjectApikeyApiFp(this.configuration).apikeyCreateObjectV1(apikeyCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Apikey
     * @param {ApikeyCreateObjectV2Request} apikeyCreateObjectV2Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectApikeyApi
     */
    public apikeyCreateObjectV2(apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request, options?: AxiosRequestConfig) {
        return ObjectApikeyApiFp(this.configuration).apikeyCreateObjectV2(apikeyCreateObjectV2Request, options).then((request) => request(this.axios, this.basePath));
    }
}
