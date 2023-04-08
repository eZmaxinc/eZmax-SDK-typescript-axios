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
import { EzsignbulksendsignermappingCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsignbulksendsignermappingCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsignbulksendsignermappingDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsignbulksendsignermappingGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignbulksendsignermappingApi - axios parameter creator
 * @export
 */
export const ObjectEzsignbulksendsignermappingApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignbulksendsignermapping
         * @param {EzsignbulksendsignermappingCreateObjectV1Request} ezsignbulksendsignermappingCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendsignermappingCreateObjectV1: async (ezsignbulksendsignermappingCreateObjectV1Request: EzsignbulksendsignermappingCreateObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignbulksendsignermappingCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsignbulksendsignermappingCreateObjectV1', 'ezsignbulksendsignermappingCreateObjectV1Request', ezsignbulksendsignermappingCreateObjectV1Request)
            const localVarPath = `/1/object/ezsignbulksendsignermapping`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignbulksendsignermappingCreateObjectV1Request, localVarRequestOptions, configuration)

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
         * @summary Delete an existing Ezsignbulksendsignermapping
         * @param {number} pkiEzsignbulksendsignermappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendsignermappingDeleteObjectV1: async (pkiEzsignbulksendsignermappingID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignbulksendsignermappingID' is not null or undefined
            assertParamExists('ezsignbulksendsignermappingDeleteObjectV1', 'pkiEzsignbulksendsignermappingID', pkiEzsignbulksendsignermappingID)
            const localVarPath = `/1/object/ezsignbulksendsignermapping/{pkiEzsignbulksendsignermappingID}`
                .replace(`{${"pkiEzsignbulksendsignermappingID"}}`, encodeURIComponent(String(pkiEzsignbulksendsignermappingID)));
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
         * @summary Retrieve an existing Ezsignbulksendsignermapping
         * @param {number} pkiEzsignbulksendsignermappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendsignermappingGetObjectV2: async (pkiEzsignbulksendsignermappingID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignbulksendsignermappingID' is not null or undefined
            assertParamExists('ezsignbulksendsignermappingGetObjectV2', 'pkiEzsignbulksendsignermappingID', pkiEzsignbulksendsignermappingID)
            const localVarPath = `/2/object/ezsignbulksendsignermapping/{pkiEzsignbulksendsignermappingID}`
                .replace(`{${"pkiEzsignbulksendsignermappingID"}}`, encodeURIComponent(String(pkiEzsignbulksendsignermappingID)));
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
 * ObjectEzsignbulksendsignermappingApi - functional programming interface
 * @export
 */
export const ObjectEzsignbulksendsignermappingApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignbulksendsignermappingApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignbulksendsignermapping
         * @param {EzsignbulksendsignermappingCreateObjectV1Request} ezsignbulksendsignermappingCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksendsignermappingCreateObjectV1(ezsignbulksendsignermappingCreateObjectV1Request: EzsignbulksendsignermappingCreateObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignbulksendsignermappingCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksendsignermappingCreateObjectV1(ezsignbulksendsignermappingCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Ezsignbulksendsignermapping
         * @param {number} pkiEzsignbulksendsignermappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksendsignermappingDeleteObjectV1(pkiEzsignbulksendsignermappingID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignbulksendsignermappingDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksendsignermappingDeleteObjectV1(pkiEzsignbulksendsignermappingID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendsignermapping
         * @param {number} pkiEzsignbulksendsignermappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksendsignermappingGetObjectV2(pkiEzsignbulksendsignermappingID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignbulksendsignermappingGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksendsignermappingGetObjectV2(pkiEzsignbulksendsignermappingID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsignbulksendsignermappingApi - factory interface
 * @export
 */
export const ObjectEzsignbulksendsignermappingApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignbulksendsignermappingApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignbulksendsignermapping
         * @param {EzsignbulksendsignermappingCreateObjectV1Request} ezsignbulksendsignermappingCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendsignermappingCreateObjectV1(ezsignbulksendsignermappingCreateObjectV1Request: EzsignbulksendsignermappingCreateObjectV1Request, options?: any): AxiosPromise<EzsignbulksendsignermappingCreateObjectV1Response> {
            return localVarFp.ezsignbulksendsignermappingCreateObjectV1(ezsignbulksendsignermappingCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsignbulksendsignermapping
         * @param {number} pkiEzsignbulksendsignermappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendsignermappingDeleteObjectV1(pkiEzsignbulksendsignermappingID: number, options?: any): AxiosPromise<EzsignbulksendsignermappingDeleteObjectV1Response> {
            return localVarFp.ezsignbulksendsignermappingDeleteObjectV1(pkiEzsignbulksendsignermappingID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendsignermapping
         * @param {number} pkiEzsignbulksendsignermappingID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendsignermappingGetObjectV2(pkiEzsignbulksendsignermappingID: number, options?: any): AxiosPromise<EzsignbulksendsignermappingGetObjectV2Response> {
            return localVarFp.ezsignbulksendsignermappingGetObjectV2(pkiEzsignbulksendsignermappingID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignbulksendsignermappingApi - object-oriented interface
 * @export
 * @class ObjectEzsignbulksendsignermappingApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignbulksendsignermappingApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsignbulksendsignermapping
     * @param {EzsignbulksendsignermappingCreateObjectV1Request} ezsignbulksendsignermappingCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksendsignermappingApi
     */
    public ezsignbulksendsignermappingCreateObjectV1(ezsignbulksendsignermappingCreateObjectV1Request: EzsignbulksendsignermappingCreateObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsignbulksendsignermappingApiFp(this.configuration).ezsignbulksendsignermappingCreateObjectV1(ezsignbulksendsignermappingCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsignbulksendsignermapping
     * @param {number} pkiEzsignbulksendsignermappingID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksendsignermappingApi
     */
    public ezsignbulksendsignermappingDeleteObjectV1(pkiEzsignbulksendsignermappingID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignbulksendsignermappingApiFp(this.configuration).ezsignbulksendsignermappingDeleteObjectV1(pkiEzsignbulksendsignermappingID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignbulksendsignermapping
     * @param {number} pkiEzsignbulksendsignermappingID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksendsignermappingApi
     */
    public ezsignbulksendsignermappingGetObjectV2(pkiEzsignbulksendsignermappingID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignbulksendsignermappingApiFp(this.configuration).ezsignbulksendsignermappingGetObjectV2(pkiEzsignbulksendsignermappingID, options).then((request) => request(this.axios, this.basePath));
    }
}
