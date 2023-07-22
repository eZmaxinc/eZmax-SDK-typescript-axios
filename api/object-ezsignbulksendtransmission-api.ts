/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
import { EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response } from '../model';
// @ts-ignore
import { EzsignbulksendtransmissionGetFormsDataV1Response } from '../model';
// @ts-ignore
import { EzsignbulksendtransmissionGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignbulksendtransmissionApi - axios parameter creator
 * @export
 */
export const ObjectEzsignbulksendtransmissionApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s Csv containing errors
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendtransmissionGetCsvErrorsV1: async (pkiEzsignbulksendtransmissionID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignbulksendtransmissionID' is not null or undefined
            assertParamExists('ezsignbulksendtransmissionGetCsvErrorsV1', 'pkiEzsignbulksendtransmissionID', pkiEzsignbulksendtransmissionID)
            const localVarPath = `/1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getCsvErrors`
                .replace(`{${"pkiEzsignbulksendtransmissionID"}}`, encodeURIComponent(String(pkiEzsignbulksendtransmissionID)));
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
        /**
         * Return the Ezsignsignatures that can be signed by the current user at the current step in the process
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s automatic Ezsignsignatures
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1: async (pkiEzsignbulksendtransmissionID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignbulksendtransmissionID' is not null or undefined
            assertParamExists('ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1', 'pkiEzsignbulksendtransmissionID', pkiEzsignbulksendtransmissionID)
            const localVarPath = `/1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getEzsignsignaturesAutomatic`
                .replace(`{${"pkiEzsignbulksendtransmissionID"}}`, encodeURIComponent(String(pkiEzsignbulksendtransmissionID)));
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
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s forms data
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendtransmissionGetFormsDataV1: async (pkiEzsignbulksendtransmissionID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignbulksendtransmissionID' is not null or undefined
            assertParamExists('ezsignbulksendtransmissionGetFormsDataV1', 'pkiEzsignbulksendtransmissionID', pkiEzsignbulksendtransmissionID)
            const localVarPath = `/1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getFormsData`
                .replace(`{${"pkiEzsignbulksendtransmissionID"}}`, encodeURIComponent(String(pkiEzsignbulksendtransmissionID)));
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
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendtransmissionGetObjectV2: async (pkiEzsignbulksendtransmissionID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignbulksendtransmissionID' is not null or undefined
            assertParamExists('ezsignbulksendtransmissionGetObjectV2', 'pkiEzsignbulksendtransmissionID', pkiEzsignbulksendtransmissionID)
            const localVarPath = `/2/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}`
                .replace(`{${"pkiEzsignbulksendtransmissionID"}}`, encodeURIComponent(String(pkiEzsignbulksendtransmissionID)));
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
 * ObjectEzsignbulksendtransmissionApi - functional programming interface
 * @export
 */
export const ObjectEzsignbulksendtransmissionApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignbulksendtransmissionApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s Csv containing errors
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksendtransmissionGetCsvErrorsV1(pkiEzsignbulksendtransmissionID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<string>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksendtransmissionGetCsvErrorsV1(pkiEzsignbulksendtransmissionID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * Return the Ezsignsignatures that can be signed by the current user at the current step in the process
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s automatic Ezsignsignatures
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1(pkiEzsignbulksendtransmissionID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1(pkiEzsignbulksendtransmissionID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s forms data
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksendtransmissionGetFormsDataV1(pkiEzsignbulksendtransmissionID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignbulksendtransmissionGetFormsDataV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksendtransmissionGetFormsDataV1(pkiEzsignbulksendtransmissionID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignbulksendtransmissionGetObjectV2(pkiEzsignbulksendtransmissionID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignbulksendtransmissionGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignbulksendtransmissionGetObjectV2(pkiEzsignbulksendtransmissionID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsignbulksendtransmissionApi - factory interface
 * @export
 */
export const ObjectEzsignbulksendtransmissionApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignbulksendtransmissionApiFp(configuration)
    return {
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s Csv containing errors
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendtransmissionGetCsvErrorsV1(pkiEzsignbulksendtransmissionID: number, options?: any): AxiosPromise<string> {
            return localVarFp.ezsignbulksendtransmissionGetCsvErrorsV1(pkiEzsignbulksendtransmissionID, options).then((request) => request(axios, basePath));
        },
        /**
         * Return the Ezsignsignatures that can be signed by the current user at the current step in the process
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s automatic Ezsignsignatures
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1(pkiEzsignbulksendtransmissionID: number, options?: any): AxiosPromise<EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response> {
            return localVarFp.ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1(pkiEzsignbulksendtransmissionID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission\'s forms data
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendtransmissionGetFormsDataV1(pkiEzsignbulksendtransmissionID: number, options?: any): AxiosPromise<EzsignbulksendtransmissionGetFormsDataV1Response> {
            return localVarFp.ezsignbulksendtransmissionGetFormsDataV1(pkiEzsignbulksendtransmissionID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignbulksendtransmission
         * @param {number} pkiEzsignbulksendtransmissionID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignbulksendtransmissionGetObjectV2(pkiEzsignbulksendtransmissionID: number, options?: any): AxiosPromise<EzsignbulksendtransmissionGetObjectV2Response> {
            return localVarFp.ezsignbulksendtransmissionGetObjectV2(pkiEzsignbulksendtransmissionID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignbulksendtransmissionApi - object-oriented interface
 * @export
 * @class ObjectEzsignbulksendtransmissionApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignbulksendtransmissionApi extends BaseAPI {
    /**
     * 
     * @summary Retrieve an existing Ezsignbulksendtransmission\'s Csv containing errors
     * @param {number} pkiEzsignbulksendtransmissionID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksendtransmissionApi
     */
    public ezsignbulksendtransmissionGetCsvErrorsV1(pkiEzsignbulksendtransmissionID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignbulksendtransmissionApiFp(this.configuration).ezsignbulksendtransmissionGetCsvErrorsV1(pkiEzsignbulksendtransmissionID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Return the Ezsignsignatures that can be signed by the current user at the current step in the process
     * @summary Retrieve an existing Ezsignbulksendtransmission\'s automatic Ezsignsignatures
     * @param {number} pkiEzsignbulksendtransmissionID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksendtransmissionApi
     */
    public ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1(pkiEzsignbulksendtransmissionID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignbulksendtransmissionApiFp(this.configuration).ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1(pkiEzsignbulksendtransmissionID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignbulksendtransmission\'s forms data
     * @param {number} pkiEzsignbulksendtransmissionID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksendtransmissionApi
     */
    public ezsignbulksendtransmissionGetFormsDataV1(pkiEzsignbulksendtransmissionID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignbulksendtransmissionApiFp(this.configuration).ezsignbulksendtransmissionGetFormsDataV1(pkiEzsignbulksendtransmissionID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignbulksendtransmission
     * @param {number} pkiEzsignbulksendtransmissionID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignbulksendtransmissionApi
     */
    public ezsignbulksendtransmissionGetObjectV2(pkiEzsignbulksendtransmissionID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignbulksendtransmissionApiFp(this.configuration).ezsignbulksendtransmissionGetObjectV2(pkiEzsignbulksendtransmissionID, options).then((request) => request(this.axios, this.basePath));
    }
}
